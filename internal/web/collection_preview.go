package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/barhaterahul/ai-dast-ing/v4/internal/attacksurface"
)

// maxPreviewRequests caps the request list returned to the UI.
const maxPreviewRequests = 500

type previewParam struct {
	Name     string `json:"name"`
	Location string `json:"location,omitempty"`
}

type previewRequest struct {
	ID       string         `json:"id"`
	Name     string         `json:"name,omitempty"`
	Folder   string         `json:"folder,omitempty"`
	Method   string         `json:"method"`
	URL      string         `json:"url"`
	Source   string         `json:"source,omitempty"`
	BodyMode string         `json:"body_mode,omitempty"`
	Params   []previewParam `json:"params,omitempty"`
	// TokenCandidate marks requests that look like they issue a token
	// (login/token/auth endpoints) so the UI can offer to turn them into a
	// token provider. Only names/keys are returned, never resolved values.
	TokenCandidate bool `json:"token_candidate,omitempty"`
}

var tokenReqRe = regexp.MustCompile(`(?i)(token|login|signin|sign-in|auth(enticate)?|oauth|session)`)

// contextPreview renders a parse result for the UI. Auth values are never
// included — only header names.
func contextPreview(res *attacksurface.Result) map[string]any {
	authNames := make([]string, 0, len(res.AuthHeaders))
	for k := range res.AuthHeaders {
		authNames = append(authNames, k)
	}
	sort.Strings(authNames)
	reqs := make([]previewRequest, 0, len(res.Endpoints))
	for i, e := range res.Endpoints {
		if i >= maxPreviewRequests {
			break
		}
		pr := previewRequest{ID: e.ID, Name: e.Name, Folder: e.Folder, Method: e.Method, URL: e.Path, Source: e.Source, BodyMode: e.BodyMode}
		for _, p := range e.Params {
			pr.Params = append(pr.Params, previewParam{Name: p, Location: e.ParamLocations[p]})
		}
		pr.TokenCandidate = e.Method == "POST" && (tokenReqRe.MatchString(e.Name) || tokenReqRe.MatchString(e.Path))
		reqs = append(reqs, pr)
	}
	return map[string]any{
		"endpoints":                len(res.Endpoints),
		"formats":                  res.Formats,
		"has_auth":                 len(res.AuthHeaders) > 0,
		"auth_headers":             authNames,
		"base_urls":                len(res.BaseURLs), // count (kept for older clients)
		"base_url_list":            res.BaseURLs,
		"notes":                    res.Notes,
		"environments":             res.Environments,
		"environment":              res.Environment,
		"missing_vars":             res.MissingVars,
		"hosts":                    res.Hosts(),
		"unresolved_host_requests": res.UnresolvedHostRequests(),
		"scripts_skipped":          res.ScriptsSkipped,
		"excluded":                 res.Excluded,
		"requests":                 reqs,
		"truncated":                len(res.Endpoints) > maxPreviewRequests,
	}
}

// resolveContextDir validates that p is an upload directory under
// <dataDir>/context and returns its cleaned absolute path.
func (s *Server) resolveContextDir(p string) (string, error) {
	root, err := filepath.Abs(filepath.Join(s.dataDir, "context"))
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(filepath.Clean(strings.TrimSpace(p)))
	if err != nil {
		return "", err
	}
	// Resolve symlinks on both sides so a link cannot escape the root.
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	if a, err := filepath.EvalSymlinks(abs); err == nil {
		abs = a
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") || strings.Contains(rel, string(filepath.Separator)) {
		return "", errors.New("path is not a context upload")
	}
	info, err := os.Stat(abs)
	if err != nil || !info.IsDir() {
		return "", errors.New("context upload not found")
	}
	return abs, nil
}

type collectionResolveRequest struct {
	Path    string            `json:"path"`
	Env     string            `json:"env"`
	Vars    map[string]string `json:"vars"`
	Exclude []string          `json:"exclude"`
}

// handleCollectionResolve serves POST /api/collection/resolve: it stores the
// operator's selection (environment, variable values, excluded requests)
// next to an upload and returns the re-parsed preview. The scan later reads
// the same selection, so it tests exactly what the operator saw.
func (s *Server) handleCollectionResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 512<<10)
	var req collectionResolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	dir, err := s.resolveContextDir(req.Path)
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if len(req.Vars) > 500 || len(req.Exclude) > 5000 {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "selection too large"})
		return
	}
	vars := map[string]string{}
	for k, v := range req.Vars {
		k = strings.TrimSpace(k)
		if k != "" && len(k) <= 200 && len(v) <= 16<<10 {
			vars[k] = v
		}
	}
	opts := attacksurface.Options{Env: strings.TrimSpace(req.Env), Vars: vars, Exclude: req.Exclude}
	// A scan's host scope is set at scan start, not by this editor; keep it.
	prev := attacksurface.ReadSelection(dir)
	opts.Hosts, opts.IncludeSubdomains = prev.Hosts, prev.IncludeSubdomains
	if err := attacksurface.WriteSelection(dir, opts); err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "could not save selection"})
		return
	}
	res, err := attacksurface.LoadFromPath(dir)
	if err != nil && res == nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "could not parse context"})
		return
	}
	resp := contextPreview(res)
	resp["path"] = dir
	resp["env"] = opts.Env
	writeJSONStatus(w, http.StatusOK, resp)
}

// maxDerivedTargets bounds how many hosts a collection can turn into targets.
const maxDerivedTargets = 20

// targetsFromContext returns the first-party base URLs of an uploaded
// context, used as scan targets when the operator entered none. Hosts
// classified as third-party (identity providers, payment gateways, other
// domains) are never chosen implicitly.
func (s *Server) targetsFromContext(p string) []string {
	dir, err := s.resolveContextDir(p)
	if err != nil {
		return nil
	}
	res, _ := attacksurface.LoadFromPath(dir)
	if res == nil {
		return nil
	}
	out := res.FirstPartyBaseURLs()
	if len(out) > maxDerivedTargets {
		out = out[:maxDerivedTargets]
	}
	return out
}
