package attacksurface

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Shared machinery for API-client collections (Postman, Bruno): layered
// variable resolution, request → Endpoint normalization with parameter
// locations, and the operator's selection (environment, variable overrides,
// excluded requests) persisted next to an upload.

// SelectionFile is the name of the operator selection stored in an upload dir.
const SelectionFile = "selection.json"

// Options steer collection parsing.
type Options struct {
	// Env selects one environment by name (case-insensitive). Empty = the
	// only environment when there is exactly one, otherwise none.
	Env string `json:"env,omitempty"`
	// Vars are operator-supplied values; they override every other scope.
	Vars map[string]string `json:"vars,omitempty"`
	// Exclude lists request IDs (Endpoint.ID) to drop from the surface.
	Exclude []string `json:"exclude,omitempty"`
	// Hosts, when set, is the scan's host scope: endpoints on any other
	// absolute host are dropped (see hosts.go). Written at scan start into
	// the scan's own copy of the context, never into an upload.
	Hosts []string `json:"hosts,omitempty"`
	// IncludeSubdomains also keeps subdomains of Hosts (wildcard scans).
	IncludeSubdomains bool `json:"include_subdomains,omitempty"`
}

// ReadSelection loads <dir>/selection.json (zero Options when absent).
func ReadSelection(dir string) Options {
	var o Options
	b, err := os.ReadFile(filepath.Join(dir, SelectionFile))
	if err != nil {
		return o
	}
	_ = json.Unmarshal(b, &o)
	return o
}

// WriteSelection stores the operator selection in an upload dir.
func WriteSelection(dir string, o Options) error {
	b, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, SelectionFile), b, 0o600)
}

// ── variable resolution ─────────────────────────────────────────────────────

var collectionVarRe = regexp.MustCompile(`\{\{\s*([^{}]+?)\s*\}\}`)

// resolver resolves {{name}} against ordered scopes (first match wins) plus
// Postman/Bruno dynamic variables ({{$guid}}, {{$timestamp}}, ...). Names
// still unresolved after substitution are recorded as missing.
type resolver struct {
	scopes  []map[string]string
	missing map[string]bool
}

func newResolver(scopes ...map[string]string) *resolver {
	return &resolver{scopes: scopes, missing: map[string]bool{}}
}

// with returns a resolver with extra highest-priority scopes (request/folder
// variables) that shares the missing set.
func (r *resolver) with(scopes ...map[string]string) *resolver {
	all := append(append([]map[string]string{}, scopes...), r.scopes...)
	return &resolver{scopes: all, missing: r.missing}
}

func (r *resolver) lookup(name string) (string, bool) {
	for _, s := range r.scopes {
		if v, ok := s[name]; ok {
			return v, true
		}
	}
	return dynamicVar(name)
}

// resolve substitutes variables; values may themselves reference variables
// (resolved up to a small depth to avoid cycles).
func (r *resolver) resolve(s string) string {
	for depth := 0; depth < 4 && strings.Contains(s, "{{"); depth++ {
		changed := false
		s = collectionVarRe.ReplaceAllStringFunc(s, func(m string) string {
			name := strings.TrimSpace(collectionVarRe.FindStringSubmatch(m)[1])
			if v, ok := r.lookup(name); ok {
				changed = true
				return v
			}
			return m
		})
		if !changed {
			break
		}
	}
	for _, m := range collectionVarRe.FindAllStringSubmatch(s, -1) {
		r.missing[strings.TrimSpace(m[1])] = true
	}
	return s
}

func (r *resolver) missingList() []string {
	out := make([]string, 0, len(r.missing))
	for k := range r.missing {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// dynamicVar renders the common Postman/Bruno dynamic variables with
// plausible values so requests stay replayable.
func dynamicVar(name string) (string, bool) {
	switch strings.TrimPrefix(name, "$") {
	case "guid", "randomUUID", "uuid":
		if !strings.HasPrefix(name, "$") {
			return "", false
		}
		b := make([]byte, 16)
		if _, err := crand.Read(b); err != nil {
			return "", false
		}
		b[6] = (b[6] & 0x0f) | 0x40
		b[8] = (b[8] & 0x3f) | 0x80
		h := hex.EncodeToString(b)
		return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], true
	case "timestamp":
		if strings.HasPrefix(name, "$") {
			return strconv.FormatInt(time.Now().Unix(), 10), true
		}
	case "isoTimestamp":
		if strings.HasPrefix(name, "$") {
			return time.Now().UTC().Format(time.RFC3339), true
		}
	case "randomInt":
		if strings.HasPrefix(name, "$") {
			return strconv.Itoa(rand.IntN(1000)), true
		}
	}
	return "", false
}

// ── request normalization ───────────────────────────────────────────────────

// collReq is a format-neutral request collected from a collection.
type collReq struct {
	source   string // postman | bruno
	name     string
	folder   string
	method   string
	rawURL   string            // resolved URL (may still contain :pathVars)
	query    []kv              // enabled query params (resolved)
	pathVars map[string]string // :name -> value (resolved)
	headers  []kv              // enabled headers (resolved)
	authHdrs []kv              // headers produced by an auth block (always auth)
	bodyMode string            // json | form | multipart | graphql | xml | text | ""
	body     string            // resolved body text
	fields   []string          // form/multipart field names
}

type kv struct{ k, v string }

var pathVarRe = regexp.MustCompile(`/:([A-Za-z_][A-Za-z0-9_]*)`)

// toEndpoint converts a collected request into an Endpoint (plus any auth
// headers it carries, returned separately for the Result's auth map).
func (cr collReq) toEndpoint() (Endpoint, map[string]string) {
	e := Endpoint{
		Method:         strings.ToUpper(strings.TrimSpace(cr.method)),
		Name:           cr.name,
		Folder:         cr.folder,
		Source:         cr.source,
		BodyMode:       cr.bodyMode,
		ParamLocations: map[string]string{},
	}
	if e.Method == "" {
		e.Method = "GET"
	}
	auth := map[string]string{}
	addParam := func(name, loc string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		if _, ok := e.ParamLocations[name]; !ok {
			e.Params = append(e.Params, name)
			e.ParamLocations[name] = loc
		}
	}

	u := cr.rawURL
	// Path variables: record as params, substitute example values.
	for _, m := range pathVarRe.FindAllStringSubmatch(stripQuery(u), -1) {
		addParam(m[1], "path")
	}
	for name, val := range cr.pathVars {
		if strings.TrimSpace(val) != "" {
			u = strings.ReplaceAll(u, "/:"+name, "/"+url.PathEscape(val))
		}
	}
	// Query from the URL itself plus the structured list.
	if i := strings.IndexByte(u, '?'); i >= 0 {
		if q, err := url.ParseQuery(u[i+1:]); err == nil {
			for k := range q {
				addParam(k, "query")
			}
		}
	}
	for _, q := range cr.query {
		addParam(q.k, "query")
	}
	e.Path = stripQuery(u)

	for _, h := range cr.headers {
		if strings.TrimSpace(h.k) == "" {
			continue
		}
		if isAuthHeader(h.k) {
			if strings.TrimSpace(h.v) != "" {
				auth[canonicalHeader(h.k)] = h.v
			}
			continue
		}
		if strings.EqualFold(h.k, "content-type") {
			e.ContentType = h.v
			continue
		}
		if isHopHeader(h.k) {
			continue
		}
		if e.Headers == nil {
			e.Headers = map[string]string{}
		}
		e.Headers[h.k] = h.v
	}

	for _, h := range cr.authHdrs {
		if strings.TrimSpace(h.k) != "" && strings.TrimSpace(h.v) != "" {
			auth[canonicalHeader(h.k)] = h.v
		}
	}

	switch cr.bodyMode {
	case "json":
		for _, k := range jsonBodyKeys(cr.body) {
			addParam(k, "body")
		}
		if e.ContentType == "" {
			e.ContentType = "application/json"
		}
	case "graphql":
		addParam("query", "body")
		for _, k := range jsonBodyKeys(gqlVars(cr.body)) {
			addParam("variables."+k, "body")
		}
		if e.ContentType == "" {
			e.ContentType = "application/json"
		}
	case "form", "multipart":
		for _, f := range cr.fields {
			addParam(f, "body")
		}
		if e.ContentType == "" {
			if cr.bodyMode == "form" {
				e.ContentType = "application/x-www-form-urlencoded"
			} else {
				e.ContentType = "multipart/form-data"
			}
		}
	case "xml":
		if e.ContentType == "" {
			e.ContentType = "application/xml"
		}
	}
	e.Body = truncate(cr.body, maxBodyChars)
	if len(e.ParamLocations) == 0 {
		e.ParamLocations = nil
	}
	e.ID = requestID(cr.source, cr.folder, cr.name, e.Method, e.Path)
	return e, auth
}

// gqlVars extracts the "variables" object from a rendered GraphQL body.
func gqlVars(body string) string {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &m) == nil {
		if v, ok := m["variables"]; ok {
			return string(v)
		}
	}
	return ""
}

// jsonBodyKeys lists top-level keys and one nested level ("a.b") of a JSON
// object body; arrays of objects contribute their first element's keys.
func jsonBodyKeys(body string) []string {
	body = strings.TrimSpace(body)
	if body == "" {
		return nil
	}
	var v any
	if json.Unmarshal([]byte(body), &v) != nil {
		return nil
	}
	if arr, ok := v.([]any); ok && len(arr) > 0 {
		v = arr[0]
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	var out []string
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, k)
		child := obj[k]
		if arr, ok := child.([]any); ok && len(arr) > 0 {
			child = arr[0]
		}
		if m, ok := child.(map[string]any); ok {
			sub := make([]string, 0, len(m))
			for ck := range m {
				sub = append(sub, ck)
			}
			sort.Strings(sub)
			for _, ck := range sub {
				out = append(out, k+"."+ck)
			}
		}
		if len(out) >= 64 {
			break
		}
	}
	return out
}

func isHopHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "host", "content-length", "connection", "keep-alive", "transfer-encoding",
		"upgrade", "te", "trailer", "proxy-connection", "accept-encoding":
		return true
	}
	return false
}

func requestID(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:6])
}

// baseURLOf returns scheme://host for an absolute http(s) URL, else "".
func baseURLOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.Contains(u.Host, "{{") {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// collectionResult assembles a Result from collected requests.
func collectionResult(format string, reqs []collReq, res *Result, opts Options) *Result {
	if res == nil {
		res = &Result{}
	}
	if res.AuthHeaders == nil {
		res.AuthHeaders = map[string]string{}
	}
	res.Formats = append(res.Formats, format)
	excluded := map[string]bool{}
	for _, id := range opts.Exclude {
		excluded[strings.TrimSpace(id)] = true
	}
	for _, cr := range reqs {
		e, auth := cr.toEndpoint()
		if excluded[e.ID] {
			res.Excluded++
			continue
		}
		res.Endpoints = append(res.Endpoints, e)
		for k, v := range auth {
			res.AuthHeaders[k] = v
		}
		if b := baseURLOf(e.Path); b != "" {
			res.BaseURLs = append(res.BaseURLs, b)
		}
	}
	return res
}

// addScriptNote records that collection scripts were present and skipped.
func addScriptNote(res *Result, n int) {
	if n <= 0 {
		return
	}
	res.ScriptsSkipped += n
	res.Notes = append(res.Notes, fmt.Sprintf("%d collection script(s) (pre-request/tests) were NOT executed; tokens they would set must come from a token provider or variables", n))
}
