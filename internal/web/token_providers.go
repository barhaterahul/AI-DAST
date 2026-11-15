package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/barhaterahul/ai-dast-ing/v4/internal/tokenprovider"
	"github.com/barhaterahul/ai-dast-ing/v4/internal/tools/httpclient"
)

// TokenAuthSelection picks a configured token provider and the profiles used
// for a scan. Profile is role A (applied to every request); ProfileB is the
// optional comparison identity for cross-account (IDOR/BOLA) proof.
type TokenAuthSelection struct {
	Provider string `json:"provider"`
	Profile  string `json:"profile,omitempty"`
	ProfileB string `json:"profile_b,omitempty"`
}

func (t *TokenAuthSelection) enabled() bool {
	return t != nil && strings.TrimSpace(t.Provider) != ""
}

func (t *TokenAuthSelection) roles() map[string]string {
	roles := map[string]string{tokenprovider.RoleA: strings.TrimSpace(t.Profile)}
	if b := strings.TrimSpace(t.ProfileB); b != "" {
		roles[tokenprovider.RoleB] = b
	}
	return roles
}

var (
	tokenStoreMu    sync.Mutex
	tokenStoreCache = map[string]*tokenprovider.Store{}
)

// tokenStore returns the provider store for this server's data dir.
func (s *Server) tokenStore() (*tokenprovider.Store, error) {
	path := filepath.Join(s.dataDir, "token_providers.json")
	tokenStoreMu.Lock()
	defer tokenStoreMu.Unlock()
	if st, ok := tokenStoreCache[path]; ok {
		return st, nil
	}
	st, err := tokenprovider.OpenStore(path)
	if err != nil {
		return nil, err
	}
	tokenStoreCache[path] = st
	return st, nil
}

// providerView is the API shape: secrets masked, plus derived metadata.
type providerView struct {
	tokenprovider.Provider
	Placeholders []string `json:"placeholders"`
}

func viewOf(p *tokenprovider.Provider) providerView {
	return providerView{Provider: p.Masked(), Placeholders: p.Placeholders()}
}

// handleTokenProviders serves:
//
//	GET    /api/token-providers              list
//	POST   /api/token-providers              create/replace
//	POST   /api/token-providers/test         test an unsaved draft (masked secrets resolve from the store)
//	GET    /api/token-providers/{id}         read
//	PUT    /api/token-providers/{id}         replace
//	DELETE /api/token-providers/{id}         delete
//	POST   /api/token-providers/{id}/test    fetch (and optionally refresh) a token for a profile
func (s *Server) handleTokenProviders(w http.ResponseWriter, r *http.Request) {
	store, err := s.tokenStore()
	if err != nil {
		log.Printf("[token-provider] store unavailable: %v", err)
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "token provider store unavailable"})
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/token-providers"), "/")
	parts := []string{}
	if rest != "" {
		parts = strings.Split(rest, "/")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)

	switch {
	case len(parts) == 0 && r.Method == http.MethodGet:
		list := store.List()
		out := make([]providerView, 0, len(list))
		for i := range list {
			out = append(out, viewOf(&list[i]))
		}
		writeJSONStatus(w, http.StatusOK, out)
	case len(parts) == 0 && r.Method == http.MethodPost:
		s.putTokenProvider(w, r, store, "")
	case len(parts) == 1 && parts[0] == "test" && r.Method == http.MethodPost:
		s.testTokenProvider(w, r, store, "")
	case len(parts) == 1 && tokenprovider.ValidID(parts[0]):
		id := parts[0]
		switch r.Method {
		case http.MethodGet:
			p := store.Get(id)
			if p == nil {
				writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "token provider not found"})
				return
			}
			writeJSONStatus(w, http.StatusOK, viewOf(p))
		case http.MethodPut:
			s.putTokenProvider(w, r, store, id)
		case http.MethodDelete:
			ok, err := store.Delete(id)
			if err != nil {
				writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "could not delete token provider"})
				return
			}
			if !ok {
				writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "token provider not found"})
				return
			}
			writeJSONStatus(w, http.StatusOK, map[string]string{"status": "deleted"})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case len(parts) == 2 && parts[1] == "test" && tokenprovider.ValidID(parts[0]) && r.Method == http.MethodPost:
		s.testTokenProvider(w, r, store, parts[0])
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (s *Server) putTokenProvider(w http.ResponseWriter, r *http.Request, store *tokenprovider.Store, pathID string) {
	var p tokenprovider.Provider
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	if pathID != "" {
		p.ID = pathID
	}
	saved, err := store.Put(p)
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSONStatus(w, http.StatusOK, viewOf(saved))
}

type tokenTestRequest struct {
	// Provider is an optional unsaved draft. Masked secrets ("********")
	// resolve from the stored provider with the same ID.
	Provider *tokenprovider.Provider `json:"provider,omitempty"`
	Profile  string                  `json:"profile"`
	// Refresh also exercises the refresh path after the initial fetch.
	Refresh bool `json:"refresh"`
}

type tokenTestStep struct {
	Step         string                 `json:"step"` // fetch | refresh
	OK           bool                   `json:"ok"`
	Error        string                 `json:"error,omitempty"`
	Missing      []string               `json:"missing,omitempty"`
	TokenPreview string                 `json:"token_preview,omitempty"`
	HasRefresh   bool                   `json:"has_refresh_token,omitempty"`
	RefreshRot   bool                   `json:"refresh_token_rotated,omitempty"`
	Header       string                 `json:"header,omitempty"`
	Expiry       *time.Time             `json:"expiry,omitempty"`
	ExpiresInSec int64                  `json:"expires_in_seconds,omitempty"`
	JWT          *tokenprovider.JWTInfo `json:"jwt,omitempty"`
	ElapsedMS    int64                  `json:"elapsed_ms"`
}

func (s *Server) testTokenProvider(w http.ResponseWriter, r *http.Request, store *tokenprovider.Store, id string) {
	var req tokenTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	var p *tokenprovider.Provider
	switch {
	case req.Provider != nil:
		p = req.Provider
		if id != "" {
			p.ID = id
		}
		p.Normalize()
		p.MergeSecrets(store.Get(p.ID))
		if err := p.Validate(); err != nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	case id != "":
		p = store.Get(id)
		if p == nil {
			writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "token provider not found"})
			return
		}
	default:
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "provider draft or id required"})
		return
	}
	profile := strings.TrimSpace(req.Profile)
	if profile == "" && len(p.Profiles) > 0 {
		profile = p.ProfileNames()[0]
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	client := tokenprovider.NewClient(p)
	steps := []tokenTestStep{}
	start := time.Now()
	tok, err := client.Fetch(ctx, p, profile)
	steps = append(steps, stepFor("fetch", tok, nil, err, time.Since(start)))
	if err == nil && req.Refresh {
		start = time.Now()
		next, rerr := client.Refresh(ctx, p, profile, tok)
		steps = append(steps, stepFor("refresh", next, tok, rerr, time.Since(start)))
	}
	ok := true
	for _, st := range steps {
		ok = ok && st.OK
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"ok": ok, "profile": profile, "steps": steps})
}

func stepFor(name string, tok, prev *tokenprovider.Token, err error, elapsed time.Duration) tokenTestStep {
	st := tokenTestStep{Step: name, ElapsedMS: elapsed.Milliseconds()}
	if err != nil {
		st.Error = err.Error()
		var mp *tokenprovider.ErrMissingParams
		if errors.As(err, &mp) {
			st.Missing = mp.Names
		}
		return st
	}
	st.OK = true
	st.TokenPreview = tokenprovider.MaskToken(tok.Value)
	st.HasRefresh = tok.Refresh != ""
	if prev != nil && tok.Refresh != "" && prev.Refresh != "" {
		st.RefreshRot = tok.Refresh != prev.Refresh
	}
	st.Header = tok.HeaderName
	exp := tok.Expiry
	st.Expiry = &exp
	st.ExpiresInSec = int64(time.Until(exp).Seconds())
	st.JWT = tok.JWT
	if name == "refresh" && tok.Source == "fetch" {
		st.Error = "refresh request failed; a full token request was used instead"
	}
	return st
}

// ---- scan integration ------------------------------------------------------

// managerRefresher adapts a Manager to httpclient.AuthRefresher for role A.
type managerRefresher struct{ m *tokenprovider.Manager }

func (r managerRefresher) RefreshOn(status int) bool { return r.m.RefreshOn(status) }

func (r managerRefresher) Refresh(ctx context.Context, stale map[string]string) bool {
	cur := r.m.Current(tokenprovider.RoleA)
	staleVal := ""
	if cur != nil {
		staleVal = stale[cur.HeaderName]
	}
	return r.m.ForceRefresh(ctx, tokenprovider.RoleA, staleVal)
}

// startTokenAuth fetches the scan's tokens before the agent starts and keeps
// them fresh. On success it returns the role-A/B header strings (in
// TargetAuth format) the agent should be seeded with; the manager then
// updates the per-context session auth on every refresh. Tokens are also
// written to <scanDir>/auth/<role>.env for terminal tools.
func (s *Server) startTokenAuth(sess *scanSession, contextID string) (authA, authB string, err error) {
	sel := sess.tokenAuth
	store, err := s.tokenStore()
	if err != nil {
		return "", "", fmt.Errorf("token provider store: %w", err)
	}
	p := store.Get(strings.TrimSpace(sel.Provider))
	if p == nil {
		return "", "", fmt.Errorf("token provider %q not found", sel.Provider)
	}
	authDir := filepath.Join(sess.scanDir, "auth")
	hooks := tokenprovider.Hooks{
		OnToken: func(role string, tok *tokenprovider.Token) {
			httpclient.RegisterRedactions(contextID, tokenprovider.SecretValues(p, tok)...)
			switch role {
			case tokenprovider.RoleA:
				httpclient.SetSessionAuth(contextID, tok.Headers())
			case tokenprovider.RoleB:
				httpclient.SetSessionAuthB(contextID, tok.Headers())
			}
			writeAuthEnv(authDir, role, tok)
			log.Printf("[token-provider] %s role %s token %s (expires %s)", sess.id, role, tok.Source, tok.Expiry.Format(time.RFC3339))
		},
		OnError: func(role string, err error, fatal bool) {
			log.Printf("[token-provider] %s role %s refresh failed (fatal=%v): %v", sess.id, role, fatal, err)
			if fatal {
				s.broadcastToInstance(sess.instanceID, WSEvent{
					Type:      "error",
					Content:   fmt.Sprintf("Token provider %q: role %s could not refresh its token %d times in a row — authenticated requests will likely fail. Last error: %v", p.ID, role, tokenprovider.MaxFailures, err),
					Timestamp: time.Now().Format(time.RFC3339),
				})
			}
		},
	}
	m, err := tokenprovider.NewManager(p, nil, sel.roles(), hooks)
	if err != nil {
		return "", "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := m.Start(ctx); err != nil {
		return "", "", err
	}
	sess.tokenManager = m
	registerTokenManager(sess.instanceID, m)
	httpclient.SetAuthRefresher(contextID, managerRefresher{m})
	if t := m.Current(tokenprovider.RoleA); t != nil {
		authA = t.HeaderName + ": " + t.HeaderValue
	}
	if t := m.Current(tokenprovider.RoleB); t != nil {
		authB = t.HeaderName + ": " + t.HeaderValue
	}
	return authA, authB, nil
}

// activeTokenManagers maps an instance ID to the token managers of its
// running sessions (a wildcard scan runs several), for the status badge.
var (
	activeTokenMu       sync.Mutex
	activeTokenManagers = map[string][]*tokenprovider.Manager{}
)

func registerTokenManager(instanceID string, m *tokenprovider.Manager) {
	if instanceID == "" || m == nil {
		return
	}
	activeTokenMu.Lock()
	defer activeTokenMu.Unlock()
	activeTokenManagers[instanceID] = append(activeTokenManagers[instanceID], m)
}

func unregisterTokenManager(instanceID string, m *tokenprovider.Manager) {
	activeTokenMu.Lock()
	defer activeTokenMu.Unlock()
	list := activeTokenManagers[instanceID]
	for i, x := range list {
		if x == m {
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(activeTokenManagers, instanceID)
	} else {
		activeTokenManagers[instanceID] = list
	}
}

// handleTokenStatus serves GET /api/token-status/{instanceID}: the token
// provider selection of a scan and, while it runs, each role's live state
// (valid/expiry/refresh count/last error). Never returns token values.
func (s *Server) handleTokenStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/token-status"), "/")
	if id == "" || strings.Contains(id, "/") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	var sel *TokenAuthSelection
	s.instancesMu.RLock()
	if inst := s.instances[id]; inst != nil {
		inst.mu.RLock()
		if inst.TokenAuth != nil {
			cp := *inst.TokenAuth
			sel = &cp
		}
		inst.mu.RUnlock()
	}
	s.instancesMu.RUnlock()

	activeTokenMu.Lock()
	managers := append([]*tokenprovider.Manager(nil), activeTokenManagers[id]...)
	activeTokenMu.Unlock()
	var roles []tokenprovider.RoleStatus
	if len(managers) > 0 {
		roles = managers[len(managers)-1].Status()
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"configured": sel.enabled(),
		"selection":  sel,
		"active":     len(roles) > 0,
		"roles":      roles,
	})
}

// stopTokenAuth ends refresh loops and unregisters the refresher.
func stopTokenAuth(sess *scanSession, contextID string) {
	if sess.tokenManager == nil {
		return
	}
	unregisterTokenManager(sess.instanceID, sess.tokenManager)
	httpclient.SetAuthRefresher(contextID, nil)
	sess.tokenManager.Stop()
	sess.tokenManager = nil
}

// tokenAuthBriefing describes the issued identities (claims, not secrets) so
// the agent can reason about stateless JWT authorization.
func tokenAuthBriefing(m *tokenprovider.Manager, providerID string) string {
	if m == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n## TOKEN PROVIDER AUTH (%s)\n", providerID)
	b.WriteString("Credentials are issued by an operator-configured token API and refreshed automatically before expiry (and once on a 401). Never paste a token into a long-running terminal command; read the current value from the auth env files instead.\n")
	for _, st := range m.Status() {
		tok := m.Current(st.Role)
		fmt.Fprintf(&b, "- Role %s (profile %q)", st.Role, st.Profile)
		if tok != nil && tok.JWT != nil {
			keys := make([]string, 0, len(tok.JWT.Claims))
			for k := range tok.JWT.Claims {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			parts := make([]string, 0, len(keys))
			for _, k := range keys {
				v, _ := json.Marshal(tok.JWT.Claims[k])
				parts = append(parts, k+"="+truncStr(string(v), 80))
			}
			fmt.Fprintf(&b, " JWT alg=%v claims: %s", tok.JWT.Header["alg"], strings.Join(parts, ", "))
		}
		b.WriteByte('\n')
	}
	b.WriteString("The target authorizes statelessly from these JWT claims. Test: signature enforcement per service (tampered/unsigned token, alg=none, RS256→HS256, kid/jku injection), claim tampering (sub/tenant/roles), audience confusion across services, expired-token acceptance, and cross-identity access using role B.\n")
	return b.String()
}

// writeAuthEnv writes the role's current header for terminal tools:
// AIDAST_AUTH_HEADER="Authorization: Bearer ..." and AIDAST_TOKEN=... .
func writeAuthEnv(dir, role string, tok *tokenprovider.Token) {
	if dir == "" || tok == nil {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	content := fmt.Sprintf("AIDAST_AUTH_HEADER=%q\nAIDAST_TOKEN=%q\nAIDAST_TOKEN_EXPIRES=%q\n",
		tok.HeaderName+": "+tok.HeaderValue, tok.Value, tok.Expiry.UTC().Format(time.RFC3339))
	path := filepath.Join(dir, "role_"+strings.ToLower(role)+".env")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}
