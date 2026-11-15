package web

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/barhaterahul/ai-dast-ing/v4/internal/tools/httpclient"
)

func fakeJWT(claims map[string]any) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]any{"alg": "HS256"}) + "." + enc(claims) + ".sig"
}

func newFakeTokenAPI(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["secret"] != "top-secret-value" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		i := n.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{
			"jwt":     fakeJWT(map[string]any{"sub": body["user"], "n": i, "exp": time.Now().Add(time.Hour).Unix()}),
			"refresh": fmt.Sprintf("refresh-token-%d", i),
		}})
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func providerJSON(url string) string {
	return fmt.Sprintf(`{
	  "id": "corp",
	  "request": {"url": %q, "body": {"user": "{{user}}", "secret": "{{secret:s}}"}},
	  "extract": {"token": "$.result.jwt", "refresh_token": "$.result.refresh"},
	  "secrets": {"s": "top-secret-value"},
	  "profiles": {"alice": {"user": "alice"}, "bob": {"user": "bob"}}
	}`, url)
}

func doJSON(t *testing.T, s *Server, method, path, body string) (int, map[string]any, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	s.handleTokenProviders(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Body.String()
}

func TestTokenProviderAPICRUDAndTest(t *testing.T) {
	s := newTestServer(t, nil)
	api, _ := newFakeTokenAPI(t)

	code, out, raw := doJSON(t, s, http.MethodPost, "/api/token-providers", providerJSON(api.URL))
	if code != http.StatusOK {
		t.Fatalf("create: %d %s", code, raw)
	}
	if strings.Contains(raw, "top-secret-value") {
		t.Fatal("API response leaked the secret")
	}
	if ph, _ := out["placeholders"].([]any); len(ph) != 1 || ph[0] != "user" {
		t.Fatalf("placeholders = %v", out["placeholders"])
	}

	code, _, raw = doJSON(t, s, http.MethodGet, "/api/token-providers", "")
	if code != http.StatusOK || !strings.Contains(raw, `"corp"`) || strings.Contains(raw, "top-secret-value") {
		t.Fatalf("list: %d %s", code, raw)
	}

	code, out, raw = doJSON(t, s, http.MethodPost, "/api/token-providers/corp/test", `{"profile":"bob","refresh":true}`)
	if code != http.StatusOK || out["ok"] != true {
		t.Fatalf("test: %d %s", code, raw)
	}
	if strings.Contains(raw, "refresh-token-") || strings.Contains(raw, "top-secret-value") {
		t.Fatalf("test response leaked credentials: %s", raw)
	}
	steps := out["steps"].([]any)
	first := steps[0].(map[string]any)
	if first["jwt"].(map[string]any)["claims"].(map[string]any)["sub"] != "bob" {
		t.Fatalf("claims not shown: %v", first)
	}

	// Draft test with a masked secret resolves the stored one.
	draft := strings.Replace(providerJSON(api.URL), "top-secret-value", "********", 1)
	code, out, raw = doJSON(t, s, http.MethodPost, "/api/token-providers/test", `{"provider":`+draft+`,"profile":"alice"}`)
	if code != http.StatusOK || out["ok"] != true {
		t.Fatalf("draft test: %d %s", code, raw)
	}

	// Missing parameter is reported precisely.
	bad := strings.Replace(providerJSON(api.URL), `"{{user}}"`, `"{{user}}-{{tenant}}"`, 1)
	_, out, _ = doJSON(t, s, http.MethodPost, "/api/token-providers/test", `{"provider":`+bad+`}`)
	st := out["steps"].([]any)[0].(map[string]any)
	if out["ok"] != false || fmt.Sprint(st["missing"]) != "[tenant]" {
		t.Fatalf("missing params not reported: %v", out)
	}

	code, _, _ = doJSON(t, s, http.MethodPost, "/api/token-providers", `{"id":"x y"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("invalid provider accepted: %d", code)
	}
	code, _, _ = doJSON(t, s, http.MethodDelete, "/api/token-providers/corp", "")
	if code != http.StatusOK {
		t.Fatalf("delete: %d", code)
	}
	code, _, _ = doJSON(t, s, http.MethodGet, "/api/token-providers/corp", "")
	if code != http.StatusNotFound {
		t.Fatalf("deleted provider still readable: %d", code)
	}
	if b, _ := os.ReadFile(filepath.Join(s.dataDir, "token_providers.json")); strings.Contains(string(b), "alice") {
		t.Fatal("deleted provider still on disk")
	}
}

func TestStartTokenAuthWiresSessionAuth(t *testing.T) {
	s := newTestServer(t, nil)
	api, calls := newFakeTokenAPI(t)
	if code, _, raw := doJSON(t, s, http.MethodPost, "/api/token-providers", providerJSON(api.URL)); code != http.StatusOK {
		t.Fatal(raw)
	}
	sess := &scanSession{id: "s1", instanceID: "inst-1", scanDir: t.TempDir(), tokenAuth: &TokenAuthSelection{Provider: "corp", Profile: "alice", ProfileB: "bob"}}
	const ctxID = "tok-ctx"
	authA, authB, err := s.startTokenAuth(sess, ctxID)
	if err != nil {
		t.Fatal(err)
	}
	defer stopTokenAuth(sess, ctxID)
	defer httpclient.SetSessionAuth(ctxID, nil)
	defer httpclient.SetSessionAuthB(ctxID, nil)

	if !strings.HasPrefix(authA, "Authorization: Bearer ") || !strings.HasPrefix(authB, "Authorization: Bearer ") || authA == authB {
		t.Fatalf("auth strings: %q / %q", authA, authB)
	}
	if got := httpclient.SessionAuthForContext(ctxID)["Authorization"]; "Authorization: "+got != authA {
		t.Fatalf("role A session auth not installed: %q", got)
	}
	if httpclient.SessionAuthBForContext(ctxID)["Authorization"] == "" {
		t.Fatal("role B session auth not installed")
	}
	env, err := os.ReadFile(filepath.Join(sess.scanDir, "auth", "role_a.env"))
	if err != nil || !strings.Contains(string(env), "AIDAST_AUTH_HEADER=") {
		t.Fatalf("auth env not written: %v %s", err, env)
	}
	if info, _ := os.Stat(filepath.Join(sess.scanDir, "auth", "role_a.env")); info.Mode().Perm() != 0o600 {
		t.Fatalf("auth env perms = %v", info.Mode().Perm())
	}
	red := strings.Join(httpclient.RedactionsForContext(ctxID), "\n")
	if !strings.Contains(red, "top-secret-value") || !strings.Contains(red, "refresh-token-1") {
		t.Fatal("token API secret / refresh token not registered for redaction")
	}
	brief := tokenAuthBriefing(sess.tokenManager, "corp")
	if !strings.Contains(brief, `sub="alice"`) || !strings.Contains(brief, "Role B") || strings.Contains(brief, "refresh-token") {
		t.Fatalf("briefing = %s", brief)
	}

	// Status endpoint: live role state, no token values.
	rec := httptest.NewRecorder()
	s.handleTokenStatus(rec, httptest.NewRequest(http.MethodGet, "/api/token-status/inst-1", nil))
	var st map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &st)
	if st["active"] != true || len(st["roles"].([]any)) != 2 || strings.Contains(rec.Body.String(), authA[len("Authorization: Bearer "):]) {
		t.Fatalf("token status = %s", rec.Body.String())
	}

	// A 401 with the current role-A token triggers exactly one refresh.
	before := calls.Load()
	r := managerRefresher{sess.tokenManager}
	stale := httpclient.SessionAuthForContext(ctxID)
	if !r.RefreshOn(401) || !r.Refresh(t.Context(), stale) {
		t.Fatal("refresh failed")
	}
	if calls.Load() != before+1 || httpclient.SessionAuthForContext(ctxID)["Authorization"] == stale["Authorization"] {
		t.Fatal("session auth not refreshed")
	}

	stopTokenAuth(sess, ctxID)
	rec = httptest.NewRecorder()
	s.handleTokenStatus(rec, httptest.NewRequest(http.MethodGet, "/api/token-status/inst-1", nil))
	if !strings.Contains(rec.Body.String(), `"active":false`) {
		t.Fatalf("status after stop = %s", rec.Body.String())
	}

	// Unknown provider fails closed.
	bad := &scanSession{id: "s2", scanDir: t.TempDir(), tokenAuth: &TokenAuthSelection{Provider: "ghost"}}
	if _, _, err := s.startTokenAuth(bad, "ctx2"); err == nil {
		t.Fatal("unknown provider must fail")
	}
}
