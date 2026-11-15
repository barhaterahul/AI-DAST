package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const previewColl = `{
  "info": {"name": "API"},
  "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{token}}"}]},
  "item": [
    {"name": "Get token", "request": {"method": "POST", "url": "{{base}}/auth/token", "body": {"mode": "raw", "raw": "{\"user\":\"u\",\"password\":\"p\"}"}}},
    {"name": "Get order", "request": {"method": "GET", "url": "{{base}}/orders/:id", "header": [{"key": "X-Tenant", "value": "{{tenant}}"}]}}
  ]
}`

func makeContextUpload(t *testing.T, s *Server) string {
	t.Helper()
	dir := filepath.Join(s.dataDir, "context", "123_abc")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"coll.json": previewColl,
		"dev.json":  `{"name":"dev","values":[{"key":"base","value":"https://dev.api.test"},{"key":"token","value":"dev-secret-token"}]}`,
		"prod.json": `{"name":"prod","values":[{"key":"base","value":"https://api.test"},{"key":"token","value":"prod-secret-token"}]}`,
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func resolveCall(t *testing.T, s *Server, body string) (int, map[string]any, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleCollectionResolve(rec, httptest.NewRequest(http.MethodPost, "/api/collection/resolve", bytes.NewBufferString(body)))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Body.String()
}

func TestCollectionResolvePreview(t *testing.T) {
	s := newTestServer(t, nil)
	dir := makeContextUpload(t, s)

	body, _ := json.Marshal(map[string]any{"path": dir, "env": "prod", "vars": map[string]string{"tenant": "t-9"}})
	code, out, raw := resolveCall(t, s, string(body))
	if code != http.StatusOK {
		t.Fatalf("resolve: %d %s", code, raw)
	}
	if strings.Contains(raw, "prod-secret-token") || strings.Contains(raw, "dev-secret-token") {
		t.Fatal("preview leaked an auth value")
	}
	if got := out["base_url_list"].([]any); len(got) != 1 || got[0] != "https://api.test" {
		t.Fatalf("base urls = %v", got)
	}
	if envs := out["environments"].([]any); len(envs) != 2 {
		t.Fatalf("environments = %v", envs)
	}
	if ah := out["auth_headers"].([]any); len(ah) != 1 || ah[0] != "Authorization" {
		t.Fatalf("auth headers = %v", ah)
	}
	reqs := out["requests"].([]any)
	var tokenReq, orderReq map[string]any
	for _, r := range reqs {
		m := r.(map[string]any)
		switch m["name"] {
		case "Get token":
			tokenReq = m
		case "Get order":
			orderReq = m
		}
	}
	if tokenReq == nil || tokenReq["token_candidate"] != true {
		t.Fatalf("token request not flagged: %v", tokenReq)
	}
	if orderReq == nil || orderReq["token_candidate"] == true {
		t.Fatalf("order request wrongly flagged: %v", orderReq)
	}

	// Exclude a request; the scan sees the same selection on disk.
	body, _ = json.Marshal(map[string]any{"path": dir, "env": "prod", "exclude": []string{orderReq["id"].(string)}})
	_, out, _ = resolveCall(t, s, string(body))
	if out["excluded"].(float64) != 1 || len(out["requests"].([]any)) != 1 {
		t.Fatalf("exclusion not applied: %v", out["requests"])
	}
	if _, err := os.Stat(filepath.Join(dir, "selection.json")); err != nil {
		t.Fatal("selection not persisted")
	}

	// Targets are derived from the selected environment's base URL.
	if got := s.targetsFromContext(dir); len(got) != 1 || got[0] != "https://api.test" {
		t.Fatalf("derived targets = %v", got)
	}
}

func TestCollectionResolveRejectsPathsOutsideContextRoot(t *testing.T) {
	s := newTestServer(t, nil)
	makeContextUpload(t, s)
	outside := t.TempDir()
	link := filepath.Join(s.dataDir, "context", "evil_link")
	_ = os.Symlink(outside, link)
	for _, p := range []string{
		outside,
		filepath.Join(s.dataDir, "context"),
		filepath.Join(s.dataDir, "context", "123_abc", ".."),
		filepath.Join(s.dataDir, "context", "..", "context", "..", "x"),
		link,
		"",
	} {
		body, _ := json.Marshal(map[string]any{"path": p})
		if code, _, raw := resolveCall(t, s, string(body)); code != http.StatusBadRequest {
			t.Errorf("path %q accepted: %d %s", p, code, raw)
		}
	}
	if _, err := os.Stat(filepath.Join(outside, "selection.json")); err == nil {
		t.Fatal("selection written outside the context root")
	}
	if s.targetsFromContext(outside) != nil {
		t.Fatal("targets derived from a path outside the context root")
	}
}

func TestBrunoRelDir(t *testing.T) {
	cases := map[string]string{
		"get.bru":                      "",
		"Users/get.bru":                "Users",
		"Users/environments/dev.bru":   filepath.Join("Users", "environments"),
		"../../etc/x.bru":              "",
		"/abs/x.bru":                   "",
		"a/../b/x.bru":                 "b", // path.Dir cleans it
		`win\style\x.bru`:              filepath.Join("win", "style"),
		"a/b/c/d/e/f/g/h/i/x.bru":      "",
		"we!rd<>/x.bru":                "we_rd_",
		"ok folder/sub folder/req.bru": filepath.Join("ok folder", "sub folder"),
	}
	for in, want := range cases {
		if got := brunoRelDir(in); got != want {
			t.Errorf("brunoRelDir(%q) = %q, want %q", in, got, want)
		}
	}
}
