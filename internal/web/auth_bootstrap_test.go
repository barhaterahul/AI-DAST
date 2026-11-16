package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/barhaterahul/ai-dast-ing/v4/internal/config"
)

// bootstrapHarness points the env file and one-time password file at a temp
// dir and restores the hooks afterwards.
func bootstrapHarness(t *testing.T) (envPath, pwPath string) {
	t.Helper()
	dir := t.TempDir()
	envPath = filepath.Join(dir, ".ai-dast-ing.env")
	pwPath = filepath.Join(dir, ".ai-dast-ing", "initial-admin-password")
	oldEnv, oldPw := envFilePathFn, initialPasswordPathFn
	envFilePathFn = func() string { return envPath }
	initialPasswordPathFn = func() string { return pwPath }
	for _, k := range []string{"AIDASTING_USERNAME", "AIDASTING_PASSWORD", "AIDASTING_PASSWORD_HASH"} {
		t.Setenv(k, os.Getenv(k)) // restored after the test
	}
	t.Cleanup(func() { envFilePathFn, initialPasswordPathFn = oldEnv, oldPw })
	resetAuthStateForTest()
	return envPath, pwPath
}

func TestEnsureDashboardAuthGeneratesAndPersistsOnLoopback(t *testing.T) {
	envPath, pwPath := bootstrapHarness(t)
	cfg := &config.Config{}
	s := &Server{cfg: cfg}

	if err := s.ensureDashboardAuth(true); err != nil {
		t.Fatal(err)
	}
	if cfg.Username != "admin" || cfg.PasswordHash == "" || cfg.Password != "" {
		t.Fatalf("cfg not populated: user=%q hash=%v plain=%q", cfg.Username, cfg.PasswordHash != "", cfg.Password)
	}
	if !authConfigured(cfg) {
		t.Fatal("auth must be enabled after bootstrap")
	}

	pwBytes, err := os.ReadFile(pwPath)
	if err != nil {
		t.Fatalf("one-time password file: %v", err)
	}
	password := strings.TrimSpace(string(pwBytes))
	if info, _ := os.Stat(pwPath); info.Mode().Perm() != 0o600 {
		t.Fatalf("password file mode = %v", info.Mode().Perm())
	}
	if bcrypt.CompareHashAndPassword([]byte(cfg.PasswordHash), []byte(password)) != nil {
		t.Fatal("generated password does not match stored hash")
	}

	saved, err := config.ReadEnvFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved["AIDASTING_USERNAME"] != "admin" || saved["AIDASTING_PASSWORD_HASH"] != cfg.PasswordHash {
		t.Fatalf("env file = %v", saved)
	}
	if strings.Contains(mustRead(t, envPath), password) {
		t.Fatal("plaintext password must never be written to the env file")
	}

	// A second start with the persisted credentials must not regenerate.
	before := cfg.PasswordHash
	if err := s.ensureDashboardAuth(true); err != nil || cfg.PasswordHash != before {
		t.Fatalf("credentials regenerated on second start (err=%v)", err)
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEnsureDashboardAuthRespectsConfigAndOptOut(t *testing.T) {
	bootstrapHarness(t)

	// Already configured: untouched.
	cfg := &config.Config{Username: "ops", PasswordHash: "$2a$10$existing"}
	if err := (&Server{cfg: cfg}).ensureDashboardAuth(true); err != nil || cfg.PasswordHash != "$2a$10$existing" {
		t.Fatalf("configured credentials changed: %+v err=%v", cfg, err)
	}

	// Opt-out on loopback: no credentials.
	cfg = &config.Config{AuthDisabled: true}
	if err := (&Server{cfg: cfg}).ensureDashboardAuth(true); err != nil || dashboardCredentialsConfigured(cfg) {
		t.Fatalf("opt-out on loopback must leave auth off: %+v", cfg)
	}

	// Opt-out is ignored when exposed: credentials are generated anyway.
	cfg = &config.Config{AuthDisabled: true}
	if err := (&Server{cfg: cfg}).ensureDashboardAuth(false); err != nil || !dashboardCredentialsConfigured(cfg) {
		t.Fatalf("non-loopback must always get credentials: %+v", cfg)
	}

	// A configured username is kept; API tokens alone do not count.
	cfg = &config.Config{Username: "alice", APITokens: []string{"tok-123456789012345678901234"}}
	if err := (&Server{cfg: cfg}).ensureDashboardAuth(true); err != nil || cfg.Username != "alice" || cfg.PasswordHash == "" {
		t.Fatalf("username/token case: %+v err=%v", cfg, err)
	}
}

func TestInitialPasswordHintAndClearOnLogin(t *testing.T) {
	_, pwPath := bootstrapHarness(t)
	cfg := &config.Config{}
	s := &Server{cfg: cfg}
	if err := s.ensureDashboardAuth(true); err != nil {
		t.Fatal(err)
	}
	password := strings.TrimSpace(mustRead(t, pwPath))

	status := func() map[string]any {
		rec := httptest.NewRecorder()
		s.handleAuthStatus(rec, httptest.NewRequest(http.MethodGet, "/api/auth/status", nil))
		var out map[string]any
		_ = json.NewDecoder(rec.Body).Decode(&out)
		return out
	}
	if got := status(); got["auth_enabled"] != true || got["authenticated"] != false || got["initial_password_file"] != pwPath {
		t.Fatalf("status before login = %v", got)
	}

	body := `{"username":"admin","password":"` + password + `"}`
	rec := httptest.NewRecorder()
	s.handleLogin(rec, httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("login with generated password: %d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(pwPath); !os.IsNotExist(err) {
		t.Fatal("one-time password file must be removed after first login")
	}
	if _, ok := status()["initial_password_file"]; ok {
		t.Fatal("hint must disappear once the file is gone")
	}
}
