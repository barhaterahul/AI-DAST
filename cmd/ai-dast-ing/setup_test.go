package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/barhaterahul/ai-dast-ing/v4/internal/config"
)

// setupHome isolates ~/.ai-dast-ing.env and the one-time password file.
func setupHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, k := range []string{"AIDASTING_USERNAME", "AIDASTING_PASSWORD", "AIDASTING_PASSWORD_HASH",
		"AIDASTING_LLM", "AIDASTING_LLM_PROVIDER", "AIDASTING_API_BASE", "AIDASTING_API_KEY", "AIDASTING_LLM_PROFILE"} {
		t.Setenv(k, "")
	}
	return home
}

// ollamaSetupInput picks Ollama (no API key) and accepts the model/URL defaults.
const ollamaSetupInput = "7\n\n\n"

func TestSetupGeneratesDashboardPassword(t *testing.T) {
	home := setupHome(t)
	// Stale one-time password from an earlier first start must be removed.
	stale := filepath.Join(home, ".ai-dast-ing", "initial-admin-password")
	_ = os.MkdirAll(filepath.Dir(stale), 0o700)
	_ = os.WriteFile(stale, []byte("old\n"), 0o600)

	var out bytes.Buffer
	in := strings.NewReader(ollamaSetupInput + "\n" /* username: admin */ + "\n" /* generate */ + "n\n")
	if _, err := runSetup(in, &out); err != nil {
		t.Fatalf("setup: %v\n%s", err, out.String())
	}
	m := regexp.MustCompile(`username: admin  password: (\S+)`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("generated password not shown:\n%s", out.String())
	}
	saved, err := config.ReadEnvFile(filepath.Join(home, ".ai-dast-ing.env"))
	if err != nil {
		t.Fatal(err)
	}
	if saved["AIDASTING_USERNAME"] != "admin" || bcrypt.CompareHashAndPassword([]byte(saved["AIDASTING_PASSWORD_HASH"]), []byte(m[1])) != nil {
		t.Fatalf("saved credentials do not match shown password: %v", saved)
	}
	if saved["AIDASTING_PASSWORD"] != "" {
		t.Fatal("plaintext password must not be stored")
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale one-time password file should be removed")
	}
}

func TestSetupCustomPasswordAndKeepExisting(t *testing.T) {
	home := setupHome(t)
	var out bytes.Buffer
	// Too-short password is rejected, then a valid one is accepted.
	in := strings.NewReader(ollamaSetupInput + "ops\n" + "short\n" + "a-long-password\n" + "n\n")
	if _, err := runSetup(in, &out); err != nil {
		t.Fatalf("setup: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "Use at least 8 characters") {
		t.Fatalf("short password not rejected:\n%s", out.String())
	}
	envPath := filepath.Join(home, ".ai-dast-ing.env")
	saved, _ := config.ReadEnvFile(envPath)
	if saved["AIDASTING_USERNAME"] != "ops" || bcrypt.CompareHashAndPassword([]byte(saved["AIDASTING_PASSWORD_HASH"]), []byte("a-long-password")) != nil {
		t.Fatalf("custom credentials not saved: %v", saved)
	}

	// Re-running setup and keeping the login leaves the hash unchanged.
	hash := saved["AIDASTING_PASSWORD_HASH"]
	out.Reset()
	in = strings.NewReader(ollamaSetupInput + "\n" /* keep login: yes */ + "n\n")
	if _, err := runSetup(in, &out); err != nil {
		t.Fatalf("second setup: %v\n%s", err, out.String())
	}
	saved, _ = config.ReadEnvFile(envPath)
	if saved["AIDASTING_PASSWORD_HASH"] != hash {
		t.Fatal("keeping the existing login must not change the hash")
	}
}
