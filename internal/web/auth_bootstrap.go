package web

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/barhaterahul/ai-dast-ing/v4/internal/config"
)

// Dashboard login is on by default, including on a loopback bind: the
// dashboard launches scans whose agent runs shell commands, and an
// unauthenticated loopback listener is reachable from any web page the
// operator visits (DNS rebinding). When no dashboard credentials are
// configured, the first start generates an admin password, stores only its
// bcrypt hash in ~/.ai-dast-ing.env, prints the password once, and writes it
// to a 0600 file that is removed after the first successful login.
//
// AIDASTING_AUTH_DISABLED=1 opts out, and only on loopback.

const defaultAdminUser = "admin"

// initialPasswordPathFn locates the one-time password file; tests override it.
var initialPasswordPathFn = func() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "/root"
	}
	return filepath.Join(home, ".ai-dast-ing", "initial-admin-password")
}

// envFilePathFn is where generated credentials are persisted; tests override it.
var envFilePathFn = config.EnvFilePath

// dashboardCredentialsConfigured reports whether a human can log in. API
// tokens alone do not count: they never open the dashboard.
func dashboardCredentialsConfigured(cfg *config.Config) bool {
	return cfg.Username != "" && (cfg.Password != "" || cfg.PasswordHash != "")
}

// GeneratePassword returns a random URL-safe password (~144 bits).
func GeneratePassword() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ensureDashboardAuth makes sure dashboard login is configured before the
// server starts listening. loopback is whether the bind address is local.
func (s *Server) ensureDashboardAuth(loopback bool) error {
	cfg := s.cfg
	if dashboardCredentialsConfigured(cfg) {
		return nil
	}
	if cfg.AuthDisabled {
		if loopback {
			return nil
		}
		// Non-loopback without auth is refused by Start; fall through so a
		// stray opt-out never leaves an exposed dashboard open.
	}

	password, err := GeneratePassword()
	if err != nil {
		return fmt.Errorf("generate dashboard password: %w", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash dashboard password: %w", err)
	}
	user := strings.TrimSpace(cfg.Username)
	if user == "" {
		user = defaultAdminUser
	}

	// Persist first: an in-memory-only password would change on every
	// restart and lock the operator out of a long-running service.
	envPath := envFilePathFn()
	updates := map[string]string{
		"AIDASTING_USERNAME":      user,
		"AIDASTING_PASSWORD_HASH": string(hash),
		"AIDASTING_PASSWORD":      "", // a stale plaintext value must not linger
	}
	persisted := true
	if err := config.UpdateEnvFile(envPath, updates); err != nil {
		persisted = false
		log.Printf("[auth] WARNING: could not save generated credentials to %s: %v — they are valid until this process exits", envPath, err)
	}

	cfg.Username = user
	cfg.PasswordHash = string(hash)
	cfg.Password = ""
	_ = os.Setenv("AIDASTING_USERNAME", user)
	_ = os.Setenv("AIDASTING_PASSWORD_HASH", string(hash))
	_ = os.Unsetenv("AIDASTING_PASSWORD")

	pwFile := initialPasswordPathFn()
	fileNote := ""
	if err := os.MkdirAll(filepath.Dir(pwFile), 0o700); err == nil {
		if err := os.WriteFile(pwFile, []byte(password+"\n"), 0o600); err == nil {
			fileNote = pwFile
		}
	}

	banner := []string{
		"============================================================",
		"  AI-DAST-ING dashboard login was not configured.",
		"  Generated an admin account:",
		"",
		"      username: " + user,
		"      password: " + password,
		"",
	}
	if fileNote != "" {
		banner = append(banner, "  Also saved to "+fileNote+" (deleted after first login).")
	}
	if persisted {
		banner = append(banner, "  The bcrypt hash is stored in "+envPath+".")
	}
	banner = append(banner,
		"  Change it with: ai-dast-ing --setup",
		"  Opt out on loopback only: AIDASTING_AUTH_DISABLED=1",
		"============================================================",
	)
	fmt.Fprintln(os.Stderr, strings.Join(banner, "\n"))
	return nil
}

// initialPasswordPending reports the path of an undeleted one-time password
// file, shown on the login page so a first-time operator knows where to look.
func initialPasswordPending() string {
	p := initialPasswordPathFn()
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// ClearInitialPassword removes the one-time password file after the first
// successful login (or once --setup sets a password of the operator's own).
func ClearInitialPassword() {
	p := initialPasswordPathFn()
	if err := os.Remove(p); err == nil {
		log.Printf("[auth] removed one-time password file %s after first login", p)
	}
}
