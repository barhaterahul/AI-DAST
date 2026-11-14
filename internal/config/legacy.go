package config

import (
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Pre-rename compatibility. The project was renamed xalgorix → ai-dast-ing,
// which moved every env var (XALGORIX_* → AIDASTING_*), the env files
// (~/.xalgorix.env → ~/.ai-dast-ing.env) and the data root (~/.xalgorix →
// ~/.ai-dast-ing). Without a shim an upgraded install silently loses its LLM
// key, dashboard credentials and scan history. Everything here is
// non-destructive: legacy values only fill gaps the new names leave, and
// nothing on disk is moved or deleted.

const (
	legacyEnvPrefix = "XALGORIX_"
	envPrefix       = "AIDASTING_"
)

// legacyEnvFiles returns the pre-rename env files in load order (lowest
// priority first), mirroring load()'s order for the current names.
func legacyEnvFiles(home string) []string {
	paths := []string{"/etc/xalgorix.env"}
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		paths = append(paths, filepath.Join("/home", sudoUser, ".xalgorix.env"))
	}
	return append(paths, filepath.Join(home, ".xalgorix.env"))
}

// applyLegacyEnv copies each XALGORIX_<NAME> to AIDASTING_<NAME> when the new
// name is unset, and returns the names it copied (sorted). The legacy
// variables themselves are left alone; subprocess environments strip both
// namespaces (tools.OperatorNamespaceKey).
func applyLegacyEnv() []string {
	var copied []string
	for _, kv := range os.Environ() {
		key, value, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(key, legacyEnvPrefix) {
			continue
		}
		name := strings.TrimPrefix(key, legacyEnvPrefix)
		if name == "" {
			continue
		}
		newKey := envPrefix + name
		if _, set := os.LookupEnv(newKey); set {
			continue
		}
		_ = os.Setenv(newKey, value)
		copied = append(copied, newKey)
	}
	sort.Strings(copied)
	return copied
}

// legacyDataDir returns ~/.xalgorix/data when an upgraded install still keeps
// its data there and has nothing at the new default location, so scan
// history stays visible. "" when no fallback applies (new data exists, no
// legacy data, or the operator pinned a location explicitly).
func legacyDataDir(home string) string {
	if os.Getenv("AIDASTING_DATA_DIR") != "" || os.Getenv("AIDASTING_WORKSPACE") != "" {
		return ""
	}
	if _, err := os.Stat(filepath.Join(home, ".ai-dast-ing", "data")); err == nil {
		return ""
	}
	legacy := filepath.Join(home, ".xalgorix", "data")
	if info, err := os.Stat(legacy); err == nil && info.IsDir() {
		return legacy
	}
	return ""
}

// applyLegacyCompat runs the pre-rename shim. Call it after the legacy env
// files and the current env files are loaded, before any AIDASTING_* value
// is read.
func applyLegacyCompat(home string) {
	if copied := applyLegacyEnv(); len(copied) > 0 {
		log.Printf("[config] Deprecated: using legacy XALGORIX_* settings for %s — rename them to AIDASTING_* (and ~/.xalgorix.env to ~/.ai-dast-ing.env).", strings.Join(copied, ", "))
	}
	if legacy := legacyDataDir(home); legacy != "" {
		_ = os.Setenv("AIDASTING_DATA_DIR", legacy)
		log.Printf("[config] Using pre-rename data directory %s. To migrate, stop the service and run: mv %s %s", legacy, filepath.Dir(legacy), filepath.Join(home, ".ai-dast-ing"))
	}
}
