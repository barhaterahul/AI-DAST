package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestApplyLegacyEnvFillsOnlyUnsetNames(t *testing.T) {
	t.Setenv("XALGORIX_API_KEY", "legacy-key")
	t.Setenv("XALGORIX_LLM", "legacy-model")
	t.Setenv("AIDASTING_LLM", "current-model")
	_ = os.Unsetenv("AIDASTING_API_KEY")
	t.Cleanup(func() { _ = os.Unsetenv("AIDASTING_API_KEY") })

	copied := applyLegacyEnv()
	if !reflect.DeepEqual(copied, []string{"AIDASTING_API_KEY"}) {
		t.Fatalf("copied = %v, want [AIDASTING_API_KEY]", copied)
	}
	if got := os.Getenv("AIDASTING_API_KEY"); got != "legacy-key" {
		t.Errorf("AIDASTING_API_KEY = %q, want legacy-key", got)
	}
	if got := os.Getenv("AIDASTING_LLM"); got != "current-model" {
		t.Errorf("AIDASTING_LLM = %q; a set new name must win over the legacy one", got)
	}
}

func TestLegacyDataDir(t *testing.T) {
	t.Setenv("AIDASTING_DATA_DIR", "")
	t.Setenv("AIDASTING_WORKSPACE", "")

	home := t.TempDir()
	if got := legacyDataDir(home); got != "" {
		t.Fatalf("no legacy data: got %q, want empty", got)
	}
	legacy := filepath.Join(home, ".xalgorix", "data")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := legacyDataDir(home); got != legacy {
		t.Fatalf("legacy only: got %q, want %q", got, legacy)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ai-dast-ing", "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := legacyDataDir(home); got != "" {
		t.Fatalf("new data present: got %q, want empty (new location wins)", got)
	}
	_ = os.RemoveAll(filepath.Join(home, ".ai-dast-ing"))
	t.Setenv("AIDASTING_DATA_DIR", "/pinned")
	if got := legacyDataDir(home); got != "" {
		t.Fatalf("explicit AIDASTING_DATA_DIR: got %q, want empty", got)
	}
}
