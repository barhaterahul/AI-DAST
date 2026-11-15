package web

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTargetDirName(t *testing.T) {
	cases := map[string]string{
		"http://localhost:8080/altoromutual": "localhost_8080_altoromutual",
		"https://api.example.com":            "api.example.com",
		"example.com":                        "example.com",
		"../../etc/passwd":                   "_.._etc_passwd",
		"..":                                 "target",
		"":                                   "target",
		"logos":                              "logos_target",
		"CONTEXT":                            "CONTEXT_target",
		"http://[::1]:9000/":                 "1__9000",
	}
	for in, want := range cases {
		got := targetDirName(in)
		if got != want {
			t.Errorf("targetDirName(%q) = %q, want %q", in, got, want)
		}
		if strings.ContainsAny(got, `/\:`) || got == "." || got == ".." {
			t.Errorf("targetDirName(%q) = %q is not a single safe path component", in, got)
		}
	}
}

func TestMakeScanDirStaysInsideDataDir(t *testing.T) {
	s := newTestServer(t, nil)
	for _, target := range []string{"http://localhost:8080/altoromutual", "../../outside", "https://x.test/a/../../b"} {
		dir := s.makeScanDir(target)
		rel, err := filepath.Rel(s.dataDir, dir)
		if err != nil || strings.HasPrefix(rel, "..") {
			t.Fatalf("%q: scan dir %q escapes data dir", target, dir)
		}
		if parts := strings.Split(rel, string(filepath.Separator)); len(parts) != 3 || strings.Contains(parts[0], ":") {
			t.Fatalf("%q: unexpected layout %q (want target/date/slug)", target, rel)
		}
	}
}
