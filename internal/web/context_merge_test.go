package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/barhaterahul/ai-dast-ing/v4/internal/attacksurface"
)

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for p, c := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func newContextUpload(t *testing.T, s *Server, files map[string]string) string {
	t.Helper()
	root := filepath.Join(s.dataDir, "context")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(root, "up_")
	if err != nil {
		t.Fatal(err)
	}
	writeFiles(t, dir, files)
	// resolveContextDir returns symlink-resolved paths (/var → /private/var
	// on macOS); match that so comparisons are exact.
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	return dir
}

const mergeOpenAPI = `{"openapi":"3.0.0","info":{"title":"x","version":"1"},
"servers":[{"url":"https://api.test"}],
"paths":{"/orders/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}]}}}}`

const mergeBru = "meta {\n  name: Ping\n  type: http\n}\n\nget {\n  url: https://api.test/ping\n}\n"

func TestResolveScanContextsMergesCollectionAndSecurityContext(t *testing.T) {
	s := &Server{dataDir: t.TempDir()}
	coll := newContextUpload(t, s, map[string]string{
		"bruno.json":      `{"version":"1","name":"API","type":"collection"}`,
		"users/ping.bru":  mergeBru,
		"selection.json":  `{"exclude":[]}`,
		"bruno_notes.txt": "collection notes",
	})
	sec := newContextUpload(t, s, map[string]string{
		"openapi.json":    mergeOpenAPI,
		"bruno_notes.txt": "security notes",
		"selection.json":  `{"exclude":["ignored"]}`,
	})

	req := ScanRequest{ScanContext: sec, APICollection: coll}
	if err := s.resolveScanContexts(&req); err != nil {
		t.Fatal(err)
	}
	merged := req.ScanContext
	if merged == coll || merged == sec || req.APICollection != "" {
		t.Fatalf("expected a fresh merged dir, got %q (collection field %q)", merged, req.APICollection)
	}
	if _, err := s.resolveContextDir(merged); err != nil {
		t.Fatalf("merged dir is not a valid context upload: %v", err)
	}

	// Bruno layout preserved; clashing security file renamed, not overwritten.
	for _, p := range []string{"bruno.json", "users/ping.bru", "openapi.json", "bruno_notes.txt", "context1_bruno_notes.txt"} {
		if !pathExists(filepath.Join(merged, filepath.FromSlash(p))) {
			t.Fatalf("missing %s in merged dir", p)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(merged, "bruno_notes.txt")); string(b) != "collection notes" {
		t.Fatalf("collection file overwritten: %q", b)
	}
	// The collection's selection wins and is a copy, not a shared inode.
	if b, _ := os.ReadFile(filepath.Join(merged, attacksurface.SelectionFile)); !strings.Contains(string(b), `"exclude":[]`) {
		t.Fatalf("selection = %q", b)
	}
	if err := os.WriteFile(filepath.Join(merged, attacksurface.SelectionFile), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(coll, attacksurface.SelectionFile)); string(b) != `{"exclude":[]}` {
		t.Fatalf("writing merged selection changed the original upload: %q", b)
	}

	res, err := attacksurface.LoadFromPath(merged)
	if err != nil {
		t.Fatal(err)
	}
	var sawPing, sawOrders bool
	for _, e := range res.Endpoints {
		sawPing = sawPing || strings.HasSuffix(e.Path, "/ping")
		sawOrders = sawOrders || strings.Contains(e.Path, "/orders/")
	}
	if !sawPing || !sawOrders {
		t.Fatalf("merged surface missing endpoints (ping=%v orders=%v): %+v", sawPing, sawOrders, res.Endpoints)
	}
}

func TestResolveScanContextsSingleAndInvalid(t *testing.T) {
	s := &Server{dataDir: t.TempDir()}
	coll := newContextUpload(t, s, map[string]string{"users/ping.bru": mergeBru, "selection.json": `{"env":"dev"}`})

	// A single upload still gets the scan's own copy, so writing the scan
	// scope never touches the upload.
	req := ScanRequest{APICollection: coll}
	if err := s.resolveScanContexts(&req); err != nil || req.ScanContext == "" || req.ScanContext == coll {
		t.Fatalf("collection only: ctx=%q err=%v", req.ScanContext, err)
	}
	if !pathExists(filepath.Join(req.ScanContext, "users", "ping.bru")) {
		t.Fatal("collection layout not copied")
	}
	if err := s.writeContextScope(req.ScanContext, []string{"https://api.test"}, false); err != nil {
		t.Fatal(err)
	}
	if got := attacksurface.ReadSelection(req.ScanContext); got.Env != "dev" || len(got.Hosts) != 1 || got.Hosts[0] != "api.test" {
		t.Fatalf("scope must extend the copied selection: %+v", got)
	}
	if got := attacksurface.ReadSelection(coll); len(got.Hosts) != 0 {
		t.Fatalf("upload selection modified: %+v", got)
	}

	sec := newContextUpload(t, s, map[string]string{"openapi.json": mergeOpenAPI})
	req = ScanRequest{ScanContext: sec}
	if err := s.resolveScanContexts(&req); err != nil || req.ScanContext == sec || !pathExists(filepath.Join(req.ScanContext, "openapi.json")) {
		t.Fatalf("security only: ctx=%q err=%v", req.ScanContext, err)
	}

	for _, bad := range []ScanRequest{
		{ScanContext: sec, APICollection: t.TempDir()},
		{ScanContext: "/etc"}, // raw filesystem paths are no longer accepted
	} {
		if err := s.resolveScanContexts(&bad); err == nil {
			t.Fatalf("path outside the context root must be rejected: %+v", bad)
		}
	}
}
