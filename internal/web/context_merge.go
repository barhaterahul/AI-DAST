package web

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/barhaterahul/ai-dast-ing/v4/internal/attacksurface"
)

// The new-scan form uploads two kinds of context separately:
//
//   - scan_context:    security context — OpenAPI/Swagger, HAR, Burp export,
//     Android app, plain-text notes.
//   - api_collection:  an API-client collection — Postman (+ environment) or
//     Bruno — with the operator's request/environment selection.
//
// Everything downstream (orchestrator, resume, edit, agent) consumes a single
// context directory. resolveScanContexts builds a fresh per-scan directory
// under <dataDir>/context from the uploads (which stay untouched), and
// writeContextScope then records the scan's host scope in it.

// resolveScanContexts validates req.ScanContext / req.APICollection and leaves
// req.ScanContext naming the scan's own context directory.
func (s *Server) resolveScanContexts(req *ScanRequest) error {
	security := strings.TrimSpace(req.ScanContext)
	collection := strings.TrimSpace(req.APICollection)
	req.APICollection = ""
	req.ScanContext = ""
	if security == "" && collection == "" {
		return nil
	}
	var collDir, secDir string
	var err error
	if collection != "" {
		if collDir, err = s.resolveContextDir(collection); err != nil {
			return fmt.Errorf("api_collection: %w", err)
		}
	}
	if security != "" {
		if secDir, err = s.resolveContextDir(security); err != nil {
			return fmt.Errorf("scan_context: %w", err)
		}
	}
	// The primary upload is copied verbatim (folder layout + selection);
	// the security context joins at the top level when both are present.
	primary, extra := collDir, secDir
	if primary == "" || primary == extra {
		primary, extra = secDir, ""
	}
	dir, err := s.mergeContextDirs(primary, extra)
	if err != nil {
		return fmt.Errorf("prepare scan context: %w", err)
	}
	req.ScanContext = dir
	return nil
}

// writeContextScope records the scan's targets as the host scope of its
// context copy, so endpoints on any other host are dropped when the agent
// loads it. dir must be a directory built by resolveScanContexts.
func (s *Server) writeContextScope(dir string, targets []string, subdomains bool) error {
	if strings.TrimSpace(dir) == "" {
		return nil
	}
	opts := attacksurface.ReadSelection(dir)
	opts.Hosts = attacksurface.ScopeHosts(targets)
	opts.IncludeSubdomains = subdomains
	if err := attacksurface.WriteSelection(dir, opts); err != nil {
		return fmt.Errorf("save scan scope: %w", err)
	}
	return nil
}

// mergeContextDirs creates a new context directory containing collDir
// verbatim (folder layout and selection.json preserved, which Bruno and the
// collection preview depend on) plus secDir's files at the top level, when
// given. Name clashes get a "context_" prefix.
func (s *Server) mergeContextDirs(collDir, secDir string) (string, error) {
	root := filepath.Join(s.dataDir, "context")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	dst, err := os.MkdirTemp(root, fmt.Sprintf("%d_scan_", time.Now().UnixMilli()))
	if err != nil {
		return "", err
	}
	fail := func(err error) (string, error) {
		_ = os.RemoveAll(dst)
		return "", err
	}

	err = filepath.WalkDir(collDir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, err := filepath.Rel(collDir, p)
		if err != nil || rel == "." {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o700)
		case d.Type().IsRegular() && d.Name() == attacksurface.SelectionFile:
			// Rewritten in place by WriteSelection: never share the inode.
			return copyFile(p, target)
		case d.Type().IsRegular():
			return linkOrCopy(p, target)
		default: // symlinks, devices: never followed
			return nil
		}
	})
	if err != nil {
		return fail(err)
	}

	if secDir == "" {
		return dst, nil
	}
	entries, err := os.ReadDir(secDir)
	if err != nil {
		return fail(err)
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || e.Name() == attacksurface.SelectionFile {
			continue
		}
		name := e.Name()
		for i := 1; pathExists(filepath.Join(dst, name)); i++ {
			name = fmt.Sprintf("context%d_%s", i, e.Name())
		}
		if err := linkOrCopy(filepath.Join(secDir, e.Name()), filepath.Join(dst, name)); err != nil {
			return fail(err)
		}
	}
	return dst, nil
}

func pathExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// linkOrCopy hard-links src to dst (uploaded artifacts are never modified in
// place, so sharing the inode is safe and avoids duplicating a large APK),
// falling back to a byte copy across filesystems.
func linkOrCopy(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	return copyFile(src, dst)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
