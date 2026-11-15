package web

import (
	"bytes"
	"image"
	_ "image/jpeg" // register JPEG decoder for image.Decode on uploaded logos
	_ "image/png"  // register PNG decoder for image.Decode on uploaded logos
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/barhaterahul/ai-dast-ing/v4/internal/methodology"
)

// PDF reports are rendered by internal/reporting (see generateReportAt in
// scan_query.go). This file keeps the web-side helpers that feed it.

func supportedReportLogoExt(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".png", ".jpg", ".jpeg":
		return true
	default:
		return false
	}
}

const maxReportLogoBytes = 5 << 20

// loadReportLogo reads an uploaded logo through a directory-bound handle.
// Renderers receive the validated bytes, never a path to reopen after validation.
func (s *Server) loadReportLogo(logoPath string) ([]byte, string) {
	logoPath = strings.TrimSpace(logoPath)
	if logoPath == "" || strings.TrimSpace(s.dataDir) == "" {
		return nil, ""
	}
	logosDir, err := filepath.Abs(filepath.Join(s.dataDir, "logos"))
	if err != nil {
		return nil, ""
	}
	name := logoPath
	if strings.HasPrefix(logoPath, "/uploads/logos/") {
		name = strings.TrimPrefix(logoPath, "/uploads/logos/")
	} else if filepath.IsAbs(logoPath) {
		// Keep legacy saved absolute paths only when they name an upload.
		name, err = filepath.Rel(logosDir, logoPath)
		if err != nil {
			return nil, ""
		}
	}
	if !filepath.IsLocal(name) || strings.ContainsAny(name, "/\\:\x00") || !supportedReportLogoExt(name) {
		return nil, ""
	}
	root, err := os.OpenRoot(logosDir)
	if err != nil {
		return nil, ""
	}
	defer func() { _ = root.Close() }()
	file, err := root.Open(name)
	if err != nil {
		return nil, ""
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxReportLogoBytes {
		return nil, ""
	}
	data, err := io.ReadAll(io.LimitReader(file, maxReportLogoBytes+1))
	if err != nil || len(data) > maxReportLogoBytes {
		return nil, ""
	}
	_, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || (format != "png" && format != "jpeg") {
		return nil, ""
	}
	return data, format
}

// methodologyPhaseNames maps phase number to name for report display. It
// is derived from the canonical internal/methodology registry so the
// report can never drift from the agent planner or the webui phase list.
var methodologyPhaseNames = func() map[int]string {
	m := make(map[int]string, methodology.PhaseCount)
	for _, p := range methodology.Phases {
		m[p.ID] = p.Name
	}
	return m
}()
