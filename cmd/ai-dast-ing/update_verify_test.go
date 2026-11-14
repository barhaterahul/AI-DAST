package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseRepoIsOwnedFork(t *testing.T) {
	if releaseRepo != "barhaterahul/AI-DAST" {
		t.Fatalf("releaseRepo = %q; updates must come from the project's own repo", releaseRepo)
	}
}

func releaseServer(t *testing.T, binary []byte, sums string, serveSums bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/SHA256SUMS"):
			if !serveSums {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(sums))
		case strings.HasSuffix(r.URL.Path, "/ai-dast-ing-linux-amd64"):
			_, _ = w.Write(binary)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestInstallBinaryVerifiesChecksum(t *testing.T) {
	binary := []byte("#!/bin/sh\necho new\n")
	sum := sha256.Sum256(binary)
	good := hex.EncodeToString(sum[:]) + "  ai-dast-ing-linux-amd64\n"
	bad := strings.Repeat("0", 64) + "  ai-dast-ing-linux-amd64\n"
	other := hex.EncodeToString(sum[:]) + "  ai-dast-ing-darwin-arm64\n"

	cases := []struct {
		name      string
		sums      string
		serveSums bool
		wantErr   string
	}{
		{"valid checksum installs", good, true, ""},
		{"mismatch is rejected", bad, true, "checksum mismatch"},
		{"missing SHA256SUMS is rejected", "", false, "refusing to install unverified binary"},
		{"missing entry is rejected", other, true, "no entry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := releaseServer(t, binary, tc.sums, tc.serveSums)
			defer srv.Close()
			dest := filepath.Join(t.TempDir(), "ai-dast-ing")
			if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
				t.Fatal(err)
			}
			err := installBinary(srv.URL+"/releases/download/v1.0.0/ai-dast-ing-linux-amd64", dest)
			got, _ := os.ReadFile(dest)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if string(got) != string(binary) {
					t.Fatalf("binary not installed")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
			if string(got) != "old" {
				t.Fatalf("existing binary was modified on a failed verification")
			}
		})
	}
}
