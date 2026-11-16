package attacksurface

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func hostResult(paths ...string) *Result {
	r := &Result{}
	for _, p := range paths {
		r.Endpoints = append(r.Endpoints, Endpoint{Method: "GET", Path: p})
	}
	return r
}

func TestHostsClassifiesFirstAndThirdParty(t *testing.T) {
	r := hostResult(
		"https://api.shop.test/v1/orders",
		"https://api.shop.test/v1/users",
		"https://auth.shop.test/token",
		"https://myco.auth0.com/oauth/token",
		"https://api.stripe.com/v1/charges",
		"https://partner.other.test/hook",
		"{{baseUrl}}/health",
		"/relative/path",
	)
	byBase := map[string]HostInfo{}
	for _, h := range r.Hosts() {
		byBase[h.BaseURL] = h
	}
	for base, wantThird := range map[string]bool{
		"https://api.shop.test":      false,
		"https://auth.shop.test":     false, // same registrable domain
		"https://myco.auth0.com":     true,
		"https://api.stripe.com":     true,
		"https://partner.other.test": true,
	} {
		h, ok := byBase[base]
		if !ok {
			t.Fatalf("missing host %s in %+v", base, byBase)
		}
		if h.ThirdParty != wantThird {
			t.Errorf("%s third_party=%v want %v (%s)", base, h.ThirdParty, wantThird, h.Reason)
		}
	}
	if byBase["https://api.shop.test"].Requests != 2 {
		t.Errorf("request count = %d", byBase["https://api.shop.test"].Requests)
	}
	if !strings.Contains(byBase["https://partner.other.test"].Reason, "shop.test") {
		t.Errorf("reason should name the primary domain: %q", byBase["https://partner.other.test"].Reason)
	}
	if got := r.UnresolvedHostRequests(); got != 1 {
		t.Errorf("unresolved = %d", got)
	}
	first := r.FirstPartyBaseURLs()
	if len(first) != 2 || first[0] != "https://api.shop.test" {
		t.Errorf("first-party = %v", first)
	}
}

func TestRestrictToHosts(t *testing.T) {
	r := hostResult(
		"https://api.shop.test/a",
		"https://API.shop.test:8443/b",
		"https://v2.api.shop.test/c",
		"https://api.stripe.com/d",
		"{{baseUrl}}/e",
		"/relative",
	)
	r.BaseURLs = []string{"https://api.shop.test", "https://api.stripe.com"}
	dropped := r.RestrictToHosts(ScopeHosts([]string{"https://api.shop.test/v1"}), false)
	var kept []string
	for _, e := range r.Endpoints {
		kept = append(kept, e.Path)
	}
	if dropped != 3 || len(kept) != 3 || r.OutOfScope != 3 {
		t.Fatalf("dropped=%d kept=%v", dropped, kept)
	}
	if len(r.BaseURLs) != 1 || r.BaseURLs[0] != "https://api.shop.test" {
		t.Fatalf("base urls = %v", r.BaseURLs)
	}
	if !strings.Contains(r.Briefing(), "Do NOT send requests to hosts that are not scan targets") {
		t.Fatal("briefing must tell the agent about removed out-of-scope requests")
	}

	// Wildcard scans keep subdomains of a bare target.
	r = hostResult("https://v2.api.shop.test/c", "https://evil-shop.test/x")
	if dropped := r.RestrictToHosts([]string{"shop.test"}, true); dropped != 1 || r.Endpoints[0].Path != "https://v2.api.shop.test/c" {
		t.Fatalf("subdomain scope: dropped=%d %+v", dropped, r.Endpoints)
	}
}

func TestLoadFromPathHonorsScopeHosts(t *testing.T) {
	dir := t.TempDir()
	coll := `{"info":{"name":"x","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
"item":[{"name":"orders","request":{"method":"GET","url":"https://api.shop.test/orders"}},
{"name":"pay","request":{"method":"POST","url":"https://api.stripe.com/v1/charges"}}]}`
	if err := os.WriteFile(filepath.Join(dir, "c.json"), []byte(coll), 0o600); err != nil {
		t.Fatal(err)
	}
	if res, err := LoadFromPath(dir); err != nil || len(res.Endpoints) != 2 {
		t.Fatalf("unscoped load: %v %+v", err, res)
	}
	if err := WriteSelection(dir, Options{Hosts: []string{"api.shop.test"}}); err != nil {
		t.Fatal(err)
	}
	res, err := LoadFromPath(dir)
	if err != nil || len(res.Endpoints) != 1 || !strings.Contains(res.Endpoints[0].Path, "api.shop.test") || res.OutOfScope != 1 {
		t.Fatalf("scoped load: %v %+v", err, res)
	}
}
