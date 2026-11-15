package reporting

import "testing"

func TestNextFindingIDUsesNewPrefixForFreshScans(t *testing.T) {
	store := &vulnStore{}
	if got := nextFindingIDLocked(store); got != "AIDAST-1" {
		t.Fatalf("fresh scan first ID = %q, want AIDAST-1", got)
	}
	store.vulns = append(store.vulns, Vulnerability{ID: "AIDAST-1"}, Vulnerability{ID: "AIDAST-7"})
	if got := nextFindingIDLocked(store); got != "AIDAST-8" {
		t.Fatalf("next ID = %q, want AIDAST-8", got)
	}
}

func TestNextFindingIDKeepsLegacyPrefixForResumedScans(t *testing.T) {
	// A scan started before the rename must not mix XALG-15 with AIDAST-16.
	store := &vulnStore{vulns: []Vulnerability{{ID: "XALG-1"}, {ID: "XALG-15"}}}
	if got := nextFindingIDLocked(store); got != "XALG-16" {
		t.Fatalf("resumed legacy scan next ID = %q, want XALG-16", got)
	}
}

func TestFindingIDNumber(t *testing.T) {
	for id, want := range map[string]int{"AIDAST-3": 3, "XALG-42": 42} {
		if n, ok := findingIDNumber(id); !ok || n != want {
			t.Errorf("findingIDNumber(%q) = %d,%v want %d", id, n, ok, want)
		}
	}
	for _, id := range []string{"", "AIDAST-", "VULN-3", "AIDAST-x"} {
		if _, ok := findingIDNumber(id); ok {
			t.Errorf("findingIDNumber(%q) parsed, want rejection", id)
		}
	}
}

func TestMergeRenumbersWithStorePrefix(t *testing.T) {
	src, dst := "merge-prefix-src", "merge-prefix-dst"
	t.Cleanup(func() { CleanupContext(src); CleanupContext(dst) })
	SeedVulnsForContext(dst, []Vulnerability{{ID: "AIDAST-1", Title: "Reflected XSS in search", Target: "https://t.example", Endpoint: "/search"}})
	SeedVulnsForContext(src, []Vulnerability{{ID: "AIDAST-1", Title: "SQL injection in login", Target: "https://t.example", Endpoint: "/login"}})
	if added := MergeVulnsToContext(src, dst); added != 1 {
		t.Fatalf("merged %d, want 1", added)
	}
	got := GetVulnerabilitiesForContext(dst)
	if len(got) != 2 || got[1].ID != "AIDAST-2" {
		t.Fatalf("renumbered collision = %+v, want second ID AIDAST-2", got)
	}
}

func TestDefaultCredentialsClassified(t *testing.T) {
	cases := []struct{ title, cwe string }{
		{"Default Credentials admin:admin Grant Full Admin API Access", ""},
		{"Vendor-default administrator credentials (admin:admin) grant full admin API access", ""},
		{"Hard-coded password in mobile config", ""},
		{"Admin login accepts admin:admin", "CWE-798"},
		{"Admin login accepts admin:admin", "CWE-1392"},
	}
	for _, tc := range cases {
		if got := extractVulnTypeWithCWE(tc.title, "", tc.cwe); got != "default_credentials" {
			t.Errorf("extractVulnTypeWithCWE(%q, %q) = %q, want default_credentials", tc.title, tc.cwe, got)
		}
	}
}

// Regression: the same admin:admin login was stored twice — an
// unverified critical (absolute endpoint URL) and a later verified high
// (path-only endpoint) — because default credentials had no vuln class.
func TestDefaultCredentialsDuplicateIsCaught(t *testing.T) {
	target := "http://localhost:8080/shop"
	first := Vulnerability{
		ID:       "AIDAST-9",
		Title:    "Default Credentials admin:admin Grant Full Admin API Access",
		CWE:      "CWE-798",
		Target:   target,
		Endpoint: "http://localhost:8080/shop/api/login",
	}
	second := Vulnerability{
		Title:    "Vendor-default administrator credentials (admin:admin) grant full admin API access and cross-user financial data extraction",
		CWE:      "CWE-798",
		Target:   target,
		Endpoint: "/shop/api/login",
		Verified: true,
	}
	if _, _, dup := findDuplicateVulnerability([]Vulnerability{first}, second.Title, "", "", second.CWE, second.Target, second.Endpoint); !dup {
		t.Fatal("second default-credentials report on the same login endpoint was not flagged as a duplicate")
	}
	// The verified report must replace the unverified candidate in place.
	if idx := findUpgradeableVulnerabilityIndex([]Vulnerability{first}, second); idx != 0 {
		t.Fatalf("verified duplicate did not upgrade the unverified candidate (index %d)", idx)
	}
	// Default credentials on a different login surface stay a separate finding.
	other := second
	other.Endpoint = "/shop/admin/login.jsp"
	if _, _, dup := findDuplicateVulnerability([]Vulnerability{first}, other.Title, "", "", other.CWE, other.Target, other.Endpoint); dup {
		t.Fatal("default credentials on a different endpoint were wrongly collapsed")
	}
}

func TestRemoveVulnerabilityFromContextPersistsAndSurvivesRestore(t *testing.T) {
	ctxID := "remove-finding-live"
	dir := t.TempDir()
	t.Cleanup(func() { CleanupContext(ctxID) })
	seed := []Vulnerability{
		{ID: "AIDAST-1", Title: "Reflected XSS in search", Target: "https://t.example", Endpoint: "/search"},
		{ID: "AIDAST-2", Title: "SQL injection in login", Target: "https://t.example", Endpoint: "/login"},
	}
	if err := RestoreContext(ctxID, dir, seed); err != nil {
		t.Fatal(err)
	}
	if n, err := RemoveVulnerabilityFromContext(ctxID, "AIDAST-1"); err != nil || n != 1 {
		t.Fatalf("remove = %d, %v; want 1, nil", n, err)
	}
	if got := GetVulnerabilitiesForContext(ctxID); len(got) != 1 || got[0].ID != "AIDAST-2" {
		t.Fatalf("live store after delete = %+v", got)
	}
	// A restart reloads findings.json; the deleted finding must stay gone and
	// its ID must not be reissued.
	CleanupContext(ctxID)
	if err := RestoreContext(ctxID, dir, nil); err != nil {
		t.Fatal(err)
	}
	if got := GetVulnerabilitiesForContext(ctxID); len(got) != 1 || got[0].ID != "AIDAST-2" {
		t.Fatalf("deleted finding came back after restore: %+v", got)
	}
	store := getStoreByID(ctxID)
	store.mu.Lock()
	next := nextFindingIDLocked(store)
	store.mu.Unlock()
	if next != "AIDAST-3" {
		t.Fatalf("next ID after delete = %q, want AIDAST-3 (deleted IDs are never reused)", next)
	}
	if n, _ := RemoveVulnerabilityFromContext("no-such-context", "AIDAST-1"); n != 0 {
		t.Fatal("unknown context should be a no-op")
	}
}

func TestRemoveVulnerabilityFromCheckpointFile(t *testing.T) {
	ctxID := "remove-finding-offline"
	dir := t.TempDir()
	t.Cleanup(func() { CleanupContext(ctxID) })
	if err := RestoreContext(ctxID, dir, []Vulnerability{
		{ID: "AIDAST-1", Title: "Default Credentials admin:admin", Target: "https://t.example", Endpoint: "/api/login"},
		{ID: "AIDAST-2", Title: "Reflected XSS in search", Target: "https://t.example", Endpoint: "/search"},
	}); err != nil {
		t.Fatal(err)
	}
	CleanupContext(ctxID) // scan no longer running: no live store
	if n, err := RemoveVulnerabilityFromCheckpoint(dir, "AIDAST-1"); err != nil || n != 1 {
		t.Fatalf("checkpoint remove = %d, %v; want 1, nil", n, err)
	}
	if n, err := RemoveVulnerabilityFromCheckpoint(dir, "AIDAST-1"); err != nil || n != 0 {
		t.Fatalf("second remove = %d, %v; want no-op", n, err)
	}
	if err := RestoreContext(ctxID, dir, nil); err != nil {
		t.Fatal(err)
	}
	if got := GetVulnerabilitiesForContext(ctxID); len(got) != 1 || got[0].ID != "AIDAST-2" {
		t.Fatalf("resume restored a deleted finding: %+v", got)
	}
	if n, err := RemoveVulnerabilityFromCheckpoint(t.TempDir(), "AIDAST-9"); err != nil || n != 0 {
		t.Fatalf("missing checkpoint = %d, %v; want no-op", n, err)
	}
}

func TestEndpointCandidates(t *testing.T) {
	cases := map[string][]string{
		"/shop/api/login": {"/shop/api/login"},
		"POST /shop/feedback (application/xml body)": {"/shop/feedback"},
		"GET/POST /x/y": {"/x/y"},
		"POST /shop/login and POST /shop/api/login (admin account)": {"/shop/login", "/shop/api/login"},
		"/a, /b; /c": {"/a", "/b", "/c"},
		"/shop/api/login (token issuance) / all /shop/api/* endpoints (token acceptance)": {"/shop/api/login"},
		"http://h.test/p (body)": {"http://h.test/p"},
		"login form":             {"login form"}, // no route: unchanged
	}
	for in, want := range cases {
		got := endpointCandidates(in)
		if len(got) != len(want) {
			t.Errorf("endpointCandidates(%q) = %q, want %q", in, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("endpointCandidates(%q) = %q, want %q", in, got, want)
				break
			}
		}
	}
}

// Regression: a resumed scan stored repeats of existing findings
// because the agent wrote endpoints as free text, and an admin-console
// escalation was classed as user_enumeration.
func TestFreeTextEndpointDuplicatesAreCaught(t *testing.T) {
	target := "http://localhost:8080/shop"
	type rep struct{ title, cwe, endpoint string }
	dups := []struct{ existing, incoming rep }{
		{rep{"Vendor-default administrator credentials (admin:admin) grant full admin API access", "CWE-798", "/shop/api/login"},
			rep{"Default Administrator Credentials admin:admin Grant Full Admin Account Access", "CWE-798", "POST /shop/login and POST /shop/api/login (admin account)"}},
		{rep{"Blind XXE: XML parser on POST /shop/feedback resolves external entities", "CWE-611", "http://localhost:8080/shop/feedback"},
			rep{"Blind XXE — XML External Entity Injection on POST /feedback", "CWE-611", "POST /shop/feedback (application/xml body)"}},
		{rep{"CSRF on /bank/transfer: forged cross-site request transfers victim funds", "CWE-352", "http://localhost:8080/shop/bank/transfer"},
			rep{"CSRF on Money Transfer — POST /bank/transfer Executes Forged Transfers", "CWE-352", "POST /shop/bank/transfer"}},
		{rep{"Vertical Privilege Escalation: normal user reaches admin console /admin/console — full username enumeration", "CWE-284", "http://localhost:8080/shop/admin/console"},
			rep{"Vertical Privilege Escalation: Low-Privilege Customer Can Access Admin Console", "CWE-284", "http://localhost:8080/shop/admin/console"}},
	}
	for _, tc := range dups {
		existing := []Vulnerability{{ID: "AIDAST-1", Title: tc.existing.title, CWE: tc.existing.cwe, Target: target, Endpoint: tc.existing.endpoint}}
		if _, _, dup := findDuplicateVulnerability(existing, tc.incoming.title, "", "", tc.incoming.cwe, target, tc.incoming.endpoint); !dup {
			t.Errorf("not flagged as duplicate: %q (%s) vs existing %q", tc.incoming.title, tc.incoming.endpoint, tc.existing.title)
		}
		// A verified repeat must upgrade the unverified original in place.
		incoming := Vulnerability{Title: tc.incoming.title, CWE: tc.incoming.cwe, Target: target, Endpoint: tc.incoming.endpoint, Verified: true}
		if idx := findUpgradeableVulnerabilityIndex(existing, incoming); idx != 0 {
			t.Errorf("verified repeat %q did not upgrade the unverified original (idx %d)", tc.incoming.title, idx)
		}
	}
	// SQL injection on a different endpoint is a distinct finding.
	existing := []Vulnerability{{ID: "AIDAST-1", Title: "Error-based SQL Injection on POST /bank/transactions startDate", CWE: "CWE-89", Target: target, Endpoint: "/shop/bank/transactions"}}
	if _, _, dup := findDuplicateVulnerability(existing, "SQL Injection in Login (uid param) bypasses authentication", "", "", "CWE-89", target, "POST /shop/login (uid parameter)"); dup {
		t.Error("SQLi on /login was wrongly collapsed into SQLi on /bank/transactions")
	}
}

func TestPrivilegeEscalationDoesNotOverrideInjectionClasses(t *testing.T) {
	if got := extractVulnType("Remote code execution via upload leading to privilege escalation", ""); got != "rce" {
		t.Errorf("RCE + privilege escalation classified as %q, want rce", got)
	}
	if got := extractVulnType("Vertical privilege escalation exposes full username enumeration", ""); got != "idor" {
		t.Errorf("privilege escalation + enumeration classified as %q, want idor", got)
	}
}
