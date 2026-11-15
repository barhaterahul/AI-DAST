package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeOverviewScan persists rec under s.dataDir/<host>/<date>/<id>/ and
// returns the scan directory.
func writeOverviewScan(t *testing.T, s *Server, rec *ScanRecord) string {
	t.Helper()
	host := strings.NewReplacer(":", "_", "/", "_", "*", "wild").Replace(explorationTargetKey(rec.Target))
	if host == "" {
		host = "empty"
	}
	date := "2026-01-01"
	if len(rec.StartedAt) >= 10 {
		date = rec.StartedAt[:10]
	}
	dir := filepath.Join(s.dataDir, host, date, rec.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	s.saveScanRecordTo(rec, dir)
	if _, err := os.Stat(filepath.Join(dir, "scan.json")); err != nil {
		t.Fatalf("scan.json not written: %v", err)
	}
	return dir
}

func getOverview(t *testing.T, s *Server, query string) *ExplorationOverview {
	t.Helper()
	rr := httptest.NewRecorder()
	s.handleExplorationOverview(rr, httptest.NewRequest(http.MethodGet, "/api/exploration/overview"+query, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET overview%s: status %d body %s", query, rr.Code, rr.Body.String())
	}
	var out ExplorationOverview
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return &out
}

func findOverviewTarget(o *ExplorationOverview, key string) *OverviewTarget {
	for i := range o.Targets {
		if o.Targets[i].Key == key {
			return &o.Targets[i]
		}
	}
	return nil
}

func findOverviewLink(o *ExplorationOverview, kind, a, b string) *OverviewLink {
	if a > b {
		a, b = b, a
	}
	for i := range o.Links {
		l := &o.Links[i]
		if l.Kind == kind && l.Source == a && l.Target == b {
			return l
		}
	}
	return nil
}

func seedOverviewPortfolio(t *testing.T, s *Server) {
	t.Helper()
	// shop.test: an older scan and a newer one (the newer must win).
	writeOverviewScan(t, s, &ScanRecord{
		ID: "shop-old", Target: "https://shop.test/", Status: "finished",
		StartedAt: "2026-01-10T10:00:00Z",
		Vulns: []VulnSummary{
			{ID: "v-old", Title: "Missing security header X-Frame-Options", Severity: "low"},
		},
	})
	writeOverviewScan(t, s, &ScanRecord{
		ID: "shop-new", Target: "https://shop.test/", Status: "finished",
		StartedAt: "2026-06-10T10:00:00Z",
		TokenAuth: &TokenAuthSelection{Provider: "corp-sso", Profile: "user"},
		Vulns: []VulnSummary{
			{ID: "v1", Title: "SQL Injection in product search", Severity: "critical", Verified: true,
				Endpoint: "/search?q=1", Description: "You have an error in your SQL syntax near MySQL server"},
			{ID: "v2", Title: "Reflected XSS in q parameter", Severity: "High", Endpoint: "/search?q=x"},
		},
	})
	writeOverviewScan(t, s, &ScanRecord{
		ID: "api-1", Target: "https://api.shop.test/v1/", Status: "running",
		StartedAt: "2026-06-11T10:00:00Z",
		TokenAuth: &TokenAuthSelection{Provider: "corp-sso"},
		Vulns: []VulnSummary{
			{ID: "a1", Title: "Blind SQL injection in id", Severity: "high", Endpoint: "/v1/items?id=1",
				Description: "Backend responded with a MySQL error"},
		},
	})
	// Wildcard sub-scan: its own target.
	writeOverviewScan(t, s, &ScanRecord{
		ID: "admin-1", Target: "https://admin.shop.test", ParentTarget: "shop.test", Status: "stopped",
		StartedAt: "2026-06-12T10:00:00Z",
		Vulns: []VulnSummary{
			{ID: "d1", Title: "Default credentials on admin console", Severity: "medium"},
		},
	})
	// Same host on a different port; saved scan with no findings.
	writeOverviewScan(t, s, &ScanRecord{
		ID: "shop-8443", Target: "https://shop.test:8443", Status: "saved",
		StartedAt: "2026-05-01T10:00:00Z",
	})
	// Empty target is skipped.
	writeOverviewScan(t, s, &ScanRecord{ID: "no-target", Target: "", Status: "saved", StartedAt: "2026-05-01T10:00:00Z"})
}

func TestExplorationOverviewGroupsTargetsAndLinks(t *testing.T) {
	s := newTestServer(t, nil)
	seedOverviewPortfolio(t, s)

	o := getOverview(t, s, "")
	if len(o.Targets) != 4 {
		keys := []string{}
		for _, tg := range o.Targets {
			keys = append(keys, tg.Key)
		}
		t.Fatalf("targets = %v, want 4", keys)
	}
	if o.GeneratedAt == "" || o.Truncated || o.Filters.Limit != overviewDefaultLimit {
		t.Fatalf("unexpected header: generated=%q truncated=%v limit=%d", o.GeneratedAt, o.Truncated, o.Filters.Limit)
	}
	// Most severe first.
	if o.Targets[0].Key != "shop.test" {
		t.Fatalf("first target = %q, want shop.test", o.Targets[0].Key)
	}

	shop := findOverviewTarget(o, "shop.test")
	if shop.LatestScanID != "shop-new" || shop.LatestStatus != "finished" || shop.LastScanned != "2026-06-10T10:00:00Z" {
		t.Fatalf("latest scan not chosen: %+v", shop)
	}
	if len(shop.Scans) != 2 || shop.Scans[0].ID != "shop-new" || shop.Scans[1].ID != "shop-old" {
		t.Fatalf("scans not newest-first: %+v", shop.Scans)
	}
	if shop.Scans[1].Findings != 1 || shop.Scans[1].TopSeverity != "low" {
		t.Fatalf("old scan ref = %+v", shop.Scans[1])
	}
	if shop.Label != "https://shop.test/" {
		t.Fatalf("label = %q", shop.Label)
	}
	if shop.Findings != 2 || shop.Verified != 1 || shop.TopSeverity != "critical" ||
		shop.Severity != (SeverityCounts{Critical: 1, High: 1}) {
		t.Fatalf("latest counts wrong: findings=%d verified=%d top=%q sev=%+v", shop.Findings, shop.Verified, shop.TopSeverity, shop.Severity)
	}
	if shop.VulnClasses["sqli"] != 1 || shop.VulnClasses["xss"] != 1 || len(shop.VulnClasses) != 2 {
		t.Fatalf("vuln classes = %v", shop.VulnClasses)
	}
	if shop.TokenProvider != "corp-sso" {
		t.Fatalf("token provider = %q", shop.TokenProvider)
	}
	if !hasOverviewTech(shop.Backend, "MySQL") {
		t.Fatalf("backend = %+v, want MySQL", shop.Backend)
	}
	if shop.Endpoints < 1 {
		t.Fatalf("endpoints = %d, want >= 1", shop.Endpoints)
	}

	admin := findOverviewTarget(o, "admin.shop.test")
	if admin == nil || admin.LatestScanID != "admin-1" || admin.VulnClasses["default_credentials"] != 1 {
		t.Fatalf("sub-scan target = %+v", admin)
	}
	saved := findOverviewTarget(o, "shop.test:8443")
	if saved == nil || saved.LatestStatus != "saved" || saved.Findings != 0 || saved.TopSeverity != "" ||
		saved.Backend == nil || saved.VulnClasses == nil {
		t.Fatalf("saved target = %+v", saved)
	}

	if l := findOverviewLink(o, overviewKindVuln, "shop.test", "api.shop.test"); l == nil || l.Label != "sqli" || l.Weight != 1 {
		t.Fatalf("shared_vuln_class link = %+v (links %+v)", l, o.Links)
	} else if l.ID != "shared_vuln_class:api.shop.test:shop.test" {
		t.Fatalf("link id = %q", l.ID)
	}
	if l := findOverviewLink(o, overviewKindBackend, "shop.test", "api.shop.test"); l == nil || l.Label != "MySQL" {
		t.Fatalf("shared_backend link = %+v", l)
	}
	if l := findOverviewLink(o, overviewKindAuth, "shop.test", "api.shop.test"); l == nil || !strings.Contains(l.Label, "corp-sso") {
		t.Fatalf("shared_auth link = %+v", l)
	}
	if l := findOverviewLink(o, overviewKindInfra, "shop.test", "shop.test:8443"); l == nil || l.Label != "shop.test" {
		t.Fatalf("shared_infra link = %+v", l)
	}
	if l := findOverviewLink(o, overviewKindVuln, "shop.test", "admin.shop.test"); l != nil {
		t.Fatalf("unexpected vuln link %+v", l)
	}

	if len(o.Matrix.Classes) == 0 || o.Matrix.Classes[0] != "sqli" {
		t.Fatalf("matrix classes = %v, want sqli first", o.Matrix.Classes)
	}
	cells := 0
	for _, c := range o.Matrix.Cells {
		if c.Count <= 0 {
			t.Fatalf("zero cell %+v", c)
		}
		if c.Target == "shop.test" && c.Class == "sqli" && c.TopSeverity != "critical" {
			t.Fatalf("cell severity %+v", c)
		}
		cells++
	}
	if cells != 4 { // shop: sqli,xss; api: sqli; admin: default_credentials
		t.Fatalf("cells = %+v", o.Matrix.Cells)
	}

	want := OverviewTotals{Targets: 4, Scans: 5, Findings: 4, Severity: SeverityCounts{Critical: 1, High: 2, Medium: 1}}
	if o.Totals != want {
		t.Fatalf("totals = %+v, want %+v", o.Totals, want)
	}

	// Deterministic output across calls.
	o2 := getOverview(t, s, "")
	a, _ := json.Marshal(o.Links)
	b, _ := json.Marshal(o2.Links)
	if string(a) != string(b) {
		t.Fatalf("links not deterministic:\n%s\n%s", a, b)
	}
}

func hasOverviewTech(techs []OverviewTech, name string) bool {
	for _, tc := range techs {
		if tc.Name == name {
			return true
		}
	}
	return false
}

func TestExplorationOverviewFilters(t *testing.T) {
	s := newTestServer(t, nil)
	seedOverviewPortfolio(t, s)

	if o := getOverview(t, s, "?q=API.SHOP"); len(o.Targets) != 1 || o.Targets[0].Key != "api.shop.test" || o.Filters.Q != "API.SHOP" {
		t.Fatalf("q filter: %+v", o.Targets)
	}
	if o := getOverview(t, s, "?min_severity=high"); len(o.Targets) != 2 || o.Totals.Targets != 2 {
		t.Fatalf("min_severity=high: %d targets", len(o.Targets))
	}
	if o := getOverview(t, s, "?min_severity=medium"); len(o.Targets) != 3 {
		t.Fatalf("min_severity=medium: %d targets", len(o.Targets))
	}
	if o := getOverview(t, s, "?status=Running"); len(o.Targets) != 1 || o.Targets[0].Key != "api.shop.test" {
		t.Fatalf("status filter: %+v", o.Targets)
	}
	// since drops the old shop.test scan and the May port-8443 scan.
	o := getOverview(t, s, "?since=2026-06-01")
	if len(o.Targets) != 3 || o.Filters.Since != "2026-06-01" {
		t.Fatalf("since: %d targets", len(o.Targets))
	}
	if shop := findOverviewTarget(o, "shop.test"); shop == nil || len(shop.Scans) != 1 {
		t.Fatalf("since kept old scan: %+v", shop)
	}
	if o := getOverview(t, s, "?since=2026-06-11T00:00:00Z"); len(o.Targets) != 2 {
		t.Fatalf("since RFC3339: %d targets", len(o.Targets))
	}
	o = getOverview(t, s, "?limit=2")
	if len(o.Targets) != 2 || !o.Truncated || o.Totals.Targets != 4 || o.Filters.Limit != 2 {
		t.Fatalf("limit: targets=%d truncated=%v totals=%d", len(o.Targets), o.Truncated, o.Totals.Targets)
	}
	for _, l := range o.Links {
		if findOverviewTarget(o, l.Source) == nil || findOverviewTarget(o, l.Target) == nil {
			t.Fatalf("link to a truncated target: %+v", l)
		}
	}
	if o := getOverview(t, s, "?limit=9999"); o.Filters.Limit != overviewMaxLimit {
		t.Fatalf("limit cap = %d", o.Filters.Limit)
	}

	for _, q := range []string{"?min_severity=urgent", "?since=yesterday", "?limit=0", "?limit=abc"} {
		rr := httptest.NewRecorder()
		s.handleExplorationOverview(rr, httptest.NewRequest(http.MethodGet, "/api/exploration/overview"+q, nil))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d, want 400", q, rr.Code)
		}
	}
}

func TestExplorationOverviewMethodNotAllowed(t *testing.T) {
	s := newTestServer(t, nil)
	rr := httptest.NewRecorder()
	s.handleExplorationOverview(rr, httptest.NewRequest(http.MethodPost, "/api/exploration/overview", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status %d, want 405", rr.Code)
	}
}

func TestExplorationOverviewEmpty(t *testing.T) {
	s := newTestServer(t, nil)
	rr := httptest.NewRecorder()
	s.handleExplorationOverview(rr, httptest.NewRequest(http.MethodGet, "/api/exploration/overview", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{`"targets":[]`, `"links":[]`, `"classes":[]`, `"cells":[]`} {
		if !strings.Contains(body, want) {
			t.Fatalf("empty response missing %s: %s", want, body)
		}
	}
}

func TestExplorationOverviewCacheInvalidatesOnScanChange(t *testing.T) {
	s := newTestServer(t, nil)
	rec := &ScanRecord{
		ID: "cache-1", Target: "https://shop.test", Status: "running", StartedAt: "2026-06-01T10:00:00Z",
		Vulns: []VulnSummary{{ID: "c1", Title: "SQL injection in login", Severity: "high",
			Description: "MySQL error returned"}},
	}
	dir := writeOverviewScan(t, s, rec)

	o := getOverview(t, s, "")
	if !hasOverviewTech(o.Targets[0].Backend, "MySQL") {
		t.Fatalf("backend = %+v", o.Targets[0].Backend)
	}
	sig, _ := overviewScanSignature(dir)
	if _, ok := overviewDigestLookup(dir, sig); !ok {
		t.Fatalf("digest not cached")
	}

	rec.Status = "finished"
	rec.Vulns[0].Description = "PSQLException: syntax error at or near"
	s.saveScanRecordTo(rec, dir)
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "scan.json"), future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	o = getOverview(t, s, "")
	tg := o.Targets[0]
	if tg.LatestStatus != "finished" || !hasOverviewTech(tg.Backend, "PostgreSQL") || hasOverviewTech(tg.Backend, "MySQL") {
		t.Fatalf("stale overview after scan.json change: status=%q backend=%+v", tg.LatestStatus, tg.Backend)
	}
}

func TestOverviewDigestCacheBounded(t *testing.T) {
	base := t.TempDir()
	for i := range overviewDigestCacheMax + 5 {
		overviewDigestStore(filepath.Join(base, fmt.Sprint(i)), "sig", overviewGraphDigest{})
	}
	overviewDigestCache.Lock()
	n := len(overviewDigestCache.m)
	_, firstKept := overviewDigestCache.m[filepath.Join(base, "0")]
	overviewDigestCache.Unlock()
	if n > overviewDigestCacheMax {
		t.Fatalf("cache size %d exceeds %d", n, overviewDigestCacheMax)
	}
	if firstKept {
		t.Fatalf("oldest entry was not evicted")
	}
}

func overviewTestTargets(n int, classes ...string) []*overviewTargetData {
	out := make([]*overviewTargetData, n)
	for i := range out {
		td := &overviewTargetData{classTop: map[string]string{}}
		td.Key = fmt.Sprintf("t%02d.shop.test", i)
		td.TopSeverity = "low"
		td.VulnClasses = map[string]int{}
		for _, c := range classes {
			td.classTop[c] = "low"
			td.VulnClasses[c] = 1
		}
		out[i] = td
	}
	return out
}

func TestOverviewLinksStarAndCap(t *testing.T) {
	// 5 targets: pairwise (10 links).
	if links := buildOverviewLinks(overviewTestTargets(5, "sqli")); len(links) != 10 {
		t.Fatalf("pairwise links = %d, want 10", len(links))
	}
	// 8 targets: 28 pairs capped at 20.
	if links := buildOverviewLinks(overviewTestTargets(8, "sqli")); len(links) != overviewLinksPerItem {
		t.Fatalf("capped pairwise links = %d, want %d", len(links), overviewLinksPerItem)
	}
	// 12 targets: a star from the most severe one.
	targets := overviewTestTargets(12, "sqli")
	targets[7].TopSeverity = "critical"
	hub := targets[7].Key
	links := buildOverviewLinks(targets)
	if len(links) != 11 {
		t.Fatalf("star links = %d, want 11", len(links))
	}
	for _, l := range links {
		if l.Source != hub && l.Target != hub {
			t.Fatalf("star link not on hub %s: %+v", hub, l)
		}
	}
	// 30 targets: star capped at 20.
	if links := buildOverviewLinks(overviewTestTargets(30, "sqli")); len(links) != overviewLinksPerItem {
		t.Fatalf("star cap = %d, want %d", len(links), overviewLinksPerItem)
	}
	// "other" never links.
	if links := buildOverviewLinks(overviewTestTargets(3, "other")); len(links) != 0 {
		t.Fatalf("other class linked: %+v", links)
	}
}

func TestOverviewLinksMergePerPair(t *testing.T) {
	links := buildOverviewLinks(overviewTestTargets(2, "xss", "sqli", "ssrf", "lfi"))
	if len(links) != 1 {
		t.Fatalf("links = %+v, want one merged link", links)
	}
	l := links[0]
	if l.Weight != 4 || l.Label != "lfi, sqli, ssrf +1" || len(l.Evidence) != 4 ||
		l.ID != "shared_vuln_class:t00.shop.test:t01.shop.test" {
		t.Fatalf("merged link = %+v", l)
	}
}

func TestOverviewMatrixColumnCap(t *testing.T) {
	td := overviewTestTargets(1)[0]
	for i := range 20 {
		c := fmt.Sprintf("class%02d", i)
		td.VulnClasses[c] = 1
		td.classTop[c] = "low"
	}
	td.VulnClasses["other"] = 2
	td.classTop["other"] = "info"
	m := buildOverviewMatrix([]*overviewTargetData{td})
	if len(m.Classes) != overviewMatrixMaxCols || m.Classes[len(m.Classes)-1] != "other" || m.Classes[0] != "class00" {
		t.Fatalf("classes = %v", m.Classes)
	}
	if len(m.Cells) != overviewMatrixMaxCols {
		t.Fatalf("cells = %d", len(m.Cells))
	}
}

func TestOverviewKeyHostname(t *testing.T) {
	for in, want := range map[string]string{
		"shop.test": "shop.test", "shop.test:8443": "shop.test", "[::1]:8080": "::1", "::1": "::1",
	} {
		if got := overviewKeyHostname(in); got != want {
			t.Fatalf("overviewKeyHostname(%q) = %q, want %q", in, got, want)
		}
	}
}
