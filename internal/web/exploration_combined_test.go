package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// combinedFixtureScan saves a scan record under s.dataDir/<host>/<date>/<id>/.
func combinedFixtureScan(t *testing.T, s *Server, host string, rec *ScanRecord) string {
	t.Helper()
	dir := filepath.Join(s.dataDir, host, "2026-11-01", rec.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s.saveScanRecordTo(rec, dir)
	if _, err := os.Stat(filepath.Join(dir, "scan.json")); err != nil {
		t.Fatalf("fixture not saved: %v", err)
	}
	s.invalidateScanListCache()
	return dir
}

func combinedTestServer(t *testing.T) *Server {
	t.Helper()
	s := newTestServer(t, nil)
	combinedFixtureScan(t, s, "shop.test", &ScanRecord{
		ID: "scan-shop-1", Target: "https://shop.test/", Status: "finished",
		Vulns: []VulnSummary{
			{ID: "F-1", Title: "SQL injection in login uid parameter", Severity: "Critical", CWE: "CWE-89",
				Endpoint: "/login", Method: "POST", Verified: true,
				TechnicalAnalysis: "The backend returned SQLState 42X01 from the database, a syntax error."},
			{ID: "F-2", Title: "Reflected XSS via the 'q' parameter", Severity: "medium", CWE: "CWE-79",
				Endpoint: "https://shop.test/search?q=x", Method: "GET"},
		},
	})
	combinedFixtureScan(t, s, "api.shop.test", &ScanRecord{
		ID: "scan-api-1", Target: "https://api.shop.test:8443/v1/", Status: "running",
		Vulns: []VulnSummary{
			{ID: "F-1", Title: "SQL injection in account lookup", Severity: "high", CWE: "CWE-89",
				Endpoint: "/v1/accounts", Method: "GET",
				TechnicalAnalysis: "Error page leaked SQLState 42X01 from the database."},
		},
	})
	return s
}

func combinedGet(t *testing.T, s *Server, rawQuery string) (*httptest.ResponseRecorder, *ExplorationCombined) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/exploration/combined?"+rawQuery, nil)
	w := httptest.NewRecorder()
	s.handleExplorationCombined(w, req)
	if w.Code != http.StatusOK {
		return w, nil
	}
	var out ExplorationCombined
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v: %s", err, w.Body.String())
	}
	return w, &out
}

func assertCombinedConsistent(t *testing.T, out *ExplorationCombined) {
	t.Helper()
	ids := map[string]string{}
	for _, n := range out.Nodes {
		if _, dup := ids[n.ID]; dup {
			t.Fatalf("duplicate node id %q", n.ID)
		}
		if !strings.HasPrefix(n.ID, n.Group+":") {
			t.Fatalf("node %q not prefixed with its group %q", n.ID, n.Group)
		}
		ids[n.ID] = n.Group
	}
	edgeIDs := map[string]bool{}
	for _, e := range out.Edges {
		if edgeIDs[e.ID] {
			t.Fatalf("duplicate edge id %q", e.ID)
		}
		edgeIDs[e.ID] = true
		sg, ok1 := ids[e.Source]
		tg, ok2 := ids[e.Target]
		if !ok1 || !ok2 {
			t.Fatalf("dangling edge %+v", e)
		}
		if sg != tg || !strings.HasPrefix(e.ID, sg+":") {
			t.Fatalf("edge crosses lanes or is unprefixed: %+v", e)
		}
	}
}

func TestExplorationCombinedMergesScans(t *testing.T) {
	s := combinedTestServer(t)
	w, out := combinedGet(t, s, "scans="+url.QueryEscape(" scan-shop-1 ,scan-api-1,scan-shop-1,,"))
	if out == nil {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type %q", ct)
	}
	if out.Scope != "findings" || out.Truncated {
		t.Fatalf("header: scope=%q truncated=%v", out.Scope, out.Truncated)
	}
	if len(out.Groups) != 2 {
		t.Fatalf("want 2 deduped groups, got %+v", out.Groups)
	}
	assertCombinedConsistent(t, out)

	g0, g1 := out.Groups[0], out.Groups[1]
	if g0.ID != "g0" || g0.ScanID != "scan-shop-1" || g0.Key != "shop.test" || g0.Status != "finished" || g0.Error != "" {
		t.Fatalf("g0: %+v", g0)
	}
	if g1.ID != "g1" || g1.ScanID != "scan-api-1" || g1.Key != "api.shop.test:8443" || g1.Status != "running" {
		t.Fatalf("g1: %+v", g1)
	}
	if g0.Stats.Findings != 2 || g0.Stats.Verified != 1 || g1.Stats.Findings != 1 {
		t.Fatalf("stats: g0=%+v g1=%+v", g0.Stats, g1.Stats)
	}
	if g0.Severity.Critical != 1 || g0.Severity.Medium != 1 || g0.TopSeverity != "critical" {
		t.Fatalf("g0 severity: %+v top=%s", g0.Severity, g0.TopSeverity)
	}
	if g1.Severity.High != 1 || g1.TopSeverity != "high" {
		t.Fatalf("g1 severity: %+v top=%s", g1.Severity, g1.TopSeverity)
	}

	// Same underlying node id in both lanes stays distinct after prefixing.
	have := map[string]bool{}
	for _, n := range out.Nodes {
		have[n.ID] = true
	}
	for _, id := range []string{"g0:target", "g1:target", "g0:finding:F-1", "g1:finding:F-1"} {
		if !have[id] {
			t.Errorf("missing node %q", id)
		}
	}

	kinds := map[string]OverviewLink{}
	for _, l := range out.Links {
		if l.Source != "g0" || l.Target != "g1" {
			t.Fatalf("link endpoints: %+v", l)
		}
		kinds[l.Kind] = l
	}
	vc, ok := kinds["shared_vuln_class"]
	if !ok || vc.Label != "sqli" || vc.Weight != 1 || len(vc.Evidence) != 1 {
		t.Fatalf("shared_vuln_class link: %+v (all: %+v)", vc, out.Links)
	}
	if b, ok := kinds["shared_backend"]; !ok || b.Weight < 1 || b.Label == "" {
		t.Fatalf("shared_backend link: %+v (all: %+v)", b, out.Links)
	}

	// Deterministic output across calls.
	_, again := combinedGet(t, s, "scans=scan-shop-1,scan-api-1")
	a, _ := json.Marshal(out.Links)
	b, _ := json.Marshal(again.Links)
	if string(a) != string(b) {
		t.Fatalf("links not deterministic:\n%s\n%s", a, b)
	}
}

func TestExplorationCombinedUnknownAndInvalidIDs(t *testing.T) {
	s := combinedTestServer(t)
	_, out := combinedGet(t, s, "scans="+url.QueryEscape("scan-shop-1,does-not-exist,../x,..,a\\b"))
	if out == nil {
		t.Fatal("request with bad ids must not fail as a whole")
	}
	if len(out.Groups) != 5 {
		t.Fatalf("groups: %+v", out.Groups)
	}
	if out.Groups[0].Error != "" {
		t.Fatalf("good scan errored: %+v", out.Groups[0])
	}
	want := []string{combinedErrNotFound, combinedErrInvalidID, combinedErrInvalidID, combinedErrInvalidID}
	for i, w := range want {
		g := out.Groups[i+1]
		if g.Error != w {
			t.Errorf("group %d (%q) error = %q, want %q", i+1, g.ScanID, g.Error, w)
		}
	}
	for _, n := range out.Nodes {
		if n.Group != "g0" {
			t.Fatalf("errored group has nodes: %+v", n)
		}
	}
	for _, l := range out.Links {
		if l.Source != "g0" && l.Target != "g0" {
			t.Fatalf("link between errored groups: %+v", l)
		}
	}
	assertCombinedConsistent(t, out)
}

func TestExplorationCombinedBadRequests(t *testing.T) {
	s := newTestServer(t, nil)
	for _, q := range []string{"", "scans=", "scans=%20,%20,"} {
		w, _ := combinedGet(t, s, q)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%q: status %d, want 400", q, w.Code)
		}
	}
	ids := make([]string, 9)
	for i := range ids {
		ids[i] = "scan-" + strconv.Itoa(i)
	}
	w, _ := combinedGet(t, s, "scans="+strings.Join(ids, ","))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf(">8 ids: %d %s", w.Code, w.Body.String())
	}
	// Exactly 8 (all unknown) is fine.
	if w, out := combinedGet(t, s, "scans="+strings.Join(ids[:8], ",")); out == nil || len(out.Groups) != 8 {
		t.Fatalf("8 ids: %d %s", w.Code, w.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/api/exploration/combined?scans=a", nil)
	rw := httptest.NewRecorder()
	s.handleExplorationCombined(rw, req)
	if rw.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rw.Code)
	}
}

func TestExplorationCombinedScopeParam(t *testing.T) {
	s := newTestServer(t, nil)
	dir := filepath.Join(s.dataDir, "shop.test", "2026-11-01", "scan-eg-1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeEGFile(t, dir, "scan.json", egScanJSON)
	writeEGFile(t, dir, "ledger.json", egLedgerJSON)
	writeEGFile(t, dir, "execution-graph.json", egExecGraphJSON)
	s.invalidateScanListCache()

	_, def := combinedGet(t, s, "scans=scan-eg-1")
	_, all := combinedGet(t, s, "scans=scan-eg-1&scope=ALL")
	_, junk := combinedGet(t, s, "scans=scan-eg-1&scope=bogus")
	if def == nil || all == nil || junk == nil {
		t.Fatal("scope requests failed")
	}
	if def.Scope != "findings" || all.Scope != "all" || junk.Scope != "findings" {
		t.Fatalf("scopes: %q %q %q", def.Scope, all.Scope, junk.Scope)
	}
	if len(all.Nodes) <= len(def.Nodes) {
		t.Fatalf("scope=all should include more nodes: all=%d findings=%d", len(all.Nodes), len(def.Nodes))
	}
	if all.Groups[0].Stats.Attempts <= def.Groups[0].Stats.Attempts {
		t.Fatalf("attempts: all=%d findings=%d", all.Groups[0].Stats.Attempts, def.Groups[0].Stats.Attempts)
	}
	assertCombinedConsistent(t, all)
}

func TestExplorationCombinedLinkLabel(t *testing.T) {
	if got := combinedLinkLabel([]string{"a", "b"}); got != "a, b" {
		t.Fatalf("got %q", got)
	}
	if got := combinedLinkLabel([]string{"a", "b", "c", "d", "e"}); got != "a, b, c +2" {
		t.Fatalf("got %q", got)
	}
	vulns := func(titles ...string) *ScanRecord {
		r := &ScanRecord{}
		for _, ti := range titles {
			r.Vulns = append(r.Vulns, VulnSummary{Title: ti})
		}
		return r
	}
	lanes := []*combinedLane{
		{group: CombinedGroup{ID: "g0"}, rec: vulns("SQL injection in login", "Something odd"), graph: &ExplorationGraph{}},
		{group: CombinedGroup{ID: "g1"}, rec: vulns("Blind SQL injection", "Something odd too"), graph: &ExplorationGraph{}},
		{group: CombinedGroup{ID: "g2"}, rec: vulns("Something odd")},
	}
	links := combinedLinks(lanes)
	if len(links) != 1 || links[0].Kind != "shared_vuln_class" || links[0].Label != "sqli" ||
		links[0].Source != "g0" || links[0].Target != "g1" || links[0].ID != "shared_vuln_class:g0:g1" {
		t.Fatalf(`"other" must not link, sqli must: %+v`, links)
	}
}

// syntheticCombinedGraph: target -> endpoint:i -> finding:i for each finding,
// plus `noise` discovery nodes hanging off the target.
func syntheticCombinedGraph(findings, noise int) *ExplorationGraph {
	g := &ExplorationGraph{Nodes: []ExplorationNode{{ID: "target", Type: "target"}}}
	add := func(src, dst, kind string) {
		g.Edges = append(g.Edges, ExplorationEdge{ID: kind + ":" + src + "->" + dst, Source: src, Target: dst, Kind: kind})
	}
	for i := 0; i < noise; i++ {
		id := "discovery:" + strconv.Itoa(i)
		g.Nodes = append(g.Nodes, ExplorationNode{ID: id, Type: "discovery"})
		add("target", id, "discovered")
	}
	for i := 0; i < findings; i++ {
		ep := "endpoint:/p" + strconv.Itoa(i)
		f := "finding:F-" + strconv.Itoa(i)
		g.Nodes = append(g.Nodes,
			ExplorationNode{ID: ep, Type: "endpoint"},
			ExplorationNode{ID: f, Type: "finding"})
		add("target", ep, "discovered")
		add(ep, f, "proves")
	}
	g.Stats = explorationStatsOf(g.Nodes)
	return g
}

func TestExplorationCombinedBudgetTrimming(t *testing.T) {
	small := syntheticCombinedGraph(2, 3) // 8 nodes
	big := syntheticCombinedGraph(10, 200)
	huge := syntheticCombinedGraph(20, 400)
	lanes := []*combinedLane{
		{group: CombinedGroup{ID: "g0"}, rec: &ScanRecord{}, graph: small, scope: "findings"},
		{group: CombinedGroup{ID: "g1"}, rec: &ScanRecord{}, graph: big, scope: "findings"},
		{group: CombinedGroup{ID: "g2"}, rec: &ScanRecord{}, graph: huge, scope: "findings"},
	}
	const budget = 200
	out := assembleExplorationCombined(lanes, "findings", budget)
	if !out.Truncated {
		t.Fatal("top-level truncated not set")
	}
	if len(out.Nodes) > budget {
		t.Fatalf("over budget: %d", len(out.Nodes))
	}
	assertCombinedConsistent(t, out)
	if out.Groups[0].Truncated || !out.Groups[1].Truncated || !out.Groups[2].Truncated {
		t.Fatalf("group truncated flags: %+v", out.Groups)
	}
	have := map[string]bool{}
	edges := map[string]bool{}
	for _, n := range out.Nodes {
		have[n.ID] = true
	}
	for _, e := range out.Edges {
		edges[e.Source+"->"+e.Target] = true
	}
	// Every finding and its endpoint chain back to the target is kept.
	for gi, nf := range []int{2, 10, 20} {
		p := "g" + strconv.Itoa(gi) + ":"
		for i := 0; i < nf; i++ {
			f := p + "finding:F-" + strconv.Itoa(i)
			ep := p + "endpoint:/p" + strconv.Itoa(i)
			if !have[f] || !have[ep] || !edges[p+"target->"+ep] || !edges[ep+"->"+f] {
				t.Fatalf("finding chain %s not kept", f)
			}
		}
	}
	if out.Groups[0].Stats.Findings != 2 || out.Groups[2].Stats.Findings != 20 {
		t.Fatalf("stats after trim: %+v", out.Groups)
	}
	if out.Groups[2].Stats != explorationStatsOf(nodesOfGroup(out, "g2")) {
		t.Fatalf("stats not recounted: %+v", out.Groups[2].Stats)
	}

	// Under budget: nothing changes.
	lanes = []*combinedLane{{group: CombinedGroup{ID: "g0"}, rec: &ScanRecord{}, graph: syntheticCombinedGraph(3, 3)}}
	if out := assembleExplorationCombined(lanes, "findings", budget); out.Truncated || len(out.Nodes) != 10 {
		t.Fatalf("under budget changed: truncated=%v nodes=%d", out.Truncated, len(out.Nodes))
	}
}

func nodesOfGroup(out *ExplorationCombined, gid string) []ExplorationNode {
	var ns []ExplorationNode
	for _, n := range out.Nodes {
		if n.Group == gid {
			ns = append(ns, n.ExplorationNode)
		}
	}
	return ns
}

func TestExplorationCombinedFairShares(t *testing.T) {
	mk := func(n int) *combinedLane {
		g := &ExplorationGraph{Nodes: make([]ExplorationNode, n)}
		return &combinedLane{graph: g}
	}
	lanes := []*combinedLane{mk(10), mk(500), {}, mk(1000)}
	caps := combinedFairShares(lanes, 300)
	if caps[0] != 10 || caps[1] != 145 || caps[2] != 0 || caps[3] != 145 {
		t.Fatalf("caps = %v", caps)
	}
}

func TestExplorationCombinedRebuildsAllAsFindings(t *testing.T) {
	dir := egFixture(t)
	rec, ok := readScanSummary(filepath.Join(dir, "scan.json"))
	if !ok {
		t.Fatal("fixture record")
	}
	findings, err := buildExplorationGraph(dir, rec, "findings")
	if err != nil {
		t.Fatal(err)
	}
	all, err := buildExplorationGraph(dir, rec, "all")
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Nodes) <= len(findings.Nodes) {
		t.Fatalf("fixture: all=%d findings=%d", len(all.Nodes), len(findings.Nodes))
	}
	lanes := []*combinedLane{{group: CombinedGroup{ID: "g0"}, dir: dir, rec: rec, graph: all, scope: "all"}}
	out := assembleExplorationCombined(lanes, "all", len(findings.Nodes))
	if !out.Truncated || !out.Groups[0].Truncated {
		t.Fatalf("truncated flags: %v %+v", out.Truncated, out.Groups[0])
	}
	if len(out.Nodes) != len(findings.Nodes) || lanes[0].scope != "findings" {
		t.Fatalf("lane not rebuilt as findings: nodes=%d scope=%s", len(out.Nodes), lanes[0].scope)
	}
	assertCombinedConsistent(t, out)
}
