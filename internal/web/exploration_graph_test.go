package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeEGFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const egScanJSON = `{
  "id": "scan-eg-1", "target": "http://testapp.local:8080/shop/", "status": "finished", "events": [],
  "vulns": [
    {"id": "AIDAST-1", "title": "SQL injection in login uid parameter", "severity": "Critical", "cvss": 9.8,
     "cwe_id": "CWE-89", "owasp": "A03", "endpoint": "/shop/login", "method": "POST", "verified": true,
     "verification_method": "verify_sqli",
     "technical_analysis": "The backend returned SQLState 42X01 from the database, a syntax error."},
    {"id": "AIDAST-2", "title": "Reflected XSS via the 'query' parameter", "severity": "high",
     "endpoint": "http://testapp.local:8080/shop/search?query=x", "method": "GET", "verified": false},
    {"id": "AIDAST-3", "title": "Deleted finding", "severity": "low", "endpoint": "/gone", "method": "GET"}
  ]
}`

const egLedgerJSON = `{
  "hypotheses": [
    {"id": "H-1", "dedup_key": "sqli|/shop/login|uid|", "title": "SQLi in uid", "vuln_class": "sqli",
     "endpoint": "/shop/login", "parameter": "uid", "status": "proven", "confidence": 0.95,
     "assigned_to": "agent-1", "origin": "recon", "attempts": 3, "next_action": "report",
     "evidence": [
       {"id": "E-1", "kind": "baseline", "summary": "normal login", "request": "POST /shop/login HTTP/1.1\nHost: testapp.local\n\nuid=alice&passw=x", "response": "200"},
       {"id": "E-2", "kind": "exploit", "source": "verify_sqli", "agent_id": "agent-1", "summary": "boolean based",
        "request": "POST /shop/login HTTP/1.1\nHost: testapp.local\nContent-Type: application/x-www-form-urlencoded\n\nuid=admin%27+OR+%271%27%3D%271&passw=x",
        "response": "HTTP/1.1 500\nServer: Apache-Coyote/1.1\n\njava.sql.SQLSyntaxErrorException: Syntax error SQLState: 42X01"},
       {"id": "E-3", "kind": "finding_ref", "finding_id": "AIDAST-1"}
     ]},
    {"id": "H-2", "dedup_key": "idor|/api/account/1001|acct|", "title": "IDOR account", "vuln_class": "idor",
     "endpoint": "http://testapp.local:8080/api/account/1001", "status": "rejected", "confidence": 0.1,
     "evidence": [
       {"id": "E-4", "kind": "probe", "summary": "403", "request": "GET http://testapp.local:8080/api/account/800001?acct=800001", "response": "403 Forbidden"}
     ]},
    {"id": "H-3", "title": "queued plan", "vuln_class": "ssrf", "endpoint": "/api/fetch", "status": "queued"},
    {"id": "H-4", "title": "linked to deleted", "vuln_class": "info", "endpoint": "/gone", "status": "proven",
     "evidence": [{"id": "E-5", "kind": "finding_ref", "finding_id": "AIDAST-3"}]}
  ]
}`

const egExecGraphJSON = `{"version":1,"agents":[
  {"id":"agent-1","name":"injection-specialist","task":"Test injection on login\nmore detail"},
  {"id":"agent-2","name":"idle-lane","task":"nothing"}
]}`

const egEventsJSONL = `{"event_id":"ev-1","type":"message","content":"starting /shop/login","agent_id":"root"}
{"event_id":"ev-2","type":"tool_call","tool_name":"add_hypothesis","tool_args":{"endpoint":"/shop/login"},"agent_id":"agent-1"}
{"event_id":"ev-3","type":"tool_call","tool_name":"http_request","tool_args":{"url":"http://testapp.local:8080/shop/login.jsp","method":"GET"},"agent_id":"agent-1","timestamp":"2026-01-01T00:00:00Z"}
{"event_id":"ev-4","type":"tool_result","tool_name":"http_request","output":"<form action=\"/shop/login\" method=\"post\">","agent_id":"agent-1"}
{"event_id":"ev-5","type":"tool_call","tool_name":"terminal","tool_args":{"command":"curl 'http://testapp.local:8080/shop/search?query=a'"},"agent_id":"root"}
{"event_id":"ev-6","type":"tool_call","tool_name":"terminal","tool_args":{"command":
`

func egFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeEGFile(t, dir, "scan.json", egScanJSON)
	writeEGFile(t, dir, "ledger.json", egLedgerJSON)
	writeEGFile(t, dir, "execution-graph.json", egExecGraphJSON)
	writeEGFile(t, dir, "events.jsonl", egEventsJSONL) // last line deliberately partial
	writeEGFile(t, dir, deletedFindingsFile, `["AIDAST-3"]`)
	return dir
}

func egIndex(g *ExplorationGraph) (map[string]ExplorationNode, map[string]bool) {
	nodes := map[string]ExplorationNode{}
	for _, n := range g.Nodes {
		nodes[n.ID] = n
	}
	edges := map[string]bool{}
	for _, e := range g.Edges {
		edges[e.Kind+" "+e.Source+" -> "+e.Target] = true
		if _, ok := nodes[e.Source]; !ok {
			panic("edge source missing: " + e.ID)
		}
		if _, ok := nodes[e.Target]; !ok {
			panic("edge target missing: " + e.ID)
		}
	}
	return nodes, edges
}

func TestExplorationGraphLedgerChain(t *testing.T) {
	dir := egFixture(t)
	g, err := buildExplorationGraph(dir, nil, "findings")
	if err != nil {
		t.Fatal(err)
	}
	nodes, edges := egIndex(g)
	if g.ScanID != "scan-eg-1" || g.Scope != "findings" || g.Truncated {
		t.Fatalf("bad header: %+v", g)
	}
	want := []string{
		"assigned target -> agent:agent-1",
		"discovered agent:agent-1 -> discovery:ev-3",
		"discovered discovery:ev-3 -> endpoint:/shop/login",
		"exposes endpoint:/shop/login -> parameter:/shop/login#uid",
		"tested parameter:/shop/login#uid -> attempt:H-1",
		"injected attempt:H-1 -> evidence:H-1/E-2",
		"proves evidence:H-1/E-2 -> finding:AIDAST-1",
		"reveals finding:AIDAST-1 -> backend:apache-derby",
		"reveals evidence:H-1/E-2 -> backend:apache-derby",
		"reveals evidence:H-1/E-2 -> backend:apache-tomcat",
	}
	for _, w := range want {
		if !edges[w] {
			t.Errorf("missing edge %q", w)
		}
	}
	ep := nodes["endpoint:/shop/login"]
	if ep.Data["method"] != "POST" || ep.Label != "POST /shop/login" {
		t.Errorf("endpoint method/label: %+v", ep)
	}
	if p := nodes["parameter:/shop/login#uid"]; p.Data["location"] != "body" {
		t.Errorf("param location = %v", p.Data["location"])
	}
	ev := nodes["evidence:H-1/E-2"]
	if ev.Data["payload"] != "admin' OR '1'='1" {
		t.Errorf("payload = %q", ev.Data["payload"])
	}
	if ev.Verified == nil || !*ev.Verified {
		t.Errorf("engine-verified evidence should be verified")
	}
	if _, ok := nodes["evidence:H-1/E-1"]; ok {
		t.Errorf("baseline evidence must not appear in findings scope")
	}
	f := nodes["finding:AIDAST-1"]
	if f.Severity != "critical" || f.Verified == nil || !*f.Verified || f.Data["cwe"] != "CWE-89" {
		t.Errorf("finding node: %+v", f)
	}
	if got := nodes["attempt:H-1"].FindingIDs; len(got) != 1 || got[0] != "AIDAST-1" {
		t.Errorf("finding_ids propagation: %v", got)
	}
	if got := nodes["backend:apache-derby"]; got.Data["category"] != "database" || !strings.Contains(got.Data["indicator"].(string), "42X01") {
		t.Errorf("derby backend: %+v", got)
	}
	a := nodes["agent:agent-1"]
	if lanes, _ := a.Data["lane_classes"].([]string); len(lanes) != 1 || lanes[0] != "sqli" {
		t.Errorf("lane_classes = %v", a.Data["lane_classes"])
	}
	if a.Data["task_summary"] != "Test injection on login" {
		t.Errorf("task_summary = %v", a.Data["task_summary"])
	}
	if _, ok := nodes["agent:agent-2"]; ok {
		t.Errorf("unreferenced agent included in findings scope")
	}
	if _, ok := nodes["discovery:ev-2"]; ok {
		t.Errorf("bookkeeping tool counted as discovery")
	}
	if g.Stats.Findings != 2 || g.Stats.Verified != 1 || g.Stats.Proven != 1 || g.Stats.Attempts != 1 {
		t.Errorf("stats = %+v", g.Stats)
	}
}

func TestExplorationGraphUnlinkedFindingAndTombstone(t *testing.T) {
	dir := egFixture(t)
	g, _ := buildExplorationGraph(dir, nil, "findings")
	nodes, edges := egIndex(g)
	if _, ok := nodes["finding:AIDAST-3"]; ok {
		t.Fatal("tombstoned finding present")
	}
	if _, ok := nodes["attempt:H-4"]; ok {
		t.Fatal("hypothesis linked only to a tombstoned finding present in findings scope")
	}
	for _, w := range []string{
		"exposes endpoint:/shop/search -> parameter:/shop/search#query",
		"proves parameter:/shop/search#query -> finding:AIDAST-2",
		"discovered target -> discovery:ev-5",
		"discovered discovery:ev-5 -> endpoint:/shop/search",
	} {
		if !edges[w] {
			t.Errorf("missing edge %q", w)
		}
	}
	if p := nodes["parameter:/shop/search#query"]; p.Data["location"] != "query" {
		t.Errorf("location = %v", p.Data["location"])
	}
}

func TestExplorationGraphScopeAll(t *testing.T) {
	dir := egFixture(t)
	g, _ := buildExplorationGraph(dir, nil, "all")
	nodes, edges := egIndex(g)
	if g.Scope != "all" {
		t.Fatalf("scope = %q", g.Scope)
	}
	if _, ok := nodes["attempt:H-3"]; ok {
		t.Error("queued hypothesis must never be included")
	}
	att, ok := nodes["attempt:H-2"]
	if !ok || att.Status != "rejected" {
		t.Fatalf("rejected attempt missing or wrong status: %+v", att)
	}
	// The target lives under /shop, so the context-relative
	// "/api/account/1001" is normalized under that context path.
	if !edges["tested endpoint:/shop/api/account/{id} -> attempt:H-2"] && !edges["tested parameter:/shop/api/account/{id}#acct -> attempt:H-2"] {
		t.Error("templated endpoint not linked to rejected attempt")
	}
	if ev := nodes["evidence:H-2/E-4"]; ev.Data["payload"] != "800001" {
		t.Errorf("probe payload = %v", ev.Data["payload"])
	}
	if _, ok := nodes["evidence:H-1/E-1"]; !ok {
		t.Error("baseline evidence should appear in scope=all")
	}
	if _, ok := nodes["agent:agent-2"]; !ok {
		t.Error("scope=all should list all agents")
	}
	if len(nodes["attempt:H-2"].FindingIDs) != 0 {
		t.Error("rejected attempt should not carry finding ids")
	}
}

func TestExplorationEndpointNormalization(t *testing.T) {
	b := &explorationBuilder{targetHost: "testapp.local:8080"}
	cases := []struct{ in, method, wantM, wantP string }{
		{"/api/account/1001", "", "", "/api/account/{id}"},
		{"http://testapp.local:8080/bank/transactions?x=1#f", "post", "POST", "/bank/transactions"},
		{"GET /users/550e8400-e29b-41d4-a716-446655440000/profile", "", "GET", "/users/{id}/profile"},
		{"search", "", "", "/search"},
		{"https://other.example/a/1", "", "", "//other.example/a/{id}"},
		{"/Mixed/Case/", "", "", "/Mixed/Case"},
		{"", "", "", ""},
	}
	for _, c := range cases {
		m, p, _ := b.normalizeEndpoint(c.in, c.method)
		if m != c.wantM || p != c.wantP {
			t.Errorf("normalize(%q,%q) = (%q,%q), want (%q,%q)", c.in, c.method, m, p, c.wantM, c.wantP)
		}
	}
}

func TestExplorationPayloadExtraction(t *testing.T) {
	cases := []struct{ req, param, want, loc string }{
		{"GET /search?query=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\nHost: x", "query", "<script>alert(1)</script>", "query"},
		{"POST /api HTTP/1.1\nContent-Type: application/json\n\n{\"user\":{\"name\":\"' OR 1=1--\"}}", "name", "' OR 1=1--", "body"},
		{`curl -s -X POST 'http://h/login' -d 'uid=a%27--&passw=1'`, "uid", "a'--", "body"},
		{`curl -H 'Cookie: session=abc; lang=..%2F..%2Fetc' http://h/`, "lang", "../../etc", "cookie"},
		{"GET /x HTTP/1.1\nX-Forwarded-Host: evil.example\n\n", "X-Forwarded-Host", "evil.example", "header"},
		{"sent payload id=1%20UNION%20SELECT to endpoint", "id", "1 UNION SELECT", "unknown"},
	}
	for _, c := range cases {
		p := parseRequestEG(c.req)
		got, loc := extractParamValueEG(p, c.req, c.param)
		if got != c.want || loc != c.loc {
			t.Errorf("extract(%q, %q) = (%q,%q), want (%q,%q)", c.req, c.param, got, loc, c.want, c.loc)
		}
	}
}

func TestExplorationBackendDetection(t *testing.T) {
	cases := []struct{ text, name, category string }{
		{"ERROR 42X01: Syntax error. SQLState: 42X01", "Apache Derby", "database"},
		{"You have an error in your SQL syntax; check the manual", "MySQL", "database"},
		{"ORA-00933: SQL command not properly ended", "Oracle", "database"},
		{"Server: Apache-Coyote/1.1", "Apache Tomcat", "server"},
		{"Server: nginx/1.25.3", "nginx", "server"},
		{"Server: Apache/2.4.58 (Ubuntu)", "Apache httpd", "server"},
		{"X-Powered-By: Express", "Express", "server"},
		{"org.springframework.web.servlet.DispatcherServlet", "Spring", "framework"},
		{"root:x:0:0:root:/root:/bin/bash", "Linux/Unix", "os"},
		{"javax.xml.parsers.DocumentBuilderFactory resolved the external entity", "Java XML parser", "parser"},
		{"cf-ray: 8a1b2c3d4e5f-AMS", "Cloudflare", "waf"},
		{"X-Powered-By: PHP/8.2.1", "PHP", "language"},
	}
	for _, c := range cases {
		hits := detectBackends(c.text)
		found := false
		for _, h := range hits {
			if h.Name == c.name && h.Category == c.category && h.Indicator != "" {
				found = true
			}
		}
		if !found {
			t.Errorf("detectBackends(%q) = %+v, want %s/%s", c.text, hits, c.category, c.name)
		}
	}
	// Ordinary English must not trigger case-sensitive rules.
	for _, h := range detectBackends("Please express your concerns via the phone.") {
		t.Errorf("false positive: %+v", h)
	}
	if hits := detectBackends(""); hits != nil {
		t.Errorf("empty text hits: %+v", hits)
	}
}

func TestExplorationGraphMissingFiles(t *testing.T) {
	dir := t.TempDir()
	rec := &ScanRecord{ID: "s", Target: "https://example.test", Status: "running",
		Vulns: []VulnSummary{{ID: "F-1", Title: "Open redirect", Severity: "medium", Endpoint: "/r?next=x"}}}
	g, err := buildExplorationGraph(dir, rec, "bogus")
	if err != nil {
		t.Fatal(err)
	}
	nodes, edges := egIndex(g)
	if g.Scope != "findings" || g.Status != "running" {
		t.Fatalf("header %+v", g)
	}
	if _, ok := nodes["finding:F-1"]; !ok || !edges["proves parameter:/r#next -> finding:F-1"] || !edges["discovered target -> endpoint:/r"] {
		t.Fatalf("unlinked finding not attached: %+v %+v", g.Nodes, g.Edges)
	}
	// Corrupt files are tolerated too.
	writeEGFile(t, dir, "ledger.json", "{not json")
	writeEGFile(t, dir, "execution-graph.json", "[")
	writeEGFile(t, dir, "events.jsonl", "garbage\n{\"type\":")
	if _, err := buildExplorationGraph(dir, rec, "all"); err != nil {
		t.Fatal(err)
	}
	// No dir and no record at all.
	if g, err := buildExplorationGraph("", nil, "all"); err != nil || len(g.Nodes) != 1 {
		t.Fatalf("empty build: %v %+v", err, g)
	}
}

func TestExplorationGraphNodeCap(t *testing.T) {
	dir := t.TempDir()
	var sb strings.Builder
	sb.WriteString(`{"hypotheses":[`)
	for i := 0; i < 1600; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"id":"H` + itoaEG(i) + `","vuln_class":"xss","endpoint":"/p` + itoaEG(i) + `x","status":"rejected"}`)
	}
	sb.WriteString(`]}`)
	writeEGFile(t, dir, "ledger.json", sb.String())
	rec := &ScanRecord{ID: "s", Target: "http://h", Vulns: []VulnSummary{{ID: "F-1", Title: "t", Endpoint: "/f"}}}
	g, _ := buildExplorationGraph(dir, rec, "all")
	if !g.Truncated || len(g.Nodes) != explorationMaxNodes {
		t.Fatalf("truncated=%v nodes=%d", g.Truncated, len(g.Nodes))
	}
	nodes, _ := egIndex(g) // panics on dangling edges
	if _, ok := nodes["finding:F-1"]; !ok {
		t.Fatal("finding dropped by cap")
	}
	if _, ok := nodes["target"]; !ok {
		t.Fatal("target dropped by cap")
	}
}

func itoaEG(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func TestHandleScanGraph(t *testing.T) {
	s := newTestServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/scans/does-not-exist/graph", nil)
	w := httptest.NewRecorder()
	s.handleScanGraph(w, req)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), `"error":"scan not found"`) ||
		!strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("404 response: %d %q", w.Code, w.Body.String())
	}

	dir := filepath.Join(s.dataDir, "scan-eg-1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeEGFile(t, dir, "scan.json", egScanJSON)
	writeEGFile(t, dir, "ledger.json", egLedgerJSON)
	s.invalidateScanListCache()

	req = httptest.NewRequest(http.MethodGet, "/api/scans/scan-eg-1/graph?scope=all", nil)
	w = httptest.NewRecorder()
	s.handleScanGraph(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var g ExplorationGraph
	if err := json.Unmarshal(w.Body.Bytes(), &g); err != nil {
		t.Fatal(err)
	}
	if g.ScanID != "scan-eg-1" || g.Scope != "all" || g.Stats.Findings != 3 {
		// AIDAST-3 is not tombstoned in this fixture (no deleted_findings.json).
		t.Fatalf("graph header/stats: %+v", g.Stats)
	}
}

// ---- regressions found against a real scan ----

func TestExplorationEndpointContextPathAndMessyInput(t *testing.T) {
	b := &explorationBuilder{targetHost: "localhost:8080", basePath: "/shop"}
	cases := []struct{ in, method, wantM, wantP string }{
		// context-relative spelling merges with the full one
		{"/bank/account-summary", "", "", "/shop/bank/account-summary"},
		{"/shop/bank/account-summary?acct=1001", "GET", "GET", "/shop/bank/account-summary"},
		{"http://localhost:8080/shop/bank/account-summary", "", "", "/shop/bank/account-summary"},
		// scheme-less host
		{"localhost:8080/shop/search", "", "", "/shop/search"},
		{"partner.example.com", "", "", "//partner.example.com"},
		// duplicated / combined methods, placeholder segments
		{"POST POST /shop/bank/transactions", "POST", "POST", "/shop/bank/transactions"},
		{"/shop/api/account/{accountId} and /shop/api/transfer", "GET/POST", "GET", "/shop/api/account/{id}"},
		{"GET/POST /api/account/:id/transactions", "", "GET", "/shop/api/account/{id}/transactions"},
		// well-known root files keep their root path
		{"/.well-known/openid-configuration", "", "", "/.well-known/openid-configuration"},
		// relative file
		{"search", "", "", "/shop/search"},
	}
	for _, c := range cases {
		m, p, _ := b.normalizeEndpoint(c.in, c.method)
		if m != c.wantM || p != c.wantP {
			t.Errorf("normalize(%q,%q) = (%q,%q), want (%q,%q)", c.in, c.method, m, p, c.wantM, c.wantP)
		}
	}
	for in, want := range map[string]string{
		"http://h:8080/shop":             "/shop",
		"http://h:8080/shop/":            "/shop",
		"http://h/app/login.php":         "/app",
		"http://h/":                      "",
		"https://h":                      "",
		"http://testapp.local:8080/shop": "/shop",
	} {
		if got := basePathEG(in); got != want {
			t.Errorf("basePathEG(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExplorationCleanParamHint(t *testing.T) {
	cases := []struct{ in, name, hint string }{
		{"accountId (path)", "accountId", "path"},
		{"none (route-level ROLE enforcement missing)", "", ""},
		{"XML body (DOCTYPE SYSTEM)", "XML body", "body"},
		{"tech stack markers", "", ""},
		{"SPF/DMARC/DKIM/MX records", "", ""},
		{"'query'", "query", ""},
		{"startDate", "startDate", ""},
		{"N/A", "", ""},
	}
	for _, c := range cases {
		n, h := cleanParamHintEG(c.in)
		if n != c.name || h != c.hint {
			t.Errorf("cleanParamHintEG(%q) = (%q,%q), want (%q,%q)", c.in, n, h, c.name, c.hint)
		}
	}
}

func TestExplorationProsePayloads(t *testing.T) {
	cases := []struct {
		text, param string
		inject      bool
		want        string
	}{
		// prefers the injected occurrence over the baseline
		{"BASELINE: POST startDate=2000-01-01&endDate=2030-12-31 -> 200\n2) Repeat with startDate=2000-01-01' ORDER BY 1 -- to see the same", "startDate", true, "2000-01-01' ORDER BY 1 --"},
		// markup with quoted '>' free attributes, followed by prose
		{`1) Host a form POSTing name=<img src=x onerror="console.log('XV');document.title='XV'"> to /feedback.`, "name", true, `<img src=x onerror="console.log('XV');document.title='XV'">`},
		// an unbalanced quote belongs to the prose
		{`GET account-summary acct=1001" — response contains "Account History"`, "acct", false, "1001"},
		// injection families never fall back to a baseline value
		{"body: cfile=comments.txt&name=Benign+Tester&comments=normal+text+control", "comments", true, ""},
		// URL in prose is parsed properly (decoded)
		{"verified at http://h/search?query=%3Cscript%3Ealert(1)%3C%2Fscript%3E now", "query", true, "<script>alert(1)</script>"},
		// JSON mention
		{`sent {"user":"' OR 1=1--","x":1}`, "user", true, "' OR 1=1--"},
		// a body-level parameter returns the entity-carrying body, not the control
		{"control: curl -s -X POST http://h/f -d '<?xml version=\"1.0\"?><a>benign</a>'\nexploit: curl -s -X POST http://h/f -d '<?xml version=\"1.0\"?><!DOCTYPE a SYSTEM \"http://oob\"><a/>'", "XML body", true, `<?xml version="1.0"?><!DOCTYPE a SYSTEM "http://oob"><a/>`},
	}
	for _, c := range cases {
		if got := payloadFromTextEG(c.text, c.param, c.inject); got != c.want {
			t.Errorf("payloadFromTextEG(%q, %q) = %q, want %q", c.text, c.param, got, c.want)
		}
	}
	// prose like "loggedIn=false" and base64 padding are not parameters
	v := &VulnSummary{ExploitationProof: `anon -> HTTP 401 "loggedIn=false / Please log in first"; token b'anNtaXRo:ZGVtbzEyMzQ=:Gs...'`}
	if p := paramFromProofEG(v); p != "" {
		t.Errorf("paramFromProofEG picked %q from prose", p)
	}
	v = &VulnSummary{PoCDescription: "POST startDate=2000-01-01&endDate=2030-12-31' UNION SELECT NULL FROM SYSIBM.SYSDUMMY1 --"}
	if p := paramFromProofEG(v); p != "endDate" {
		t.Errorf("paramFromProofEG = %q, want endDate", p)
	}
	b := &explorationBuilder{basePath: "/shop"}
	if got := b.pathValueFromTextEG("GET /api/account/1001/transactions -> 200", "/shop/api/account/{id}/transactions"); got != "1001" {
		t.Errorf("pathValueFromTextEG = %q", got)
	}
}

const egMislinkScanJSON = `{
  "id": "scan-eg-2", "target": "http://app.local:8080/bank", "status": "running", "events": [],
  "vulns": [
    {"id": "F-1", "title": "IDOR: user reads any account via REST API", "severity": "medium", "cwe_id": "CWE-639",
     "endpoint": "http://app.local:8080/bank/api/account/1001", "method": "GET",
     "exploitation_proof": "GET /bank/api/account/1001 as alice -> 200 foreign account"},
    {"id": "F-2", "title": "Error-based SQL injection in transaction date filter", "severity": "high", "cwe_id": "CWE-89",
     "endpoint": "POST /bank/transactions", "method": "POST",
     "poc_description": "1) Login. 2) POST startDate=2000-01-01&endDate=2030-12-31 baseline. 3) POST startDate=2000-01-01' ORDER BY 1 -- and observe Derby 42X01."},
    {"id": "F-3", "title": "Default credentials admin:admin", "severity": "critical", "cwe_id": "CWE-798",
     "endpoint": "/bank/api/login", "method": "POST",
     "exploitation_proof": "REQUEST: POST /bank/api/login  Content-Type: application/json  {\"username\":\"admin\",\"password\":\"admin\"}\nRESPONSE 200"}
  ]
}`

const egMislinkLedgerJSON = `{"hypotheses": [
  {"id": "H-10", "title": "SSRF in HostName", "vuln_class": "ssrf", "endpoint": "/bank/util/serverStatusCheckService.jsp",
   "parameter": "HostName", "status": "proven", "confidence": 0.9,
   "evidence": [{"id": "EV-1", "kind": "finding_ref", "finding_id": "F-1"}]},
  {"id": "H-11", "title": "IDOR account path", "vuln_class": "idor", "endpoint": "/api/account/1001",
   "parameter": "accountId (path)", "status": "proven", "confidence": 0.8, "evidence": []},
  {"id": "H-12", "title": "SQLi startDate", "vuln_class": "sqli", "endpoint": "/bank/transactions",
   "parameter": "startDate", "status": "proven", "confidence": 1, "evidence": []}
]}`

func TestExplorationGraphMislinkedRefsAndInferredLinks(t *testing.T) {
	dir := t.TempDir()
	writeEGFile(t, dir, "scan.json", egMislinkScanJSON)
	writeEGFile(t, dir, "ledger.json", egMislinkLedgerJSON)
	writeEGFile(t, dir, "events.jsonl",
		`{"event_id":"e1","type":"tool_call","tool_name":"terminal_execute","tool_args":{"command":"python3 -c \"import json;print(json.load(open('ledger.json')))\""},"agent_id":"a"}
{"event_id":"e2","type":"tool_result","output":"/bank/transactions /bank/api/login","agent_id":"a"}
{"event_id":"e3","type":"tool_call","tool_name":"terminal_execute","tool_args":{"command":"curl -s http://app.local:8080/bank/transactions"},"agent_id":"a"}
`)
	g, err := buildExplorationGraph(dir, nil, "findings")
	if err != nil {
		t.Fatal(err)
	}
	nodes, edges := egIndex(g)

	// The SSRF hypothesis's finding_ref to an IDOR on another endpoint is
	// implausible and dropped; the IDOR hypothesis on the same (context-
	// relative) endpoint is inferred instead.
	if _, ok := nodes["attempt:H-10"]; ok {
		t.Error("mis-linked SSRF hypothesis should not appear in findings scope")
	}
	if !edges["tested parameter:/bank/api/account/{id}#accountId -> attempt:H-11"] {
		t.Error("IDOR finding not attached to the inferred hypothesis H-11")
	}
	if p := nodes["parameter:/bank/api/account/{id}#accountId"]; p.Data["location"] != "path" {
		t.Errorf("accountId location = %v, want path", p.Data["location"])
	}
	// No exploit evidence in the ledger: the finding's own proof becomes the
	// evidence step and carries the concrete value.
	ev, ok := nodes["evidence:F-1/proof"]
	if !ok || ev.Data["payload"] != "1001" || ev.Data["source"] != "report" {
		t.Errorf("F-1 proof evidence = %+v", ev)
	}
	if !edges["injected attempt:H-11 -> evidence:F-1/proof"] || !edges["proves evidence:F-1/proof -> finding:F-1"] {
		t.Error("F-1 proof chain missing")
	}
	// SQLi: inferred link, injected (not baseline) payload.
	if ev := nodes["evidence:F-2/proof"]; ev.Data["payload"] != "2000-01-01' ORDER BY 1 --" {
		t.Errorf("F-2 payload = %v", ev.Data["payload"])
	}
	if !edges["injected attempt:H-12 -> evidence:F-2/proof"] {
		t.Error("F-2 not linked to H-12")
	}
	// Ledger-less login finding: the JSON body is the payload.
	if ev := nodes["evidence:F-3/proof"]; ev.Data["payload"] != `{"username":"admin","password":"admin"}` {
		t.Errorf("F-3 payload = %v", ev.Data["payload"])
	}
	// The ledger-reading command is bookkeeping, and its result is not
	// credited to any discovery; the real curl is the discovery.
	if _, ok := nodes["discovery:e1"]; ok {
		t.Error("bookkeeping command shown as discovery")
	}
	if !edges["discovered discovery:e3 -> endpoint:/bank/transactions"] {
		t.Error("curl discovery missing")
	}
}

func TestExplorationGraphNoProofNodeWhenEvidenceProves(t *testing.T) {
	dir := t.TempDir()
	writeEGFile(t, dir, "scan.json", `{"id":"s","target":"http://h/","vulns":[
	  {"id":"F-1","title":"Reflected XSS via the 'q' parameter","severity":"medium","endpoint":"/s","method":"GET",
	   "poc_description":"GET /s?q=<b>x</b>"}]}`)
	writeEGFile(t, dir, "ledger.json", `{"hypotheses":[
	  {"id":"H-1","vuln_class":"xss","endpoint":"/s","parameter":"q","status":"proven","evidence":[
	    {"id":"E-1","kind":"exploit","source":"verify_xss","request":"http://h/s?q=%3Cimg%20src%3Dx%3E"},
	    {"id":"E-2","kind":"finding_ref","finding_id":"F-1"}]},
	  {"id":"H-2","vuln_class":"xss","endpoint":"/s","parameter":"q","status":"proven","evidence":[
	    {"id":"E-3","kind":"finding_ref","finding_id":"F-1"}]}]}`)
	g, _ := buildExplorationGraph(dir, nil, "findings")
	nodes, edges := egIndex(g)
	if _, ok := nodes["evidence:F-1/proof"]; ok {
		t.Error("proof node added although ledger exploit evidence proves the finding")
	}
	if !edges["proves attempt:H-2 -> finding:F-1"] || !edges["proves evidence:H-1/E-1 -> finding:F-1"] {
		t.Error("expected direct proves edges")
	}
}

func TestExplorationCrossOriginEndpointURL(t *testing.T) {
	b := &explorationBuilder{
		targetURL: "http://localhost:8080/shop", targetHost: "localhost:8080",
		nodeIdx: map[string]*ExplorationNode{}, edgeSet: map[string]bool{},
		endpointSamples: map[string][]string{},
	}
	for path, want := range map[string]string{
		"//partner.example.com":  "http://partner.example.com",
		"/shop/search":           "http://localhost:8080/shop/search",
		"//other.example/a/{id}": "http://other.example/a/{id}",
	} {
		id := b.addEndpoint(path, "GET", "")
		if got := b.nodeIdx[id].Data["url"]; got != want {
			t.Errorf("endpoint %q url = %q, want %q", path, got, want)
		}
	}
}
