package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// FuzzExplorationGraph feeds arbitrary finding/ledger/event strings through the
// builder: it must never panic and must never emit an edge whose endpoints are
// missing from the node list. The seeds run as part of the normal test suite.
func FuzzExplorationGraph(f *testing.F) {
	f.Add("http://localhost:8080/shop", "/api/account/{accountId}", "POST POST", "XSS in q",
		"curl -X POST 'http://localhost:8080/x?q=<svg>' -d 'a=1'", "GET/POST /x/:id", "accountId (path)",
		"POST /x HTTP/1.1\n\n{\"a\":\"'--\"}", "SQLState 42X01 Apache Derby", `{"type":"tool_call","tool_name":"terminal","tool_args":{"command":"curl /x"}}`)
	f.Add("", "", "", "", "", "", "", "", "", "")
	f.Add("localhost:8080", "localhost:8080", "{", "}", "-d", "-H", "none (n/a)", "GET", "<!DOCTYPE x [<!ENTITY", "{")
	f.Add("http://[::1", "//evil", "\x00", "'\"", "curl '", "<id>", "{x", "GET http://", "\n\n\n", `{"tool_args":"x"}`)
	f.Fuzz(func(t *testing.T, target, endpoint, method, title, poc, hypEndpoint, param, req, resp, event string) {
		dir := t.TempDir()
		rec := map[string]any{
			"id": "s", "target": target, "status": "running",
			"vulns": []map[string]any{
				{"id": "F-1", "title": title, "severity": "high", "endpoint": endpoint, "method": method,
					"poc_description": poc, "poc_script": req, "exploitation_proof": resp, "technical_analysis": resp},
				{"id": "F-2", "title": title, "severity": "low", "endpoint": hypEndpoint, "method": method},
			},
		}
		ledger := map[string]any{"hypotheses": []map[string]any{
			{"id": "H-1", "title": title, "vuln_class": title, "endpoint": hypEndpoint, "parameter": param,
				"status": "proven", "dedup_key": param + "|" + endpoint + "|" + param,
				"evidence": []map[string]any{
					{"id": "E-1", "kind": "exploit", "request": req, "response": resp, "source": poc},
					{"id": "E-2", "kind": "finding_ref", "finding_id": "F-1"},
					{"id": "E-3", "kind": "baseline", "request": poc},
				}},
			{"id": "H-2", "title": param, "vuln_class": param, "endpoint": endpoint, "parameter": param, "status": "rejected",
				"evidence": []map[string]any{{"id": "E-1", "kind": "probe", "request": endpoint}}},
		}}
		for name, v := range map[string]any{"scan.json": rec, "ledger.json": ledger} {
			data, _ := json.Marshal(v)
			if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		_ = os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(event+"\n"+event), 0o600)
		for _, scope := range []string{explorationScopeFindings, explorationScopeAll} {
			g, err := buildExplorationGraph(dir, nil, scope)
			if err != nil {
				t.Fatal(err)
			}
			ids := map[string]bool{}
			for _, n := range g.Nodes {
				if ids[n.ID] {
					t.Fatalf("duplicate node id %q", n.ID)
				}
				ids[n.ID] = true
			}
			for _, e := range g.Edges {
				if !ids[e.Source] || !ids[e.Target] {
					t.Fatalf("dangling edge %q", e.ID)
				}
			}
			if _, err := json.Marshal(g); err != nil {
				t.Fatal(err)
			}
		}
	})
}
