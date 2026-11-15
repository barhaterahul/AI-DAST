package web

import "testing"

func TestExplorationTargetKeyAndSeverity(t *testing.T) {
	for in, want := range map[string]string{
		"https://API.shop.test/v1/": "api.shop.test",
		"http://localhost:8080/app": "localhost:8080",
		"shop.test":                 "shop.test",
		"https://shop.test:443":     "shop.test",
		"":                          "",
	} {
		if got := explorationTargetKey(in); got != want {
			t.Errorf("explorationTargetKey(%q) = %q, want %q", in, got, want)
		}
	}
	c, top := severityCountsFromVulns([]VulnSummary{{Severity: "High"}, {Severity: "critical"}, {Severity: "weird"}})
	if c.Critical != 1 || c.High != 1 || c.Info != 1 || top != "critical" {
		t.Fatalf("counts=%+v top=%s", c, top)
	}
	if vulnClassOf(VulnSummary{Title: "SQL Injection in login", CWE: "CWE-89"}) != "sqli" {
		t.Fatal("classifier not wired")
	}
}
