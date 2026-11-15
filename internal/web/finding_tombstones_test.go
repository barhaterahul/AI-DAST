package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Regression: deleting a finding from a running scan came back, because the
// live session re-saved its own in-memory record and the handler looked the
// instance up by record ID while live instances are keyed by instance ID.
func TestDeleteVulnSticksAgainstLiveSessionResave(t *testing.T) {
	s := newTestServer(t, nil)
	rel := "example/2026-11-14/scan-rec"
	writeScanRecord(t, s.dataDir, rel, ScanRecord{
		ID: "scan-rec", InstanceID: "inst-xyz", Target: "https://example.test",
		StartedAt: "2026-11-14T10:00:00Z", Status: "running",
		Vulns: []VulnSummary{{ID: "AIDAST-1", Title: "dup"}, {ID: "AIDAST-2", Title: "keep"}},
	})
	dir := filepath.Join(s.dataDir, rel)
	inst := &ScanInstance{ID: "inst-xyz", Status: "running", scanDir: dir,
		Vulns: []VulnSummary{{ID: "AIDAST-1"}, {ID: "AIDAST-2"}}, VulnCount: 2}
	s.instancesMu.Lock()
	s.instances["inst-xyz"] = inst
	s.instancesMu.Unlock()

	rr := httptest.NewRecorder()
	s.handleDeleteVuln(rr, httptest.NewRequest(http.MethodDelete, "/api/scans/scan-rec/vulns/AIDAST-1", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("delete code=%d body=%s", rr.Code, rr.Body.String())
	}
	// The live instance (keyed by instance ID) must be updated too.
	inst.mu.RLock()
	if len(inst.Vulns) != 1 || inst.Vulns[0].ID != "AIDAST-2" || inst.VulnCount != 1 {
		t.Fatalf("live instance not updated: %+v count=%d", inst.Vulns, inst.VulnCount)
	}
	inst.mu.RUnlock()

	// Simulate the running session saving its stale in-memory copy.
	stale := &ScanRecord{ID: "scan-rec", InstanceID: "inst-xyz", Target: "https://example.test", Status: "running",
		Vulns: []VulnSummary{{ID: "AIDAST-1", Title: "dup"}, {ID: "AIDAST-2", Title: "keep"}, {ID: "AIDAST-3", Title: "new"}}}
	s.saveScanRecordTo(stale, dir)

	data, err := os.ReadFile(filepath.Join(dir, "scan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var onDisk ScanRecord
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, v := range onDisk.Vulns {
		ids[v.ID] = true
	}
	if ids["AIDAST-1"] || !ids["AIDAST-2"] || !ids["AIDAST-3"] {
		t.Fatalf("stale re-save resurrected or dropped findings: %v", ids)
	}
}

func TestWithoutTombstoned(t *testing.T) {
	in := []VulnSummary{{ID: "a"}, {ID: "b"}}
	if got := withoutTombstoned(in, nil); len(got) != 2 {
		t.Fatal("nil tombstones must keep everything")
	}
	if got := withoutTombstoned(in, map[string]bool{"a": true}); len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("got %+v", got)
	}
	dir := t.TempDir()
	if err := addFindingTombstone(dir, "x"); err != nil {
		t.Fatal(err)
	}
	_ = addFindingTombstone(dir, "x")
	if ts := readFindingTombstones(dir); len(ts) != 1 || !ts["x"] {
		t.Fatalf("tombstones = %v", ts)
	}
}
