package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"github.com/barhaterahul/ai-dast-ing/v4/internal/storage"
)

// deletedFindingsFile records finding IDs an operator deleted from a scan.
//
// A running scan holds its own in-memory copy of the scan record and saves it
// on every new finding and again at cleanup, re-merging the agent's reporting
// store. Removing a finding from scan.json alone therefore let it come back
// on the next save. Every write of scan.json goes through saveScanRecordTo,
// which filters these IDs out, so a deletion sticks no matter which copy of
// the record is saved — including after a restart or resume.
const deletedFindingsFile = "deleted_findings.json"

// readFindingTombstones returns the deleted finding IDs for a scan dir. A
// missing or unreadable file yields an empty set.
func readFindingTombstones(scanDir string) map[string]bool {
	if scanDir == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(scanDir, deletedFindingsFile))
	if err != nil {
		return nil
	}
	var ids []string
	if json.Unmarshal(data, &ids) != nil {
		return nil
	}
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id != "" {
			out[id] = true
		}
	}
	return out
}

// addFindingTombstone durably records vulnID as deleted for scanDir.
func addFindingTombstone(scanDir, vulnID string) error {
	if scanDir == "" || vulnID == "" {
		return nil
	}
	set := readFindingTombstones(scanDir)
	if set == nil {
		set = map[string]bool{}
	}
	if set[vulnID] {
		return nil
	}
	set[vulnID] = true
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	data, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	return storage.WriteAtomic(filepath.Join(scanDir, deletedFindingsFile), data)
}

// withoutTombstoned returns vulns minus any ID in tombstones, reusing the
// original slice when nothing is removed.
func withoutTombstoned(vulns []VulnSummary, tombstones map[string]bool) []VulnSummary {
	if len(tombstones) == 0 {
		return vulns
	}
	removed := false
	for _, v := range vulns {
		if tombstones[v.ID] {
			removed = true
			break
		}
	}
	if !removed {
		return vulns
	}
	out := make([]VulnSummary, 0, len(vulns))
	for _, v := range vulns {
		if !tombstones[v.ID] {
			out = append(out, v)
		}
	}
	return out
}
