package reporting

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/barhaterahul/ai-dast-ing/v4/internal/storage"
)

type findingCheckpoint struct {
	Version  int             `json:"version"`
	ScanID   string          `json:"scan_id"`
	Sequence int             `json:"sequence"`
	Findings []Vulnerability `json:"findings"`
}

// Finding IDs are "<prefix><n>". New scans use FindingIDPrefix; a scan that
// already holds pre-rename (xalgorix) "XALG-" findings — e.g. one resumed from
// a checkpoint — keeps that prefix so a single report never mixes XALG-15 with
// AIDAST-16 and existing ledger links (finding_ref "XALG-3") stay valid.
const (
	FindingIDPrefix       = "AIDAST-"
	legacyFindingIDPrefix = "XALG-"
)

// findingIDNumber returns the sequence number of a finding ID in either the
// current or the legacy format.
func findingIDNumber(id string) (int, bool) {
	for _, prefix := range []string{FindingIDPrefix, legacyFindingIDPrefix} {
		if rest, ok := strings.CutPrefix(id, prefix); ok {
			if n, err := strconv.Atoi(rest); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

// findingIDPrefixFor picks the prefix for new IDs in a store holding vulns.
func findingIDPrefixFor(vulns []Vulnerability) string {
	for _, v := range vulns {
		if strings.HasPrefix(v.ID, legacyFindingIDPrefix) {
			return legacyFindingIDPrefix
		}
	}
	return FindingIDPrefix
}

func nextFindingIDLocked(store *vulnStore) string {
	used := make(map[string]bool, len(store.vulns))
	for _, v := range store.vulns {
		used[v.ID] = true
		if n, ok := findingIDNumber(v.ID); ok && n > store.nextSequence {
			store.nextSequence = n
		}
	}
	prefix := findingIDPrefixFor(store.vulns)
	for {
		store.nextSequence++
		id := fmt.Sprintf("%s%d", prefix, store.nextSequence)
		if !used[id] {
			return id
		}
	}
}

func (store *vulnStore) persistLocked() error {
	if store.persistPath == "" {
		return nil
	}
	data, err := json.Marshal(findingCheckpoint{1, store.scanID, store.nextSequence, store.vulns})
	if err != nil {
		return err
	}
	return storage.WriteAtomic(store.persistPath, data)
}

// RestoreContext restores deduplication and identity state before the first
// report. Existing legacy collisions are preserved; new IDs exceed every
// saved sequence, including gaps, rather than restarting at list length.
func RestoreContext(contextID, dir string, legacy []Vulnerability) error {
	if contextID == "" || dir == "" {
		return nil
	}
	if err := storage.EnsureSecureDir(dir); err != nil {
		return err
	}
	store := getStoreForContext(contextID)
	store.mu.Lock()
	defer store.mu.Unlock()
	store.persistPath = filepath.Join(dir, "findings.json")
	store.scanID = contextID
	data, err := os.ReadFile(store.persistPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		var saved findingCheckpoint
		if err := json.Unmarshal(data, &saved); err != nil {
			return err
		}
		if saved.Version != 1 || saved.ScanID != contextID || saved.Sequence < 0 {
			return fmt.Errorf("invalid or incompatible finding checkpoint")
		}
		store.vulns = saved.Findings
		store.nextSequence = saved.Sequence
	}
	for _, v := range legacy {
		mergeRestoredFinding(store, v)
	}
	return store.persistLocked()
}

// RemoveVulnerabilityFromContext deletes every finding with vulnID from a
// context's store and rewrites its checkpoint, returning how many were
// removed. The web layer calls it when an operator deletes a finding: scan
// records are re-merged from this store when a scan finishes or resumes, so
// deleting only from the record let the finding come back. The sequence
// counter is untouched, so a deleted ID is never reissued. A context with no
// store is a no-op.
func RemoveVulnerabilityFromContext(contextID, vulnID string) (int, error) {
	if contextID == "" || vulnID == "" {
		return 0, nil
	}
	storesMu.RLock()
	store, ok := stores[contextID]
	storesMu.RUnlock()
	if !ok {
		return 0, nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	kept := store.vulns[:0:0]
	removed := 0
	for _, v := range store.vulns {
		if v.ID == vulnID {
			removed++
			continue
		}
		kept = append(kept, v)
	}
	if removed == 0 {
		return 0, nil
	}
	store.vulns = kept
	return removed, store.persistLocked()
}

// RemoveVulnerabilityFromCheckpoint deletes vulnID from the findings.json
// checkpoint in scanDir, for scans with no live store (finished or stopped),
// so a later resume cannot restore a finding the operator deleted. A missing
// checkpoint or absent ID is a no-op. The sequence counter is preserved.
func RemoveVulnerabilityFromCheckpoint(scanDir, vulnID string) (int, error) {
	if scanDir == "" || vulnID == "" {
		return 0, nil
	}
	path := filepath.Join(scanDir, "findings.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var saved findingCheckpoint
	if err := json.Unmarshal(data, &saved); err != nil {
		return 0, err
	}
	kept := saved.Findings[:0:0]
	removed := 0
	for _, v := range saved.Findings {
		if v.ID == vulnID {
			removed++
			continue
		}
		kept = append(kept, v)
	}
	if removed == 0 {
		return 0, nil
	}
	saved.Findings = kept
	out, err := json.Marshal(saved)
	if err != nil {
		return 0, err
	}
	return removed, storage.WriteAtomic(path, out)
}
