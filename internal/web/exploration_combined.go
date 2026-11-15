package web

// Combined Exploration Graph: several scans' exploration graphs merged into one
// response so the dashboard can draw them as side-by-side lanes.
//
// GET /api/exploration/combined?scans=id1,id2,...&scope=findings|all
//
// Each scan becomes a group "g<i>" (request order). Its graph is built exactly
// like GET /api/scans/{id}/graph, then every node/edge id is prefixed "g<i>:"
// so lanes never collide. A scan that cannot be resolved is still returned as
// a group with Error set, so one stale id never fails the whole view. The total
// node count is bounded (explorationCombinedMaxNodes): large "all" lanes are
// first rebuilt as "findings", then over-budget lanes are trimmed to a fair
// share, keeping findings, backends and the path that reached each finding.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

const (
	explorationCombinedMaxScans    = 8
	explorationCombinedMaxNodes    = 3000
	explorationCombinedMaxIDLen    = 256
	explorationCombinedLabelItems  = 3
	explorationCombinedMaxEvidence = 20

	combinedErrNotFound  = "scan not found"
	combinedErrInvalidID = "invalid scan id"
	combinedErrBuild     = "failed to build graph"
)

// combinedLane is one group while the response is being assembled.
type combinedLane struct {
	group CombinedGroup
	dir   string
	rec   *ScanRecord
	graph *ExplorationGraph
	scope string
}

// handleExplorationCombined serves GET /api/exploration/combined.
func (s *Server) handleExplorationCombined(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeGraphJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	q := r.URL.Query()
	ids := parseCombinedScanIDs(q.Get("scans"))
	if len(ids) == 0 {
		writeGraphJSONError(w, http.StatusBadRequest, "scans is required")
		return
	}
	if len(ids) > explorationCombinedMaxScans {
		writeGraphJSONError(w, http.StatusBadRequest,
			"at most "+strconv.Itoa(explorationCombinedMaxScans)+" scans can be combined")
		return
	}
	scope := explorationScopeFindings
	if strings.EqualFold(strings.TrimSpace(q.Get("scope")), explorationScopeAll) {
		scope = explorationScopeAll
	}

	// One summary walk serves every id in the request.
	var summaries []scanEntry
	walked := false
	summariesOnce := func() []scanEntry {
		if !walked {
			summaries = s.findAllScanSummaries()
			walked = true
		}
		return summaries
	}

	lanes := make([]*combinedLane, 0, len(ids))
	for i, id := range ids {
		lane := &combinedLane{
			group: CombinedGroup{ID: "g" + strconv.Itoa(i), ScanID: id},
			scope: scope,
		}
		dir, rec, errMsg := s.resolveCombinedScan(id, summariesOnce)
		if errMsg != "" {
			lane.group.Error = errMsg
			lanes = append(lanes, lane)
			continue
		}
		lane.dir, lane.rec = dir, rec
		g, err := buildExplorationGraph(dir, rec, scope)
		if err != nil || g == nil {
			lane.group.Error = combinedErrBuild
			lanes = append(lanes, lane)
			continue
		}
		lane.graph = g
		lanes = append(lanes, lane)
	}

	out := assembleExplorationCombined(lanes, scope, explorationCombinedMaxNodes)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

// parseCombinedScanIDs splits the comma-separated scans parameter, trimming
// blanks and dropping duplicates while keeping request order.
func parseCombinedScanIDs(raw string) []string {
	seen := map[string]bool{}
	ids := []string{}
	for _, part := range strings.Split(raw, ",") {
		id := strings.TrimSpace(part)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids
}

// validCombinedScanID applies the same id rules as handleScanGraph.
func validCombinedScanID(id string) bool {
	return id != "" && len(id) <= explorationCombinedMaxIDLen &&
		!strings.ContainsAny(id, `/\`) && id != "." && id != ".."
}

// resolveCombinedScan resolves one scan id the way handleScanGraph does: a
// scan directory (record + live instance snapshot), else an in-memory-only
// running instance. errMsg is non-empty when the scan cannot be used.
func (s *Server) resolveCombinedScan(id string, summaries func() []scanEntry) (dir string, rec *ScanRecord, errMsg string) {
	if !validCombinedScanID(id) {
		return "", nil, combinedErrInvalidID
	}
	dir, ok := s.resolveScanDirByIDFrom(id, summaries)
	if ok {
		if loaded, ok2 := s.loadScanRecordForDetail(dir, 0); ok2 && loaded != nil {
			rec = loaded
		} else {
			rec = &ScanRecord{ID: id}
		}
		s.applyInstanceSnapshot(rec, false)
	} else {
		s.instancesMu.RLock()
		inst := s.instances[id]
		s.instancesMu.RUnlock()
		rec = s.scanRecordFromInstance(inst)
		if rec == nil {
			return "", nil, combinedErrNotFound
		}
		dir = ""
	}
	finalizeScanRecordForResponse(rec)
	if dir != "" {
		// Match the graph builder: operator-deleted findings never count.
		rec.Vulns = withoutTombstoned(rec.Vulns, readFindingTombstones(dir))
	}
	return dir, rec, ""
}

// assembleExplorationCombined applies the node budget, fills the groups,
// prefixes ids and computes cross-lane links. It is pure apart from rebuilding
// over-budget "all" lanes from their scan directory.
func assembleExplorationCombined(lanes []*combinedLane, scope string, budget int) *ExplorationCombined {
	out := &ExplorationCombined{
		Scope:  scope,
		Groups: make([]CombinedGroup, 0, len(lanes)),
		Nodes:  []CombinedNode{},
		Edges:  []ExplorationEdge{},
		Links:  []OverviewLink{},
	}

	// Step 1: shrink the largest "all" lanes to "findings" while over budget.
	if combinedNodeTotal(lanes) > budget {
		order := lanesBySizeDesc(lanes)
		for _, lane := range order {
			if combinedNodeTotal(lanes) <= budget {
				break
			}
			if lane.scope != explorationScopeAll || lane.rec == nil {
				continue
			}
			if g, err := buildExplorationGraph(lane.dir, lane.rec, explorationScopeFindings); err == nil && g != nil {
				lane.graph = g
				lane.scope = explorationScopeFindings
				lane.group.Truncated = true
				out.Truncated = true
			}
		}
	}

	// Cross-lane links use the untrimmed (post scope-reduction) graphs so a
	// shared technology is reported even if trimming hides its node.
	out.Links = combinedLinks(lanes)

	// Step 2: trim each over-budget lane to its fair share.
	if combinedNodeTotal(lanes) > budget {
		caps := combinedFairShares(lanes, budget)
		for i, lane := range lanes {
			if lane.graph == nil || len(lane.graph.Nodes) <= caps[i] {
				continue
			}
			lane.graph = trimExplorationGraph(lane.graph, caps[i])
			lane.group.Truncated = true
			out.Truncated = true
		}
	}

	for _, lane := range lanes {
		gid := lane.group.ID
		if lane.rec != nil {
			lane.group.Target = lane.rec.Target
			lane.group.Key = explorationTargetKey(lane.rec.Target)
			lane.group.Status = lane.rec.Status
			lane.group.Severity, lane.group.TopSeverity = severityCountsFromVulns(lane.rec.Vulns)
		}
		if g := lane.graph; g != nil {
			if g.Truncated {
				lane.group.Truncated = true
				out.Truncated = true
			}
			lane.group.Stats = g.Stats
			prefix := gid + ":"
			for _, n := range g.Nodes {
				n.ID = prefix + n.ID
				out.Nodes = append(out.Nodes, CombinedNode{ExplorationNode: n, Group: gid})
			}
			for _, e := range g.Edges {
				out.Edges = append(out.Edges, ExplorationEdge{
					ID: prefix + e.ID, Source: prefix + e.Source, Target: prefix + e.Target, Kind: e.Kind,
				})
			}
		}
		out.Groups = append(out.Groups, lane.group)
	}
	return out
}

func combinedNodeTotal(lanes []*combinedLane) int {
	total := 0
	for _, l := range lanes {
		if l.graph != nil {
			total += len(l.graph.Nodes)
		}
	}
	return total
}

func lanesBySizeDesc(lanes []*combinedLane) []*combinedLane {
	order := append([]*combinedLane(nil), lanes...)
	sort.SliceStable(order, func(i, j int) bool {
		return combinedLaneSize(order[i]) > combinedLaneSize(order[j])
	})
	return order
}

func combinedLaneSize(l *combinedLane) int {
	if l.graph == nil {
		return 0
	}
	return len(l.graph.Nodes)
}

// combinedFairShares splits budget across lanes by water-filling: lanes below
// the running share keep everything and their slack goes to larger lanes.
func combinedFairShares(lanes []*combinedLane, budget int) []int {
	caps := make([]int, len(lanes))
	idx := make([]int, 0, len(lanes))
	for i, l := range lanes {
		if l.graph != nil && len(l.graph.Nodes) > 0 {
			idx = append(idx, i)
		}
	}
	sort.SliceStable(idx, func(a, b int) bool {
		return combinedLaneSize(lanes[idx[a]]) < combinedLaneSize(lanes[idx[b]])
	})
	remaining := budget
	for k, i := range idx {
		share := remaining / (len(idx) - k)
		if share < 1 {
			share = 1
		}
		n := combinedLaneSize(lanes[i])
		if n < share {
			share = n
		}
		caps[i] = share
		remaining -= share
		if remaining < 0 {
			remaining = 0
		}
	}
	return caps
}

// trimExplorationGraph returns a copy of g with at most limit nodes. Priority:
// the target node, findings, backends, then the ancestors of findings (nearest
// first, by walking edges backwards), then everything else by node type.
// Original node order is preserved, dangling edges are dropped and Stats are
// recounted.
func trimExplorationGraph(g *ExplorationGraph, limit int) *ExplorationGraph {
	out := *g
	if limit < 0 {
		limit = 0
	}
	if len(g.Nodes) <= limit {
		return &out
	}
	out.Truncated = true

	pos := make(map[string]int, len(g.Nodes))
	for i, n := range g.Nodes {
		pos[n.ID] = i
	}
	picked := make([]bool, len(g.Nodes))
	keep := 0
	take := func(i int) {
		if keep < limit && !picked[i] {
			picked[i] = true
			keep++
		}
	}
	for i, n := range g.Nodes {
		if n.Type == "target" {
			take(i)
		}
	}
	for i, n := range g.Nodes {
		if n.Type == "finding" {
			take(i)
		}
	}
	for i, n := range g.Nodes {
		if n.Type == "backend" {
			take(i)
		}
	}

	incoming := map[string][]string{}
	for _, e := range g.Edges {
		incoming[e.Target] = append(incoming[e.Target], e.Source)
	}
	visited := map[string]bool{}
	queue := []string{}
	for _, n := range g.Nodes {
		if n.Type == "finding" {
			visited[n.ID] = true
			queue = append(queue, n.ID)
		}
	}
	for len(queue) > 0 && keep < limit {
		cur := queue[0]
		queue = queue[1:]
		for _, src := range incoming[cur] {
			if visited[src] {
				continue
			}
			visited[src] = true
			if i, ok := pos[src]; ok {
				take(i)
			}
			queue = append(queue, src)
		}
	}

	if keep < limit {
		rest := make([]int, 0, len(g.Nodes))
		for i := range g.Nodes {
			if !picked[i] {
				rest = append(rest, i)
			}
		}
		sort.SliceStable(rest, func(a, b int) bool {
			pa, okA := nodeTypePriorityEG[g.Nodes[rest[a]].Type]
			pb, okB := nodeTypePriorityEG[g.Nodes[rest[b]].Type]
			if !okA {
				pa = len(nodeTypePriorityEG)
			}
			if !okB {
				pb = len(nodeTypePriorityEG)
			}
			return pa < pb
		})
		for _, i := range rest {
			if keep >= limit {
				break
			}
			take(i)
		}
	}

	out.Nodes = make([]ExplorationNode, 0, keep)
	kept := make(map[string]bool, keep)
	for i, n := range g.Nodes {
		if picked[i] {
			out.Nodes = append(out.Nodes, n)
			kept[n.ID] = true
		}
	}
	out.Edges = make([]ExplorationEdge, 0, len(g.Edges))
	for _, e := range g.Edges {
		if kept[e.Source] && kept[e.Target] {
			out.Edges = append(out.Edges, e)
		}
	}
	out.Stats = explorationStatsOf(out.Nodes)
	return &out
}

// explorationStatsOf counts nodes by kind (same rules as the graph builder).
func explorationStatsOf(nodes []ExplorationNode) ExplorationStats {
	var st ExplorationStats
	for _, n := range nodes {
		switch n.Type {
		case "endpoint":
			st.Endpoints++
		case "parameter":
			st.Parameters++
		case "attempt":
			st.Attempts++
			if n.Status == "proven" {
				st.Proven++
			}
		case "finding":
			st.Findings++
			if n.Verified != nil && *n.Verified {
				st.Verified++
			}
		case "agent":
			st.Agents++
		case "backend":
			st.Backend++
		}
	}
	return st
}

// combinedItemSet is a case-insensitive set that remembers a display form.
type combinedItemSet map[string]string

func (c combinedItemSet) add(item string) {
	item = strings.TrimSpace(item)
	if item == "" {
		return
	}
	key := strings.ToLower(item)
	if _, ok := c[key]; !ok {
		c[key] = item
	}
}

// combinedLinks computes shared_backend and shared_vuln_class links between
// every pair of usable lanes, ordered by (source lane, target lane, kind).
func combinedLinks(lanes []*combinedLane) []OverviewLink {
	backends := make([]combinedItemSet, len(lanes))
	classes := make([]combinedItemSet, len(lanes))
	for i, l := range lanes {
		backends[i] = combinedItemSet{}
		classes[i] = combinedItemSet{}
		if l.graph != nil {
			for _, n := range l.graph.Nodes {
				if n.Type != "backend" {
					continue
				}
				name, _ := n.Data["name"].(string)
				if name == "" {
					name = n.Label
				}
				backends[i].add(name)
			}
		}
		if l.rec != nil && l.group.Error == "" {
			for _, v := range l.rec.Vulns {
				if c := vulnClassOf(v); c != "" && c != "other" {
					classes[i].add(c)
				}
			}
		}
	}

	links := []OverviewLink{}
	for i := range lanes {
		if lanes[i].group.Error != "" {
			continue
		}
		for j := i + 1; j < len(lanes); j++ {
			if lanes[j].group.Error != "" {
				continue
			}
			src, dst := lanes[i].group.ID, lanes[j].group.ID
			if l, ok := combinedLink("shared_backend", src, dst, backends[i], backends[j]); ok {
				links = append(links, l)
			}
			if l, ok := combinedLink("shared_vuln_class", src, dst, classes[i], classes[j]); ok {
				links = append(links, l)
			}
		}
	}
	return links
}

func combinedLink(kind, src, dst string, a, b combinedItemSet) (OverviewLink, bool) {
	keys := make([]string, 0)
	for k := range a {
		if _, ok := b[k]; ok {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return OverviewLink{}, false
	}
	sort.Strings(keys)
	items := make([]string, len(keys))
	for i, k := range keys {
		items[i] = a[k]
	}
	evidence := items
	if len(evidence) > explorationCombinedMaxEvidence {
		evidence = evidence[:explorationCombinedMaxEvidence]
	}
	return OverviewLink{
		ID:       fmt.Sprintf("%s:%s:%s", kind, src, dst),
		Kind:     kind,
		Source:   src,
		Target:   dst,
		Label:    combinedLinkLabel(items),
		Weight:   len(items),
		Evidence: append([]string(nil), evidence...),
	}, true
}

// combinedLinkLabel joins up to three items and summarizes the rest ("+N").
func combinedLinkLabel(items []string) string {
	if len(items) <= explorationCombinedLabelItems {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:explorationCombinedLabelItems], ", ") +
		" +" + strconv.Itoa(len(items)-explorationCombinedLabelItems)
}
