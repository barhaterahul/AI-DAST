package web

// Exploration Overview: the portfolio view across every scanned target.
//
// GET /api/exploration/overview?q=&min_severity=&status=&since=&limit=
//
// Scans are grouped by normalized target (explorationTargetKey). Each target
// reports its latest scan's findings, vulnerability classes and exploration
// graph stats; targets are then linked when they share a backend technology,
// a vulnerability class, an auth provider / default credentials, or a host on
// different ports. The response is built from the cached, events-free scan
// summaries plus a per-scan digest cache, so repeated requests only rebuild
// the graphs of scans whose files changed.

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	overviewDefaultLimit   = 200
	overviewMaxLimit       = 500
	overviewMaxScanRefs    = 20
	overviewMatrixMaxCols  = 15
	overviewPairwiseMax    = 8  // item shared by <= this many targets: pairwise links
	overviewLinksPerItem   = 20 // max links contributed by one shared item
	overviewLabelItems     = 3
	overviewEvidenceMax    = 10
	overviewDigestCacheMax = 1000
	overviewGraphWorkers   = 4

	overviewKindBackend = "shared_backend"
	overviewKindVuln    = "shared_vuln_class"
	overviewKindAuth    = "shared_auth"
	overviewKindInfra   = "shared_infra"
)

// overviewKindOrder fixes the output order of link kinds.
var overviewKindOrder = map[string]int{
	overviewKindBackend: 0, overviewKindVuln: 1, overviewKindAuth: 2, overviewKindInfra: 3,
}

// ---- per-scan graph digest cache ----

// overviewGraphDigest is what the overview needs from one scan's exploration
// graph. It is immutable once cached.
type overviewGraphDigest struct {
	Endpoints  int
	Parameters int
	Attempts   int
	Backend    []OverviewTech
}

type overviewDigestEntry struct {
	sig    string
	seq    uint64
	digest overviewGraphDigest
}

// overviewDigestCache memoizes graph digests per scan directory. The entry is
// valid only while the directory's file signature (scan.json plus the graph
// inputs, by modtime and size) is unchanged.
var overviewDigestCache = struct {
	sync.Mutex
	m   map[string]overviewDigestEntry
	seq uint64
}{m: map[string]overviewDigestEntry{}}

// overviewScanSignature stats the files buildExplorationGraph reads. scan.json
// must exist; the other inputs are optional.
func overviewScanSignature(dir string) (string, bool) {
	info, err := os.Stat(filepath.Join(dir, "scan.json"))
	if err != nil {
		return "", false
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d:%d", info.ModTime().UnixNano(), info.Size())
	for _, name := range []string{"ledger.json", "execution-graph.json", "events.jsonl", "deleted_findings.json"} {
		if fi, err := os.Stat(filepath.Join(dir, name)); err == nil {
			fmt.Fprintf(&b, "|%s=%d:%d", name, fi.ModTime().UnixNano(), fi.Size())
		}
	}
	return b.String(), true
}

func overviewDigestLookup(dir, sig string) (overviewGraphDigest, bool) {
	overviewDigestCache.Lock()
	defer overviewDigestCache.Unlock()
	e, ok := overviewDigestCache.m[dir]
	if !ok || e.sig != sig {
		return overviewGraphDigest{}, false
	}
	return e.digest, true
}

func overviewDigestStore(dir, sig string, d overviewGraphDigest) {
	overviewDigestCache.Lock()
	defer overviewDigestCache.Unlock()
	if _, exists := overviewDigestCache.m[dir]; !exists && len(overviewDigestCache.m) >= overviewDigestCacheMax {
		// Evict the oldest-inserted entry. O(n) over a bounded map, and only
		// on insertion of a new directory into a full cache.
		oldestDir, oldestSeq := "", uint64(0)
		for k, v := range overviewDigestCache.m {
			if oldestDir == "" || v.seq < oldestSeq {
				oldestDir, oldestSeq = k, v.seq
			}
		}
		delete(overviewDigestCache.m, oldestDir)
	}
	overviewDigestCache.seq++
	overviewDigestCache.m[dir] = overviewDigestEntry{sig: sig, seq: overviewDigestCache.seq, digest: d}
}

// overviewScanDigest returns the graph digest for one scan, from cache when
// its files are unchanged. A graph that fails to build yields a zero digest
// (the target still appears, with its findings).
func overviewScanDigest(dir string, rec *ScanRecord) overviewGraphDigest {
	sig, ok := overviewScanSignature(dir)
	if ok {
		if d, hit := overviewDigestLookup(dir, sig); hit {
			return d
		}
	}
	d := computeOverviewDigest(dir, rec)
	if ok {
		overviewDigestStore(dir, sig, d)
	}
	return d
}

func computeOverviewDigest(dir string, rec *ScanRecord) (d overviewGraphDigest) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[exploration] overview graph build panicked for %s: %v\n%s", dir, r, debug.Stack())
			d = overviewGraphDigest{Backend: []OverviewTech{}}
		}
	}()
	d.Backend = []OverviewTech{}
	// The summary record is shared with the scan-summary cache: hand the
	// builder its own copy of the findings slice.
	cp := *rec
	cp.Vulns = append([]VulnSummary(nil), rec.Vulns...)
	cp.Events = nil
	g, err := buildExplorationGraph(dir, &cp, explorationScopeFindings)
	if err != nil || g == nil {
		return d
	}
	d.Endpoints = g.Stats.Endpoints
	d.Parameters = g.Stats.Parameters
	d.Attempts = g.Stats.Attempts
	seen := map[string]bool{}
	for _, n := range g.Nodes {
		if n.Type != "backend" {
			continue
		}
		name, _ := n.Data["name"].(string)
		if name = strings.TrimSpace(name); name == "" {
			name = strings.TrimSpace(n.Label)
		}
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		cat, _ := n.Data["category"].(string)
		if cat = strings.TrimSpace(cat); cat == "" {
			cat = "other"
		}
		d.Backend = append(d.Backend, OverviewTech{Name: name, Category: cat})
	}
	return d
}

// ---- request parsing ----

type overviewFilters struct {
	q           string
	minSeverity string
	status      string
	since       time.Time
	hasSince    bool
	limit       int
	echo        OverviewFiltersEcho
}

func parseOverviewFilters(v url.Values) (overviewFilters, error) {
	f := overviewFilters{limit: overviewDefaultLimit}
	f.echo.Q = strings.TrimSpace(v.Get("q"))
	f.q = strings.ToLower(f.echo.Q)

	if ms := strings.ToLower(strings.TrimSpace(v.Get("min_severity"))); ms != "" {
		if _, ok := severityRank[ms]; !ok {
			return f, fmt.Errorf("invalid min_severity (want critical, high, medium, low or info)")
		}
		f.minSeverity = ms
		f.echo.MinSeverity = ms
	}
	f.echo.Status = strings.TrimSpace(v.Get("status"))
	f.status = strings.ToLower(f.echo.Status)

	if since := strings.TrimSpace(v.Get("since")); since != "" {
		t, ok := parseOverviewTime(since)
		if !ok {
			if d, err := time.Parse("2006-01-02", since); err == nil {
				t, ok = d.UTC(), true
			}
		}
		if !ok {
			return f, fmt.Errorf("invalid since (want RFC3339 or YYYY-MM-DD)")
		}
		f.since, f.hasSince = t, true
		f.echo.Since = since
	}
	if ls := strings.TrimSpace(v.Get("limit")); ls != "" {
		n, err := strconv.Atoi(ls)
		if err != nil || n < 1 {
			return f, fmt.Errorf("invalid limit")
		}
		f.limit = min(n, overviewMaxLimit)
	}
	f.echo.Limit = f.limit
	return f, nil
}

func parseOverviewTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// overviewScanNewer reports whether a started after b (newest-first order).
// Parsed times are compared when both parse; otherwise the raw strings.
func overviewScanNewer(a, b *ScanRecord) bool {
	ta, oka := parseOverviewTime(a.StartedAt)
	tb, okb := parseOverviewTime(b.StartedAt)
	if oka && okb && !ta.Equal(tb) {
		return ta.After(tb)
	}
	if (!oka || !okb) && a.StartedAt != b.StartedAt {
		return a.StartedAt > b.StartedAt
	}
	return a.ID > b.ID
}

// ---- aggregation ----

// overviewTargetData is one target being assembled, plus the per-target facts
// link building needs.
type overviewTargetData struct {
	OverviewTarget
	scanCount  int
	latestDir  string
	latestRec  *ScanRecord
	classTop   map[string]string // class -> top severity (latest scan)
	defaultCrd bool
}

// handleExplorationOverview serves GET /api/exploration/overview.
func (s *Server) handleExplorationOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	f, err := parseOverviewFilters(r.URL.Query())
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	out := buildExplorationOverview(s.findAllScanSummaries(), f, time.Now())
	w.Header().Set("Cache-Control", "no-store")
	writeJSONStatus(w, http.StatusOK, out)
}

// buildExplorationOverview assembles the overview from scan summaries. It is
// independent of Server state apart from the per-scan digest cache.
func buildExplorationOverview(entries []scanEntry, f overviewFilters, now time.Time) *ExplorationOverview {
	out := &ExplorationOverview{
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Targets:     []OverviewTarget{},
		Links:       []OverviewLink{},
		Matrix:      OverviewMatrix{Classes: []string{}, Cells: []OverviewMatrixCell{}},
		Filters:     f.echo,
	}

	// Group by normalized target. Wildcard sub-scan records carry their own
	// subdomain target, so each subdomain is grouped as its own target.
	type group struct {
		key  string
		recs []int // indexes into entries
	}
	groups := map[string]*group{}
	for i := range entries {
		rec := &entries[i].rec
		key := explorationTargetKey(rec.Target)
		if key == "" {
			continue
		}
		if f.hasSince {
			t, ok := parseOverviewTime(rec.StartedAt)
			if !ok || t.Before(f.since) {
				continue
			}
		}
		g := groups[key]
		if g == nil {
			g = &group{key: key}
			groups[key] = g
		}
		g.recs = append(g.recs, i)
	}

	matched := make([]*overviewTargetData, 0, len(groups))
	for _, g := range groups {
		sort.SliceStable(g.recs, func(a, b int) bool {
			return overviewScanNewer(&entries[g.recs[a]].rec, &entries[g.recs[b]].rec)
		})
		latest := &entries[g.recs[0]]
		oldest := &entries[g.recs[len(g.recs)-1]].rec
		td := &overviewTargetData{
			scanCount: len(g.recs),
			latestDir: latest.dir,
			latestRec: &latest.rec,
			classTop:  map[string]string{},
		}
		t := &td.OverviewTarget
		t.Key = g.key
		t.Label = strings.TrimSpace(oldest.Target)
		t.LatestScanID = latest.rec.ID
		t.LatestStatus = latest.rec.Status
		t.LastScanned = latest.rec.StartedAt
		if ts, ok := parseOverviewTime(latest.rec.StartedAt); ok {
			t.LastScanned = ts.UTC().Format(time.RFC3339)
		}
		t.Scans = make([]OverviewScanRef, 0, min(len(g.recs), overviewMaxScanRefs))
		for _, idx := range g.recs[:min(len(g.recs), overviewMaxScanRefs)] {
			rec := &entries[idx].rec
			_, top := severityCountsFromVulns(rec.Vulns)
			t.Scans = append(t.Scans, OverviewScanRef{
				ID: rec.ID, InstanceID: rec.InstanceID, Status: rec.Status,
				StartedAt: rec.StartedAt, Findings: len(rec.Vulns), TopSeverity: top,
			})
		}
		t.Severity, t.TopSeverity = severityCountsFromVulns(latest.rec.Vulns)
		t.Findings = len(latest.rec.Vulns)
		t.VulnClasses = map[string]int{}
		for _, v := range latest.rec.Vulns {
			if v.Verified {
				t.Verified++
			}
			c := vulnClassOf(v)
			t.VulnClasses[c]++
			td.classTop[c] = higherSeverity(td.classTop[c], normSeverity(v.Severity))
			if c == "default_credentials" {
				td.defaultCrd = true
			}
		}
		if latest.rec.TokenAuth.enabled() {
			t.TokenProvider = strings.TrimSpace(latest.rec.TokenAuth.Provider)
		}
		t.Backend = []OverviewTech{}

		if !overviewTargetMatches(td, f) {
			continue
		}
		matched = append(matched, td)
	}

	// Most severe first, then most findings, most recent, key.
	sort.Slice(matched, func(i, j int) bool {
		a, b := matched[i], matched[j]
		if ra, rb := severityRank[a.TopSeverity], severityRank[b.TopSeverity]; ra != rb {
			return ra > rb
		}
		if a.Findings != b.Findings {
			return a.Findings > b.Findings
		}
		if a.LastScanned != b.LastScanned {
			return a.LastScanned > b.LastScanned
		}
		return a.Key < b.Key
	})

	for _, td := range matched {
		out.Totals.Targets++
		out.Totals.Scans += td.scanCount
		out.Totals.Findings += td.Findings
		addSeverityCounts(&out.Totals.Severity, td.Severity)
	}

	if len(matched) > f.limit {
		out.Truncated = true
		matched = matched[:f.limit]
	}

	fillOverviewGraphDigests(matched)

	for _, td := range matched {
		out.Targets = append(out.Targets, td.OverviewTarget)
	}
	out.Links = buildOverviewLinks(matched)
	out.Matrix = buildOverviewMatrix(matched)
	return out
}

func overviewTargetMatches(td *overviewTargetData, f overviewFilters) bool {
	if f.q != "" && !strings.Contains(strings.ToLower(td.Key), f.q) && !strings.Contains(strings.ToLower(td.Label), f.q) {
		return false
	}
	if f.minSeverity != "" && severityRank[td.TopSeverity] < severityRank[f.minSeverity] {
		return false
	}
	if f.status != "" && !strings.EqualFold(strings.TrimSpace(td.LatestStatus), f.status) {
		return false
	}
	return true
}

func addSeverityCounts(dst *SeverityCounts, src SeverityCounts) {
	dst.Critical += src.Critical
	dst.High += src.High
	dst.Medium += src.Medium
	dst.Low += src.Low
	dst.Info += src.Info
}

// fillOverviewGraphDigests attaches each target's latest-scan graph stats and
// backend technology, building uncached graphs on a small worker pool.
func fillOverviewGraphDigests(targets []*overviewTargetData) {
	if len(targets) == 0 {
		return
	}
	jobs := make(chan *overviewTargetData)
	var wg sync.WaitGroup
	for range min(overviewGraphWorkers, len(targets)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for td := range jobs {
				d := overviewScanDigest(td.latestDir, td.latestRec)
				td.Endpoints = d.Endpoints
				td.Parameters = d.Parameters
				td.Attempts = d.Attempts
				td.Backend = append([]OverviewTech{}, d.Backend...)
			}
		}()
	}
	for _, td := range targets {
		jobs <- td
	}
	close(jobs)
	wg.Wait()
}

// ---- links ----

type overviewPairKey struct {
	kind, a, b string // a < b
}

// buildOverviewLinks connects targets that share items. targets must already
// be in their final order; the result is deterministic.
func buildOverviewLinks(targets []*overviewTargetData) []OverviewLink {
	// kind -> item -> target indexes (deduplicated, ascending)
	items := map[string]map[string][]int{}
	add := func(kind, item string, ti int) {
		item = strings.TrimSpace(item)
		if item == "" {
			return
		}
		m := items[kind]
		if m == nil {
			m = map[string][]int{}
			items[kind] = m
		}
		if l := m[item]; len(l) > 0 && l[len(l)-1] == ti {
			return
		}
		m[item] = append(m[item], ti)
	}
	for ti, td := range targets {
		for _, tech := range td.Backend {
			add(overviewKindBackend, tech.Name, ti)
		}
		classes := make([]string, 0, len(td.classTop))
		for c := range td.classTop {
			if c != "other" {
				classes = append(classes, c)
			}
		}
		sort.Strings(classes)
		for _, c := range classes {
			add(overviewKindVuln, c, ti)
		}
		if td.TokenProvider != "" {
			add(overviewKindAuth, "token provider "+td.TokenProvider, ti)
		}
		if td.defaultCrd {
			add(overviewKindAuth, "default credentials", ti)
		}
		add(overviewKindInfra, overviewKeyHostname(td.Key), ti)
	}

	pairs := map[overviewPairKey][]string{}
	for kind, m := range items {
		for item, idxs := range m {
			if len(idxs) < 2 {
				continue
			}
			for _, p := range overviewItemPairs(targets, idxs) {
				a, b := targets[p[0]].Key, targets[p[1]].Key
				if a > b {
					a, b = b, a
				}
				k := overviewPairKey{kind: kind, a: a, b: b}
				pairs[k] = append(pairs[k], item)
			}
		}
	}

	links := make([]OverviewLink, 0, len(pairs))
	for k, its := range pairs {
		sort.Strings(its)
		label := strings.Join(its[:min(len(its), overviewLabelItems)], ", ")
		if extra := len(its) - overviewLabelItems; extra > 0 {
			label += fmt.Sprintf(" +%d", extra)
		}
		links = append(links, OverviewLink{
			ID:       k.kind + ":" + k.a + ":" + k.b,
			Kind:     k.kind,
			Source:   k.a,
			Target:   k.b,
			Label:    label,
			Weight:   len(its),
			Evidence: append([]string(nil), its[:min(len(its), overviewEvidenceMax)]...),
		})
	}
	sort.Slice(links, func(i, j int) bool {
		a, b := links[i], links[j]
		if oa, ob := overviewKindOrder[a.Kind], overviewKindOrder[b.Kind]; oa != ob {
			return oa < ob
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.Target < b.Target
	})
	return links
}

// overviewItemPairs returns the target-index pairs one shared item links: all
// pairs for small groups, else a star from the most severe target. At most
// overviewLinksPerItem pairs.
func overviewItemPairs(targets []*overviewTargetData, idxs []int) [][2]int {
	sorted := append([]int(nil), idxs...)
	sort.Slice(sorted, func(i, j int) bool { return targets[sorted[i]].Key < targets[sorted[j]].Key })
	var pairs [][2]int
	if len(sorted) <= overviewPairwiseMax {
		for i := 0; i < len(sorted) && len(pairs) < overviewLinksPerItem; i++ {
			for j := i + 1; j < len(sorted) && len(pairs) < overviewLinksPerItem; j++ {
				pairs = append(pairs, [2]int{sorted[i], sorted[j]})
			}
		}
		return pairs
	}
	hub := sorted[0]
	for _, ti := range sorted[1:] {
		a, h := targets[ti], targets[hub]
		if ra, rh := severityRank[a.TopSeverity], severityRank[h.TopSeverity]; ra != rh {
			if ra > rh {
				hub = ti
			}
			continue
		}
		if a.Findings > h.Findings {
			hub = ti
		}
	}
	for _, ti := range sorted {
		if ti == hub {
			continue
		}
		if len(pairs) >= overviewLinksPerItem {
			break
		}
		pairs = append(pairs, [2]int{hub, ti})
	}
	return pairs
}

// overviewKeyHostname strips the port from a target key ("shop.test:8443" ->
// "shop.test"; bracketed IPv6 keeps its brackets off).
func overviewKeyHostname(key string) string {
	if strings.HasPrefix(key, "[") {
		if end := strings.Index(key, "]"); end > 0 {
			return key[1:end]
		}
	}
	if i := strings.LastIndex(key, ":"); i > 0 && strings.Count(key, ":") == 1 {
		return key[:i]
	}
	return key
}

// ---- matrix ----

func buildOverviewMatrix(targets []*overviewTargetData) OverviewMatrix {
	m := OverviewMatrix{Classes: []string{}, Cells: []OverviewMatrixCell{}}
	freq := map[string]int{}
	for _, td := range targets {
		for c, n := range td.VulnClasses {
			if n > 0 {
				freq[c]++
			}
		}
	}
	hasOther := freq["other"] > 0
	classes := make([]string, 0, len(freq))
	for c := range freq {
		if c != "other" {
			classes = append(classes, c)
		}
	}
	sort.Slice(classes, func(i, j int) bool {
		if freq[classes[i]] != freq[classes[j]] {
			return freq[classes[i]] > freq[classes[j]]
		}
		return classes[i] < classes[j]
	})
	room := overviewMatrixMaxCols
	if hasOther {
		room--
	}
	if len(classes) > room {
		classes = classes[:room]
	}
	if hasOther {
		classes = append(classes, "other")
	}
	m.Classes = classes
	for _, td := range targets {
		for _, c := range classes {
			if n := td.VulnClasses[c]; n > 0 {
				m.Cells = append(m.Cells, OverviewMatrixCell{
					Target: td.Key, Class: c, Count: n, TopSeverity: td.classTop[c],
				})
			}
		}
	}
	return m
}
