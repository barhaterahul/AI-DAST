package web

// Exploration Graph: a read-only, per-scan provenance graph that shows HOW each
// finding was reached — target -> agent lane -> discovering tool call ->
// endpoint -> parameter -> attempt (ledger hypothesis) -> injected evidence ->
// finding -> revealed backend technology.
//
// GET /api/scans/{id}/graph?scope=findings|all
//
// The builder (buildExplorationGraph) is pure: it reads only files inside the
// scan directory (ledger.json, execution-graph.json, events.jsonl,
// deleted_findings.json) plus the supplied ScanRecord, so it is unit-testable
// without Server state. Every input is optional and bounded; a running scan's
// partially written files simply yield a smaller graph.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	explorationMaxNodes        = 1500
	explorationMaxEventsBytes  = 50 << 20 // events.jsonl bytes scanned for discovery
	explorationMaxLedgerBytes  = 64 << 20
	explorationMaxExecGraph    = 16 << 20
	explorationMaxHaystack     = 64 << 10 // per-event text searched for endpoint mentions
	explorationLabelMax        = 80
	explorationReqRespMax      = 2000
	explorationFindingTextMax  = 1500
	explorationSummaryMax      = 1000
	explorationPayloadMax      = 500
	explorationIndicatorMax    = 160
	explorationCommandMax      = 300
	explorationTaskSummaryMax  = 300
	explorationEndpointSamples = 4

	explorationScopeFindings = "findings"
	explorationScopeAll      = "all"
)

// ExplorationGraph is the GET /api/scans/{id}/graph response.
type ExplorationGraph struct {
	ScanID    string            `json:"scan_id"`
	Target    string            `json:"target"`
	Status    string            `json:"status"`
	Scope     string            `json:"scope"`
	Truncated bool              `json:"truncated"`
	Stats     ExplorationStats  `json:"stats"`
	Nodes     []ExplorationNode `json:"nodes"`
	Edges     []ExplorationEdge `json:"edges"`
}

// ExplorationStats counts nodes by kind in the returned graph.
type ExplorationStats struct {
	Endpoints  int `json:"endpoints"`
	Parameters int `json:"parameters"`
	Attempts   int `json:"attempts"`
	Proven     int `json:"proven"`
	Findings   int `json:"findings"`
	Verified   int `json:"verified"`
	Agents     int `json:"agents"`
	Backend    int `json:"backend"`
}

// ExplorationNode is one graph node. Data's shape depends on Type.
type ExplorationNode struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Label      string         `json:"label"`
	Subtitle   string         `json:"subtitle,omitempty"`
	Status     string         `json:"status,omitempty"`
	Severity   string         `json:"severity,omitempty"`
	Verified   *bool          `json:"verified,omitempty"`
	FindingIDs []string       `json:"finding_ids,omitempty"`
	Data       map[string]any `json:"data"`

	order int
}

// ExplorationEdge is a directed edge source -> target.
type ExplorationEdge struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
	Kind   string `json:"kind"`
}

// ---- on-disk shapes (decoded leniently; only the fields we need) ----

type egLedgerFile struct {
	Hypotheses []egHypothesis `json:"hypotheses"`
}

type egHypothesis struct {
	ID         string       `json:"id"`
	DedupKey   string       `json:"dedup_key"`
	Title      string       `json:"title"`
	VulnClass  string       `json:"vuln_class"`
	Target     string       `json:"target"`
	Endpoint   string       `json:"endpoint"`
	Parameter  string       `json:"parameter"`
	Status     string       `json:"status"`
	Confidence float64      `json:"confidence"`
	AssignedTo string       `json:"assigned_to"`
	NextAction string       `json:"next_action"`
	Attempts   int          `json:"attempts"`
	Evidence   []egEvidence `json:"evidence"`
	Origin     string       `json:"origin"`
}

type egEvidence struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Summary   string `json:"summary"`
	Request   string `json:"request"`
	Response  string `json:"response"`
	FindingID string `json:"finding_id"`
	AgentID   string `json:"agent_id"`
	Source    string `json:"source"`
	CreatedAt string `json:"created_at"`
}

type egExecGraph struct {
	Agents []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Task string `json:"task"`
	} `json:"agents"`
}

type egEvent struct {
	EventID   string          `json:"event_id"`
	Type      string          `json:"type"`
	ToolName  string          `json:"tool_name"`
	ToolArgs  json.RawMessage `json:"tool_args"`
	Content   string          `json:"content"`
	Output    string          `json:"output"`
	AgentID   string          `json:"agent_id"`
	Timestamp string          `json:"timestamp"`
}

// ---- builder ----

type explorationBuilder struct {
	scope      string
	targetURL  string
	targetHost string
	basePath   string // target context path, e.g. "/shop"

	nodes   []*ExplorationNode
	nodeIdx map[string]*ExplorationNode
	edges   []ExplorationEdge
	edgeSet map[string]bool

	// endpoint node id -> raw (pre-template) paths, used as discovery needles.
	endpointSamples map[string][]string
	endpointOrder   []string
	// agent ids referenced by included attempts/evidence.
	referencedAgents map[string]bool
	// finding node ids proven by real ledger exploit evidence.
	provenByEvidence map[string]bool
	// attempt/parameter/endpoint -> finding steps awaiting a proof node.
	pendingProofs []egPendingProof
}

// egPendingProof is a step to a finding that had no ledger exploit evidence.
// It is resolved after all hypotheses are read: when another hypothesis
// already proves the finding with real evidence, the step links straight to
// the finding; otherwise an evidence node is built from the finding's own
// written proof.
type egPendingProof struct {
	from, finding, param, loc, path, family, status string
	v                                               *VulnSummary
}

func (b *explorationBuilder) addNode(n *ExplorationNode) *ExplorationNode {
	if existing, ok := b.nodeIdx[n.ID]; ok {
		return existing
	}
	if n.Data == nil {
		n.Data = map[string]any{}
	}
	n.Label = truncateRunesEG(n.Label, explorationLabelMax)
	n.Subtitle = truncateRunesEG(n.Subtitle, explorationLabelMax*2)
	n.order = len(b.nodes)
	b.nodes = append(b.nodes, n)
	b.nodeIdx[n.ID] = n
	return n
}

func (b *explorationBuilder) addEdge(source, target, kind string) {
	if source == "" || target == "" || source == target {
		return
	}
	id := kind + ":" + source + "->" + target
	if b.edgeSet[id] {
		return
	}
	b.edgeSet[id] = true
	b.edges = append(b.edges, ExplorationEdge{ID: id, Source: source, Target: target, Kind: kind})
}

// buildExplorationGraph builds the exploration graph for one scan directory.
// rec may be nil, in which case scan.json is read (events-free) from scanDir.
// Missing or partial files are tolerated.
func buildExplorationGraph(scanDir string, rec *ScanRecord, scope string) (*ExplorationGraph, error) {
	if scope != explorationScopeAll {
		scope = explorationScopeFindings
	}
	if rec == nil && scanDir != "" {
		if r, ok := readScanSummary(filepath.Join(scanDir, "scan.json")); ok {
			rec = r
		}
	}
	if rec == nil {
		rec = &ScanRecord{}
	}

	b := &explorationBuilder{
		scope:            scope,
		targetURL:        rec.Target,
		nodeIdx:          map[string]*ExplorationNode{},
		edgeSet:          map[string]bool{},
		endpointSamples:  map[string][]string{},
		referencedAgents: map[string]bool{},
		provenByEvidence: map[string]bool{},
	}
	if u, err := url.Parse(strings.TrimSpace(rec.Target)); err == nil {
		b.targetHost = strings.ToLower(u.Host)
	}
	b.basePath = basePathEG(rec.Target)

	targetLabel := rec.Target
	if b.targetHost != "" {
		targetLabel = b.targetHost
	}
	if targetLabel == "" {
		targetLabel = "target"
	}
	b.addNode(&ExplorationNode{
		ID: "target", Type: "target", Label: targetLabel, Subtitle: rec.Status,
		Data: map[string]any{"url": rec.Target},
	})

	// ---- findings (tombstones excluded) ----
	tomb := readFindingTombstones(scanDir)
	type findingRef struct {
		v      *VulnSummary
		nodeID string
	}
	findings := []findingRef{}
	byID := map[string]*findingRef{}
	for i := range rec.Vulns {
		v := &rec.Vulns[i]
		id := strings.TrimSpace(v.ID)
		if id == "" || tomb[id] {
			continue
		}
		if _, dup := byID[strings.ToLower(id)]; dup {
			continue
		}
		findings = append(findings, findingRef{v: v, nodeID: "finding:" + id})
		byID[strings.ToLower(id)] = &findings[len(findings)-1]
	}
	// re-point map entries (slice may have reallocated during append)
	for i := range findings {
		byID[strings.ToLower(strings.TrimSpace(findings[i].v.ID))] = &findings[i]
	}
	for _, f := range findings {
		b.addFindingNode(f.nodeID, f.v)
	}

	// ---- ledger hypotheses ----
	ledger := readLedgerEG(scanDir)
	agentClasses := map[string]map[string]bool{}
	linkedFindings := map[string]bool{}

	// Resolve finding links first: explicit finding_ref evidence that is
	// plausible (endpoint or vuln family agrees), then, for findings the
	// ledger never linked, the best matching hypothesis.
	linksByHyp := make([][]*findingRef, len(ledger.Hypotheses))
	for hi := range ledger.Hypotheses {
		h := &ledger.Hypotheses[hi]
		if h.ID == "" || strings.EqualFold(strings.TrimSpace(h.Status), "queued") {
			continue
		}
		seenLinked := map[string]bool{}
		for _, ev := range h.Evidence {
			if strings.ToLower(ev.Kind) != "finding_ref" || ev.FindingID == "" {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(ev.FindingID))
			f, ok := byID[key]
			if !ok || seenLinked[key] || !b.linkPlausibleEG(h, f.v) {
				continue
			}
			seenLinked[key] = true
			linksByHyp[hi] = append(linksByHyp[hi], f)
			linkedFindings[f.nodeID] = true
		}
	}
	for i := range findings {
		f := &findings[i]
		if linkedFindings[f.nodeID] {
			continue
		}
		if hi := b.inferHypothesisEG(ledger.Hypotheses, f.v); hi >= 0 {
			linksByHyp[hi] = append(linksByHyp[hi], f)
			linkedFindings[f.nodeID] = true
		}
	}

	for hi := range ledger.Hypotheses {
		h := &ledger.Hypotheses[hi]
		status := strings.ToLower(strings.TrimSpace(h.Status))
		if status == "queued" || h.ID == "" {
			continue
		}
		for _, aid := range []string{h.AssignedTo, h.Origin} {
			if aid = strings.TrimSpace(aid); aid != "" && h.VulnClass != "" {
				if agentClasses[aid] == nil {
					agentClasses[aid] = map[string]bool{}
				}
				agentClasses[aid][h.VulnClass] = true
			}
		}
		linked := linksByHyp[hi]
		if scope == explorationScopeFindings && len(linked) == 0 {
			continue
		}
		ids := make([]string, 0, len(linked))
		vs := make([]*VulnSummary, 0, len(linked))
		for _, f := range linked {
			ids = append(ids, f.nodeID)
			vs = append(vs, f.v)
		}
		b.addHypothesis(h, status, ids, vs)
	}

	// ---- findings without a ledger link: endpoint (-> parameter) -> finding ----
	for _, f := range findings {
		if linkedFindings[f.nodeID] {
			continue
		}
		method, path, raw := b.normalizeEndpoint(f.v.Endpoint, f.v.Method)
		if path == "" {
			b.addEdge("target", f.nodeID, "proves")
			continue
		}
		epID := b.addEndpoint(path, method, raw)
		parent := epID
		param := paramFromFindingEG(f.v)
		if param == "" {
			param = paramFromProofEG(f.v)
		}
		loc := ""
		if param == "" {
			if param = placeholderParamEG(f.v); param != "" {
				loc = "path"
			}
		}
		if param != "" && loc == "" {
			loc = locationFromURLEG(f.v.Endpoint, param)
			if loc == "unknown" {
				loc = locationFromTextEG(findingProofTextEG(f.v), param, method)
			}
		}
		if param != "" {
			pID := b.addParameter(path, param, loc)
			b.addEdge(epID, pID, "exposes")
			parent = pID
		}
		b.pendingProofs = append(b.pendingProofs, egPendingProof{
			from: parent, finding: f.nodeID, param: param, loc: loc, path: path,
			family: findingFamilyEG(f.v), status: "proven", v: f.v,
		})
	}
	b.resolvePendingProofs()

	// ---- discovery from events.jsonl ----
	discoveries := b.scanDiscoveries(scanDir)

	// ---- agents ----
	exec := readExecGraphEG(scanDir)
	agentNodeByKey := map[string]string{}
	discoveryAgents := map[string]bool{}
	for _, d := range discoveries {
		if d.agentID != "" {
			discoveryAgents[d.agentID] = true
		}
	}
	for _, a := range exec.Agents {
		if a.ID == "" {
			continue
		}
		referenced := b.referencedAgents[a.ID] || b.referencedAgents[a.Name] ||
			discoveryAgents[a.ID] || discoveryAgents[a.Name]
		if scope == explorationScopeFindings && !referenced {
			continue
		}
		classes := map[string]bool{}
		for c := range agentClasses[a.ID] {
			classes[c] = true
		}
		if a.Name != "" {
			for c := range agentClasses[a.Name] {
				classes[c] = true
			}
		}
		lanes := sortedKeysEG(classes)
		summary := firstLineEG(a.Task)
		id := "agent:" + a.ID
		name := a.Name
		if name == "" {
			name = a.ID
		}
		b.addNode(&ExplorationNode{
			ID: id, Type: "agent", Label: name, Subtitle: strings.Join(lanes, ", "),
			Data: map[string]any{
				"name": name, "lane_classes": lanes,
				"task_summary": truncateRunesEG(summary, explorationTaskSummaryMax),
			},
		})
		b.addEdge("target", id, "assigned")
		agentNodeByKey[a.ID] = id
		if a.Name != "" {
			if _, taken := agentNodeByKey[a.Name]; !taken {
				agentNodeByKey[a.Name] = id
			}
		}
	}

	discovered := map[string]bool{}
	for _, d := range discoveries {
		n := b.addNode(&ExplorationNode{
			ID: d.nodeID, Type: "discovery", Label: d.tool, Subtitle: truncateRunesEG(d.command, explorationLabelMax),
			Data: map[string]any{
				"tool": d.tool, "command": d.command, "event_id": d.eventID,
				"timestamp": d.timestamp, "agent_id": d.agentID,
			},
		})
		parent := "target"
		if aid, ok := agentNodeByKey[d.agentID]; ok {
			parent = aid
		}
		b.addEdge(parent, n.ID, "discovered")
		for _, ep := range d.endpoints {
			b.addEdge(n.ID, ep, "discovered")
			discovered[ep] = true
		}
	}
	for _, ep := range b.endpointOrder {
		if !discovered[ep] {
			b.addEdge("target", ep, "discovered")
		}
	}

	b.propagateFindingIDs()
	return b.finish(rec, scope), nil
}

func (b *explorationBuilder) addFindingNode(nodeID string, v *VulnSummary) {
	sev := normalizeSeverityEG(v.Severity)
	verified := v.Verified
	sub := v.ID
	if sev != "" {
		sub += " · " + sev
	}
	n := b.addNode(&ExplorationNode{
		ID: nodeID, Type: "finding", Label: firstNonEmptyEG(v.Title, v.ID), Subtitle: sub,
		Status: "proven", Severity: sev, Verified: &verified,
		Data: map[string]any{
			"id": v.ID, "title": v.Title, "severity": sev, "cvss": v.CVSS,
			"cwe": v.CWE, "owasp": v.OWASP, "verified": v.Verified,
			"verification_method": truncateRunesEG(v.VerificationMethod, explorationFindingTextMax),
			"impact":              truncateRunesEG(v.Impact, explorationFindingTextMax),
			"poc_description":     truncateRunesEG(v.PoCDescription, explorationFindingTextMax),
			"technical_analysis":  truncateRunesEG(v.TechnicalAnalysis, explorationFindingTextMax),
		},
	})
	for _, field := range []struct{ name, text string }{
		{"technical_analysis", v.TechnicalAnalysis},
		{"description", v.Description},
		{"exploitation_proof", v.ExploitationProof},
	} {
		for _, hit := range detectBackends(field.text) {
			b.addBackend(hit, fmt.Sprintf("finding %s %s", v.ID, field.name), n.ID)
		}
	}
}

func (b *explorationBuilder) addBackend(hit backendHit, source, fromNode string) {
	id := "backend:" + slugEG(hit.Name)
	b.addNode(&ExplorationNode{
		ID: id, Type: "backend", Label: hit.Name, Subtitle: hit.Category,
		Data: map[string]any{
			"category": hit.Category, "name": hit.Name,
			"indicator": hit.Indicator, "source": source,
		},
	})
	b.addEdge(fromNode, id, "reveals")
}

func (b *explorationBuilder) addEndpoint(path, method, raw string) string {
	id := "endpoint:" + path
	if n, ok := b.nodeIdx[id]; ok {
		if n.Data["method"] == "" && method != "" {
			n.Data["method"] = method
			n.Label = truncateRunesEG(method+" "+path, explorationLabelMax)
		}
	} else {
		label := path
		if method != "" {
			label = method + " " + path
		}
		fullURL := path
		if b.targetURL != "" && strings.HasPrefix(path, "/") {
			if u, err := url.Parse(b.targetURL); err == nil && u.Host != "" {
				if strings.HasPrefix(path, "//") {
					// Cross-origin endpoint ("//other.host/x"): keep its own host.
					fullURL = u.Scheme + ":" + path
				} else {
					fullURL = u.Scheme + "://" + u.Host + path
				}
			}
		}
		b.addNode(&ExplorationNode{
			ID: id, Type: "endpoint", Label: label,
			Data: map[string]any{"method": method, "path": path, "url": fullURL},
		})
		b.endpointOrder = append(b.endpointOrder, id)
	}
	if raw != "" && len(b.endpointSamples[id]) < explorationEndpointSamples {
		dup := false
		for _, s := range b.endpointSamples[id] {
			if s == raw {
				dup = true
				break
			}
		}
		if !dup {
			b.endpointSamples[id] = append(b.endpointSamples[id], raw)
		}
	}
	return id
}

func (b *explorationBuilder) addParameter(path, name, location string) string {
	id := "parameter:" + path + "#" + name
	if n, ok := b.nodeIdx[id]; ok {
		if n.Data["location"] == "unknown" && location != "unknown" {
			n.Data["location"] = location
			n.Subtitle = location
		}
		return id
	}
	b.addNode(&ExplorationNode{
		ID: id, Type: "parameter", Label: name, Subtitle: location,
		Data: map[string]any{"name": name, "location": location},
	})
	return id
}

func attemptStatusEG(status string) string {
	switch status {
	case "proven", "rejected", "blocked", "exhausted":
		return status
	default:
		return "active"
	}
}

func isExploitEvidenceEG(ev egEvidence) bool {
	k := strings.ToLower(ev.Kind)
	return k == "exploit" || (ev.Source != "" && k != "baseline" && k != "control")
}

func (b *explorationBuilder) addHypothesis(h *egHypothesis, status string, findingNodes []string, linked []*VulnSummary) {
	// Parse evidence requests once (exploit evidence first for method/location).
	type parsedEv struct {
		ev  egEvidence
		req parsedRequestEG
	}
	var evs []parsedEv
	for _, ev := range h.Evidence {
		if strings.ToLower(ev.Kind) == "finding_ref" {
			continue
		}
		evs = append(evs, parsedEv{ev: ev, req: parseRequestEG(ev.Request)})
	}
	ordered := make([]parsedEv, 0, len(evs))
	for _, e := range evs {
		if isExploitEvidenceEG(e.ev) {
			ordered = append(ordered, e)
		}
	}
	for _, e := range evs {
		if !isExploitEvidenceEG(e.ev) {
			ordered = append(ordered, e)
		}
	}

	method := ""
	for _, e := range ordered {
		if e.req.method != "" {
			method = e.req.method
			break
		}
	}
	rawEndpoint := strings.TrimSpace(h.Endpoint)
	if rawEndpoint == "" {
		for _, v := range linked {
			if v.Endpoint != "" {
				rawEndpoint = v.Endpoint
				if method == "" {
					method = strings.ToUpper(strings.TrimSpace(v.Method))
				}
				break
			}
		}
	}
	if rawEndpoint == "" {
		for _, e := range ordered {
			if e.req.rawURL != "" {
				rawEndpoint = e.req.rawURL
				break
			}
		}
	}
	if rawEndpoint == "" {
		rawEndpoint = h.Target
	}
	if method == "" {
		for _, v := range linked {
			if v.Method != "" {
				method = strings.ToUpper(strings.TrimSpace(v.Method))
				break
			}
		}
	}
	m, path, raw := b.normalizeEndpoint(rawEndpoint, method)

	param, locHint := cleanParamHintEG(h.Parameter)
	if param == "" {
		parts := strings.Split(h.DedupKey, "|")
		if len(parts) >= 3 {
			param, locHint = cleanParamHintEG(parts[2])
		}
	}

	parent := "target"
	if path != "" {
		parent = b.addEndpoint(path, m, raw)
	}
	loc := ""
	family := hypothesisFamilyEG(h)
	if param != "" {
		loc = "unknown"
		for _, e := range ordered {
			if l := inferLocationEG(e.req, param); l != "unknown" {
				loc = l
				break
			}
		}
		if loc == "unknown" && locHint != "" {
			loc = locHint
		}
		if loc == "unknown" {
			loc = locationFromURLEG(rawEndpoint, param)
		}
		for _, v := range linked {
			if loc == "unknown" {
				loc = locationFromURLEG(v.Endpoint, param)
			}
		}
		if loc == "unknown" {
			loc = locationFromDedupEG(h.DedupKey)
		}
		for _, v := range linked {
			if loc == "unknown" {
				loc = locationFromTextEG(findingProofTextEG(v), param, firstNonEmptyEG(m, strings.ToUpper(v.Method)))
			}
		}
		pathKey := path
		if pathKey == "" {
			pathKey = "/"
		}
		pID := b.addParameter(pathKey, param, loc)
		b.addEdge(parent, pID, "exposes")
		parent = pID
	}

	attemptID := "attempt:" + h.ID
	st := attemptStatusEG(status)
	title := firstNonEmptyEG(h.Title, h.VulnClass, h.ID)
	label := firstNonEmptyEG(h.VulnClass, title)
	b.addNode(&ExplorationNode{
		ID: attemptID, Type: "attempt", Label: label,
		Subtitle: fmt.Sprintf("%s · %.0f%%", st, h.Confidence*100),
		Status:   st,
		Data: map[string]any{
			"hypothesis_id": h.ID, "vuln_class": h.VulnClass, "status": status,
			"confidence": h.Confidence, "title": truncateRunesEG(title, explorationSummaryMax),
			"next_action": truncateRunesEG(h.NextAction, explorationSummaryMax),
			"attempts":    h.Attempts,
		},
	})
	b.addEdge(parent, attemptID, "tested")
	if a := strings.TrimSpace(h.AssignedTo); a != "" {
		b.referencedAgents[a] = true
	}
	if a := strings.TrimSpace(h.Origin); a != "" {
		b.referencedAgents[a] = true
	}

	provedViaEvidence := false
	for i, e := range evs {
		exploit := isExploitEvidenceEG(e.ev)
		if b.scope == explorationScopeFindings && !exploit {
			continue
		}
		evKey := e.ev.ID
		if evKey == "" {
			evKey = fmt.Sprintf("#%d", i)
		}
		evID := "evidence:" + h.ID + "/" + evKey
		kind := strings.ToLower(firstNonEmptyEG(e.ev.Kind, "artifact"))
		payload := ""
		if param != "" {
			payload, _ = extractParamValueEG(e.req, e.ev.Request, param)
		}
		if payload == "" && param != "" && exploit {
			// The request may be a bare URL (browser verifiers); fall back to
			// the evidence summary, then the linked finding's written proof.
			payload = b.payloadForEG(e.ev.Summary, param, loc, path, family)
			for _, v := range linked {
				if payload == "" {
					payload = b.payloadForEG(findingProofTextEG(v), param, loc, path, family)
				}
			}
		}
		payload = truncateRunesEG(payload, explorationPayloadMax)
		label := kind
		if e.ev.Source != "" {
			label = kind + " · " + e.ev.Source
		}
		sub := payload
		if sub == "" {
			sub = firstLineEG(e.ev.Summary)
		}
		node := &ExplorationNode{
			ID: evID, Type: "evidence", Label: label, Subtitle: truncateRunesEG(sub, explorationLabelMax),
			Status: st,
			Data: map[string]any{
				"evidence_id": e.ev.ID, "kind": kind, "source": e.ev.Source, "agent_id": e.ev.AgentID,
				"summary":    truncateRunesEG(e.ev.Summary, explorationSummaryMax),
				"payload":    payload,
				"request":    truncateRunesEG(e.ev.Request, explorationReqRespMax),
				"response":   truncateRunesEG(e.ev.Response, explorationReqRespMax),
				"created_at": e.ev.CreatedAt,
			},
		}
		if strings.HasPrefix(e.ev.Source, "verify_") {
			t := true
			node.Verified = &t
		}
		b.addNode(node)
		b.addEdge(attemptID, evID, "injected")
		if a := strings.TrimSpace(e.ev.AgentID); a != "" {
			b.referencedAgents[a] = true
		}
		if exploit {
			for _, f := range findingNodes {
				b.addEdge(evID, f, "proves")
				b.provenByEvidence[f] = true
				provedViaEvidence = true
			}
		}
		for _, hit := range detectBackends(e.ev.Response) {
			b.addBackend(hit, "evidence "+firstNonEmptyEG(e.ev.ID, evKey)+" response", evID)
		}
	}
	if !provedViaEvidence {
		// No exploit evidence in the ledger: show the injection the finding
		// itself documents (its PoC / exploitation proof) as the evidence step.
		for i, f := range findingNodes {
			var v *VulnSummary
			if i < len(linked) {
				v = linked[i]
			}
			b.pendingProofs = append(b.pendingProofs, egPendingProof{
				from: attemptID, finding: f, param: param, loc: loc, path: path,
				family: family, status: st, v: v,
			})
		}
	}
}

// payloadForEG extracts the injected value for param from proof text: a
// concrete path segment for path parameters, else a request/prose mention.
// Injection families require an injected-looking value.
func (b *explorationBuilder) payloadForEG(text, param, loc, path, family string) string {
	if loc == "path" {
		if v := b.pathValueFromTextEG(text, path); v != "" {
			return truncateRunesEG(v, explorationPayloadMax)
		}
	}
	return payloadFromTextEG(text, param, injectionFamilyEG(family))
}

func (b *explorationBuilder) resolvePendingProofs() {
	for _, p := range b.pendingProofs {
		if b.provenByEvidence[p.finding] {
			b.addEdge(p.from, p.finding, "proves")
			continue
		}
		if evID := b.addFindingProofEvidence(p); evID != "" {
			b.addEdge(p.from, evID, "injected")
		} else {
			b.addEdge(p.from, p.finding, "proves")
		}
	}
	b.pendingProofs = nil
}

// addFindingProofEvidence adds an evidence node built from a finding's own
// PoC / exploitation proof (source "report") with an edge to the finding, and
// returns its id, or "" when the finding documents no proof.
func (b *explorationBuilder) addFindingProofEvidence(p egPendingProof) string {
	v, findingNode, param, status := p.v, p.finding, p.param, p.status
	if v == nil || strings.TrimSpace(v.ExploitationProof+v.PoCDescription) == "" {
		return ""
	}
	id := "evidence:" + strings.TrimSpace(v.ID) + "/proof"
	payload := ""
	if param != "" {
		payload = b.payloadForEG(findingProofTextEG(v), param, p.loc, p.path, p.family)
	} else {
		// No single parameter (credential login, CSRF form): show the body
		// the proof sent, when it has one.
		payload = truncateRunesEG(bodyFromTextEG(findingProofTextEG(v)), explorationPayloadMax)
	}
	sub := payload
	if sub == "" {
		sub = firstLineEG(firstNonEmptyEG(v.PoCDescription, v.ExploitationProof))
	}
	if status == "" {
		status = "proven"
	}
	b.addNode(&ExplorationNode{
		ID: id, Type: "evidence", Label: "exploit · report", Subtitle: truncateRunesEG(sub, explorationLabelMax),
		Status: status,
		Data: map[string]any{
			"evidence_id": "", "kind": "exploit", "source": "report", "agent_id": "",
			"summary":    truncateRunesEG(firstNonEmptyEG(v.PoCDescription, v.ExploitationProof), explorationSummaryMax),
			"payload":    payload,
			"request":    truncateRunesEG(v.ExploitationProof, explorationReqRespMax),
			"response":   "",
			"created_at": "",
		},
	})
	b.addEdge(id, findingNode, "proves")
	return id
}

// ---- endpoint normalization ----

var (
	egUUIDRe     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	egHexIDRe    = regexp.MustCompile(`^[0-9a-fA-F]{24,}$`)
	egDigitsRe   = regexp.MustCompile(`^[0-9]+$`)
	egMethodWord = regexp.MustCompile(`^((?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)(?:\s*[/|,]\s*(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT))*)\s+`)
	// method field values like "GET/POST" or "GET, POST"
	egMethodListRe  = regexp.MustCompile(`^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)(?:\s*[/|,]\s*[A-Z]+)+$`)
	egMethodNameRe  = regexp.MustCompile(`GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT`)
	egPlaceholderRe = regexp.MustCompile(`^(?:\{[^{}/]+\}|:[A-Za-z_][A-Za-z0-9_]*|<[A-Za-z_][A-Za-z0-9_]*>)$`)
	egHostRe        = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:\d{1,5})?$`)
)

// normalizeEndpoint returns (method, templated path, raw path). The path has
// scheme/host stripped when same-origin with the target (cross-origin keeps
// "//host" as a prefix), no query/fragment, and numeric/uuid/placeholder
// segments templated to {id}. When the target lives under a context path
// (e.g. http://host/shop) and the endpoint was written relative to it
// ("/bank/account-summary"), the context path is prepended so both spellings share
// one node. raw is the untemplated path as written, for event matching.
func (b *explorationBuilder) normalizeEndpoint(endpoint, method string) (string, string, string) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if m := egMethodListRe.FindString(method); m != "" {
		method = egMethodNameRe.FindString(m)
	}
	e := strings.TrimSpace(endpoint)
	// "POST POST /x", "GET/POST /x", "GET, POST /x": take the first method.
	for {
		m := egMethodWord.FindStringSubmatch(strings.ToUpper(e))
		if m == nil {
			break
		}
		if method == "" {
			method = egMethodNameRe.FindString(m[1])
		}
		e = strings.TrimSpace(e[len(m[0]):])
	}
	if e == "" {
		return method, "", ""
	}
	if i := strings.IndexAny(e, " \t\n"); i >= 0 {
		e = e[:i]
	}
	prefix := ""
	lower := strings.ToLower(e)
	if !strings.HasPrefix(e, "/") && !strings.Contains(lower, "://") {
		// "localhost:8080/app/x" or "example.com" written without a scheme.
		first := e
		if i := strings.IndexByte(first, '/'); i >= 0 {
			first = first[:i]
		}
		if looksLikeHostEG(first, b.targetHost) {
			e = "//" + e
			lower = strings.ToLower(e)
		}
	}
	sameOrigin := true
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || strings.HasPrefix(e, "//") {
		if u, err := url.Parse(e); err == nil {
			host := strings.ToLower(u.Host)
			if host != "" && b.targetHost != "" && !sameOriginHostEG(host, b.targetHost) {
				prefix = "//" + host
				sameOrigin = false
			}
			e = u.EscapedPath()
			if p, err := url.PathUnescape(e); err == nil {
				e = p
			}
		} else {
			return method, "", ""
		}
	}
	if i := strings.IndexAny(e, "?#"); i >= 0 {
		e = e[:i]
	}
	if e == "" {
		e = "/"
	}
	if !strings.HasPrefix(e, "/") {
		e = "/" + e
	}
	raw := e
	if sameOrigin {
		e = b.withBasePathEG(e)
	}
	segs := strings.Split(e, "/")
	for i, s := range segs {
		if s == "" {
			continue
		}
		if egDigitsRe.MatchString(s) || egUUIDRe.MatchString(s) || egHexIDRe.MatchString(s) || egPlaceholderRe.MatchString(s) {
			segs[i] = "{id}"
		}
	}
	path := prefix + strings.Join(segs, "/")
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = strings.TrimRight(path, "/")
	}
	return method, path, raw
}

// withBasePathEG prepends the target's context path to a same-origin path
// that was written relative to it. Well-known root files are left alone.
func (b *explorationBuilder) withBasePathEG(p string) string {
	base := b.basePath
	if base == "" || base == "/" || p == base || strings.HasPrefix(p, base+"/") {
		return p
	}
	low := strings.ToLower(p)
	for _, root := range []string{"/.well-known/", "/robots.txt", "/sitemap.xml", "/favicon.ico", "/crossdomain.xml", "/security.txt"} {
		if strings.HasPrefix(low, root) {
			return p
		}
	}
	if p == "/" {
		return base
	}
	return base + p
}

// basePathEG returns the directory-like context path of a target URL:
// "http://h/app/" and "http://h/app" -> "/app"; "http://h/app/login.php" ->
// "/app"; "http://h/" -> "".
func basePathEG(target string) string {
	u, err := url.Parse(strings.TrimSpace(target))
	if err != nil || u.Host == "" {
		return ""
	}
	p := strings.TrimRight(u.Path, "/")
	if i := strings.LastIndexByte(p, '/'); i >= 0 && strings.Contains(p[i+1:], ".") {
		p = p[:i]
	}
	if p == "" || p == "/" {
		return ""
	}
	return p
}

var egHostTLDs = map[string]bool{"com": true, "net": true, "org": true, "io": true, "dev": true, "app": true,
	"co": true, "edu": true, "gov": true, "info": true, "biz": true, "local": true, "internal": true, "test": true}

// looksLikeHostEG reports whether a scheme-less first path segment is really a
// host ("localhost:8080", "example.com", the target host) rather than a file.
func looksLikeHostEG(seg, targetHost string) bool {
	seg = strings.ToLower(seg)
	if seg == "" || !egHostRe.MatchString(seg) {
		return false
	}
	if targetHost != "" && (sameOriginHostEG(seg, targetHost) || strings.Split(seg, ":")[0] == strings.Split(targetHost, ":")[0]) {
		return true
	}
	if strings.Contains(seg, ":") {
		return true
	}
	if i := strings.LastIndexByte(seg, '.'); i > 0 {
		return egHostTLDs[seg[i+1:]]
	}
	return false
}

func sameOriginHostEG(a, b string) bool {
	strip := func(h string) string {
		h = strings.TrimSuffix(strings.TrimSuffix(h, ":80"), ":443")
		return strings.TrimPrefix(h, "www.")
	}
	return strip(a) == strip(b)
}

// ---- request parsing / payload extraction ----

type parsedRequestEG struct {
	method  string
	rawURL  string
	query   url.Values
	headers map[string]string // lower-cased names
	body    string
}

var (
	egURLRe        = regexp.MustCompile(`https?://[^\s"'<>]+`)
	egReqLineRe    = regexp.MustCompile(`^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+(\S+)`)
	egAnyMethodRe  = regexp.MustCompile(`\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b`)
	egHeaderLineRe = regexp.MustCompile(`^([A-Za-z0-9-]+):\s*(.*)$`)
)

func parseRequestEG(req string) parsedRequestEG {
	p := parsedRequestEG{headers: map[string]string{}}
	s := strings.TrimSpace(strings.ReplaceAll(req, "\r\n", "\n"))
	if s == "" {
		return p
	}
	if strings.HasPrefix(strings.ToLower(s), "curl ") || strings.HasPrefix(strings.ToLower(s), "curl\t") {
		parseCurlEG(s, &p)
	} else if m := egReqLineRe.FindStringSubmatch(s); m != nil {
		p.method = m[1]
		p.rawURL = m[2]
		lines := strings.Split(s, "\n")
		i := 1
		for ; i < len(lines); i++ {
			line := strings.TrimSpace(lines[i])
			if line == "" {
				i++
				break
			}
			if hm := egHeaderLineRe.FindStringSubmatch(line); hm != nil {
				p.headers[strings.ToLower(hm[1])] = hm[2]
			} else {
				// Not a header block: treat the remainder as the body.
				break
			}
		}
		if i < len(lines) {
			p.body = strings.TrimSpace(strings.Join(lines[i:], "\n"))
		}
	} else {
		if u := egURLRe.FindString(s); u != "" {
			p.rawURL = strings.TrimRight(u, ".,;)")
		}
		if m := egAnyMethodRe.FindStringSubmatch(s); m != nil {
			p.method = m[1]
		}
	}
	if p.rawURL != "" {
		if i := strings.Index(p.rawURL, "?"); i >= 0 {
			q := p.rawURL[i+1:]
			if j := strings.Index(q, "#"); j >= 0 {
				q = q[:j]
			}
			p.query, _ = url.ParseQuery(q)
		}
	}
	return p
}

func splitShellWordsEG(s string) []string {
	var out []string
	var cur strings.Builder
	inWord := false
	var quote rune
	escape := false
	for _, r := range s {
		switch {
		case escape:
			cur.WriteRune(r)
			escape = false
		case quote != 0:
			if r == quote {
				quote = 0
			} else if r == '\\' && quote == '"' {
				escape = true
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			inWord = true
		case r == '\\':
			escape = true
			inWord = true
		case r == ' ' || r == '\t' || r == '\n':
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out
}

func parseCurlEG(s string, p *parsedRequestEG) {
	words := splitShellWordsEG(s)
	var data []string
	for i := 1; i < len(words); i++ {
		w := words[i]
		next := func() string {
			if i+1 < len(words) {
				i++
				return words[i]
			}
			return ""
		}
		switch {
		case w == "-X" || w == "--request":
			p.method = strings.ToUpper(next())
		case w == "-d" || w == "--data" || w == "--data-raw" || w == "--data-binary" || w == "--data-urlencode":
			data = append(data, next())
		case w == "-H" || w == "--header":
			if hm := egHeaderLineRe.FindStringSubmatch(strings.TrimSpace(next())); hm != nil {
				p.headers[strings.ToLower(hm[1])] = hm[2]
			}
		case w == "-b" || w == "--cookie":
			p.headers["cookie"] = next()
		case w == "--url":
			p.rawURL = next()
		case strings.HasPrefix(w, "http://") || strings.HasPrefix(w, "https://"):
			if p.rawURL == "" {
				p.rawURL = w
			}
		}
	}
	p.body = strings.Join(data, "&")
	if p.method == "" {
		if p.body != "" {
			p.method = "POST"
		} else {
			p.method = "GET"
		}
	}
}

func isJSONBodyEG(body string) bool {
	b := strings.TrimSpace(body)
	return strings.HasPrefix(b, "{") || strings.HasPrefix(b, "[")
}

func findJSONKeyEG(v any, key string, depth int) (string, bool) {
	if depth > 8 {
		return "", false
	}
	switch t := v.(type) {
	case map[string]any:
		if val, ok := t[key]; ok {
			switch s := val.(type) {
			case string:
				return s, true
			default:
				raw, _ := json.Marshal(s)
				return string(raw), true
			}
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if s, ok := findJSONKeyEG(t[k], key, depth+1); ok {
				return s, true
			}
		}
	case []any:
		for _, e := range t {
			if s, ok := findJSONKeyEG(e, key, depth+1); ok {
				return s, true
			}
		}
	}
	return "", false
}

func cookieValueEG(cookie, name string) (string, bool) {
	for _, part := range strings.Split(cookie, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && k == name {
			return v, true
		}
	}
	return "", false
}

// extractParamValueEG returns the URL-decoded value of param in the request
// and where it was found.
func extractParamValueEG(p parsedRequestEG, rawReq, param string) (string, string) {
	if param == "" {
		return "", "unknown"
	}
	if vals, ok := p.query[param]; ok && len(vals) > 0 {
		return vals[0], "query"
	}
	if p.body != "" {
		if isJSONBodyEG(p.body) {
			var v any
			if json.Unmarshal([]byte(p.body), &v) == nil {
				if s, ok := findJSONKeyEG(v, param, 0); ok {
					return s, "body"
				}
			}
		} else if strings.Contains(p.body, "=") {
			if q, _ := url.ParseQuery(p.body); q != nil {
				if vals, ok := q[param]; ok && len(vals) > 0 {
					return vals[0], "body"
				}
			}
		}
	}
	if c, ok := p.headers["cookie"]; ok {
		if v, ok := cookieValueEG(c, param); ok {
			return decodeEG(v), "cookie"
		}
	}
	if v, ok := p.headers[strings.ToLower(param)]; ok {
		return v, "header"
	}
	re, err := regexp.Compile(`(?:^|[?&\s"'])` + regexp.QuoteMeta(param) + `=([^&\s"'#]*)`)
	if err == nil {
		if m := re.FindStringSubmatch(rawReq); m != nil {
			return decodeEG(m[1]), "unknown"
		}
	}
	return "", "unknown"
}

func decodeEG(v string) string {
	if d, err := url.QueryUnescape(v); err == nil {
		return d
	}
	if d, err := url.PathUnescape(v); err == nil {
		return d
	}
	return v
}

func inferLocationEG(p parsedRequestEG, param string) string {
	if param == "" {
		return "unknown"
	}
	if _, ok := p.query[param]; ok {
		return "query"
	}
	_, loc := extractParamValueEG(p, "", param)
	if loc != "unknown" {
		return loc
	}
	if p.rawURL != "" && strings.Contains(p.rawURL, "{"+param+"}") {
		return "path"
	}
	return "unknown"
}

func locationFromURLEG(raw, param string) string {
	if param == "" {
		return "unknown"
	}
	if i := strings.Index(raw, "?"); i >= 0 {
		if q, _ := url.ParseQuery(raw[i+1:]); q != nil {
			if _, ok := q[param]; ok {
				return "query"
			}
		}
	}
	if strings.Contains(raw, "{"+param+"}") || strings.Contains(raw, ":"+param) {
		return "path"
	}
	return "unknown"
}

func locationFromDedupEG(key string) string {
	parts := strings.Split(key, "|")
	for i := 3; i < len(parts); i++ {
		switch strings.ToLower(strings.TrimSpace(parts[i])) {
		case "query":
			return "query"
		case "body", "form", "json":
			return "body"
		case "path":
			return "path"
		case "header":
			return "header"
		case "cookie":
			return "cookie"
		}
	}
	return "unknown"
}

var (
	egParamQuotedRe = regexp.MustCompile(`(?i)['"\x60]([A-Za-z_][A-Za-z0-9_.\-\[\]]{0,63})['"\x60]\s+(?:parameter|param|field|argument)`)
	egParamAfterRe  = regexp.MustCompile(`(?i)\b(?:parameter|param|field)\s+['"\x60]?([A-Za-z_][A-Za-z0-9_.\-\[\]]{0,63})['"\x60]?`)
	egParamBeforeRe = regexp.MustCompile(`(?i)\b(?:via|in|through)\s+(?:the\s+)?['"\x60]?([A-Za-z_][A-Za-z0-9_.\-]{0,63})['"\x60]?\s+(?:parameter|param|field)\b`)
)

// paramFromFindingEG derives a parameter name for a ledger-less finding from
// its title or its endpoint's query string.
func paramFromFindingEG(v *VulnSummary) string {
	for _, re := range []*regexp.Regexp{egParamQuotedRe, egParamBeforeRe, egParamAfterRe} {
		if m := re.FindStringSubmatch(v.Title); m != nil {
			name := cleanParamEG(m[1])
			switch strings.ToLower(name) {
			case "the", "a", "an", "is", "of", "to", "in", "on", "and", "or", "via", "parameter", "param", "field":
				continue
			}
			if name != "" {
				return name
			}
		}
	}
	if i := strings.Index(v.Endpoint, "?"); i >= 0 {
		if q, _ := url.ParseQuery(v.Endpoint[i+1:]); len(q) > 0 {
			keys := make([]string, 0, len(q))
			for k := range q {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			return cleanParamEG(keys[0])
		}
	}
	return ""
}

func cleanParamEG(p string) string {
	name, _ := cleanParamHintEG(p)
	return name
}

var (
	egParenRe     = regexp.MustCompile(`\s*[(\[][^)\]]*[)\]]`)
	egNoParamName = map[string]bool{"none": true, "n/a": true, "na": true, "-": true, "null": true, "nil": true,
		"no": true, "unknown": true, "any": true, "all": true, "multiple": true, "various": true}
)

// cleanParamHintEG turns an agent-written parameter description into a short
// parameter name plus an optional location hint. "accountId (path)" ->
// ("accountId","path"); "XML body (DOCTYPE SYSTEM)" -> ("XML body","body");
// "none (route-level check)" and prose such as "tech stack markers" -> "".
func cleanParamHintEG(p string) (string, string) {
	p = strings.TrimSpace(strings.Trim(strings.TrimSpace(p), "'\"`"))
	if p == "" {
		return "", ""
	}
	hint := ""
	for _, m := range egParenRe.FindAllString(p, -1) {
		if l := locationWordEG(m); l != "" {
			hint = l
			break
		}
	}
	name := strings.TrimSpace(egParenRe.ReplaceAllString(p, ""))
	name = strings.TrimSpace(strings.Trim(name, "'\"`:,;"))
	if egNoParamName[strings.ToLower(name)] {
		return "", ""
	}
	if strings.ContainsAny(name, " \t") {
		// Multi-word descriptions are only kept when they name a request body.
		l := locationWordEG(name)
		if l != "body" {
			return "", ""
		}
		hint = "body"
	}
	return truncateRunesEG(name, explorationLabelMax), hint
}

// locationWordEG maps a free-text location mention to a location value.
func locationWordEG(s string) string {
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "cookie"):
		return "cookie"
	case strings.Contains(l, "header"):
		return "header"
	case strings.Contains(l, "body"), strings.Contains(l, "json"), strings.Contains(l, "form"), strings.Contains(l, "xml"):
		return "body"
	case strings.Contains(l, "query"), strings.Contains(l, "querystring"):
		return "query"
	case strings.Contains(l, "path"), strings.Contains(l, "route"), strings.Contains(l, "url segment"):
		return "path"
	}
	return ""
}

// ---- backend detection ----

type backendHit struct {
	Category  string
	Name      string
	Indicator string
}

type backendRule struct {
	category string
	name     string
	re       *regexp.Regexp
}

// backendRules is ordered: more specific rules first. Matching is
// deterministic (table order). Patterns are case-sensitive unless they opt in
// with (?i), to avoid matching ordinary English words.
var backendRules = []backendRule{
	// databases
	{"database", "Apache Derby", regexp.MustCompile(`(?i)SQLState\s*[:=]?\s*\(?\s*42X\d\d|org\.apache\.derby|\bApache Derby\b|\bDerby\b`)},
	{"database", "MySQL", regexp.MustCompile(`(?i)\bMySQL\b|\bMariaDB\b|You have an error in your SQL syntax|com\.mysql\.jdbc`)},
	{"database", "PostgreSQL", regexp.MustCompile(`(?i)\bPostgre(?:SQL|s)\b|PSQLException|org\.postgresql|\bpg_query\b|syntax error at or near`)},
	{"database", "Oracle", regexp.MustCompile(`\bORA-\d{5}\b|(?i:oracle\.jdbc|Oracle (?:Database|JDBC|DB))`)},
	{"database", "Microsoft SQL Server", regexp.MustCompile(`(?i)Microsoft SQL Server|\bMSSQL\b|SQLServerException|Unclosed quotation mark after the character string`)},
	{"database", "SQLite", regexp.MustCompile(`(?i)\bSQLite3?\b|SQLITE_ERROR`)},
	{"database", "MongoDB", regexp.MustCompile(`(?i)\bMongoDB\b|MongoError|MongoServerError`)},
	{"database", "HSQLDB", regexp.MustCompile(`(?i)\bHSQLDB\b|org\.hsqldb`)},
	{"database", "H2", regexp.MustCompile(`org\.h2\.jdbc|\bH2 Database\b`)},
	// servers
	{"server", "Apache Tomcat", regexp.MustCompile(`(?i)Apache[- ]Tomcat|\bTomcat\b|Apache-Coyote`)},
	{"server", "Jetty", regexp.MustCompile(`(?i)\bJetty\b`)},
	{"server", "nginx", regexp.MustCompile(`(?i)\bnginx\b`)},
	{"server", "Apache httpd", regexp.MustCompile(`\bApache/\d[\d.]*|(?i:Apache httpd)|(?m)^Server:\s*Apache(?:\s|$|/)`)},
	{"server", "Microsoft IIS", regexp.MustCompile(`Microsoft-IIS(?:/[\d.]+)?|\bIIS\b`)},
	{"server", "Express", regexp.MustCompile(`(?i)X-Powered-By:\s*Express|\bExpress\.js\b|\bExpressJS\b`)},
	// frameworks
	{"framework", "Spring", regexp.MustCompile(`(?i)\bSpring (?:Boot|Framework|MVC|Security)\b|org\.springframework|Whitelabel Error Page`)},
	{"framework", "Apache Struts", regexp.MustCompile(`(?i)org\.apache\.struts|\bStruts2?\b`)},
	{"framework", "Django", regexp.MustCompile(`(?i)\bDjango\b|csrfmiddlewaretoken`)},
	{"framework", "Flask", regexp.MustCompile(`(?i)\bFlask\b|\bWerkzeug\b`)},
	{"framework", "Laravel", regexp.MustCompile(`(?i)\bLaravel\b|laravel_session`)},
	{"framework", "Ruby on Rails", regexp.MustCompile(`(?i)Ruby on Rails|ActionController|ActiveRecord::`)},
	{"framework", "ASP.NET", regexp.MustCompile(`(?i)ASP\.NET|X-AspNet-Version|__VIEWSTATE`)},
	// languages / runtimes
	{"language", "Java (JSP/Servlet)", regexp.MustCompile(`\bJSP\b|\.jsp\b|JSESSIONID|(?:javax|jakarta)\.servlet|\bServlets?\b|java\.lang\.[A-Za-z]+(?:Exception|Error)`)},
	{"language", "PHP", regexp.MustCompile(`\bPHP\b|PHP/\d|PHPSESSID|(?i:X-Powered-By:\s*PHP)|\.php\b`)},
	{"language", "Python", regexp.MustCompile(`Traceback \(most recent call last\)|\bPython/\d`)},
	{"language", "Node.js", regexp.MustCompile(`(?i)\bNode\.js\b`)},
	// parsers
	{"parser", "Java XML parser", regexp.MustCompile(`javax\.xml|org\.xml\.sax|SAXParseException|DocumentBuilderFactory|(?i:xerces)`)},
	{"parser", "XML parser (XXE)", regexp.MustCompile(`\bXXE\b|(?i:XML External Entit)|<!DOCTYPE[^>]*\[\s*<!ENTITY`)},
	// operating systems
	{"os", "Linux/Unix", regexp.MustCompile(`root:x:0:0:|uid=\d+\([^)]*\)\s+gid=|\bLinux\b|\bUbuntu\b|\bDebian\b`)},
	{"os", "Windows", regexp.MustCompile(`\[boot loader\]|\[fonts\]|(?i:C:\\Windows)|\bWindows Server\b`)},
	// WAF / edge
	{"waf", "Cloudflare", regexp.MustCompile(`(?i)\bCloudflare\b|\bcf-ray\b|__cf_bm`)},
	{"waf", "ModSecurity", regexp.MustCompile(`(?i)Mod_?Security`)},
	{"waf", "AWS WAF", regexp.MustCompile(`(?i)\bAWS WAF\b|x-amzn-waf`)},
	{"waf", "Akamai", regexp.MustCompile(`(?i)\bAkamai(?:GHost)?\b`)},
	{"waf", "Imperva", regexp.MustCompile(`(?i)\bImperva\b|\bIncapsula\b`)},
	{"waf", "Sucuri", regexp.MustCompile(`(?i)\bSucuri\b`)},
}

// detectBackends returns one hit per matching rule (in rule order) with the
// short matched text (plus a little context) as indicator.
func detectBackends(text string) []backendHit {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	if len(text) > 256<<10 {
		text = text[:256<<10]
	}
	var hits []backendHit
	for _, r := range backendRules {
		loc := r.re.FindStringIndex(text)
		if loc == nil {
			continue
		}
		start := max(0, loc[0]-30)
		end := min(len(text), loc[1]+50)
		for start > 0 && !utf8.RuneStart(text[start]) {
			start--
		}
		for end < len(text) && !utf8.RuneStart(text[end]) {
			end++
		}
		ind := strings.Join(strings.Fields(text[start:end]), " ")
		hits = append(hits, backendHit{
			Category: r.category, Name: r.name,
			Indicator: truncateRunesEG(ind, explorationIndicatorMax),
		})
	}
	return hits
}

// ---- discovery (events.jsonl) ----

type discoveryEG struct {
	nodeID, tool, command, eventID, timestamp, agentID string
	endpoints                                          []string
}

// Tools whose args merely restate an endpoint already known (reporting,
// ledger bookkeeping, planning, delegation) are not discovery.
var egNonDiscoveryTool = []string{"hypothes", "report", "finding", "ledger", "note", "plan", "think", "agent", "delegat", "finish", "todo", "memory", "evidence", "coverage", "checkpoint"}

func isDiscoveryToolEG(name string) bool {
	n := strings.ToLower(name)
	if n == "" {
		return false
	}
	for _, s := range egNonDiscoveryTool {
		if strings.Contains(n, s) {
			return false
		}
	}
	return true
}

// isBookkeepingCommandEG reports a shell/code call that only reads or edits
// the scan's own state files (ledger, findings, notes); such a call mentions
// endpoints because the agent already knew them, so it is not discovery.
func isBookkeepingCommandEG(args map[string]string) bool {
	cmd := strings.ToLower(args["command"] + "\n" + args["cmd"] + "\n" + args["code"])
	for _, f := range []string{"ledger.json", "findings.json", "notes.json", "scan.json", "coverage.json", "execution-graph.json", "events.jsonl", "scan.meta.json"} {
		if strings.Contains(cmd, f) {
			return true
		}
	}
	return false
}

func toolArgsEG(raw json.RawMessage) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return out
	}
	for k, v := range m {
		switch t := v.(type) {
		case string:
			out[k] = t
		default:
			b, _ := json.Marshal(t)
			out[k] = string(b)
		}
	}
	return out
}

func commandFromArgsEG(args map[string]string) string {
	for _, k := range []string{"command", "cmd", "url", "code", "request", "query", "action", "path", "target"} {
		if v := strings.TrimSpace(args[k]); v != "" {
			return truncateRunesEG(v, explorationCommandMax)
		}
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+args[k])
	}
	return truncateRunesEG(strings.Join(parts, " "), explorationCommandMax)
}

func (b *explorationBuilder) scanDiscoveries(scanDir string) []*discoveryEG {
	if scanDir == "" || len(b.endpointOrder) == 0 {
		return nil
	}
	f, err := os.Open(filepath.Join(scanDir, scanEventJournalFile))
	if err != nil {
		return nil
	}
	defer f.Close()

	type needle struct {
		endpoint string
		texts    []string
	}
	var pending []needle
	for _, ep := range b.endpointOrder {
		var texts []string
		for _, s := range b.endpointSamples[ep] {
			if len(s) >= 2 && s != "/" {
				texts = append(texts, s)
			}
		}
		if len(texts) == 0 {
			// fall back to the templated path's static prefix
			path, _ := b.nodeIdx[ep].Data["path"].(string)
			if i := strings.Index(path, "{"); i >= 0 {
				path = path[:i]
			}
			if len(path) >= 2 && path != "/" {
				texts = append(texts, path)
			}
		}
		if len(texts) > 0 {
			pending = append(pending, needle{endpoint: ep, texts: texts})
		}
	}
	if len(pending) == 0 {
		return nil
	}

	type callInfo struct {
		eventID, tool, command, timestamp, agentID string
	}
	lastCall := map[string]callInfo{}
	skipResult := map[string]bool{}
	byEvent := map[string]*discoveryEG{}
	var out []*discoveryEG

	reader := bufio.NewReaderSize(io.LimitReader(f, explorationMaxEventsBytes), 64<<10)
	lineNo := 0
	for len(pending) > 0 {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			lineNo++
			var ev egEvent
			if json.Unmarshal(line, &ev) == nil {
				var hay string
				var call callInfo
				switch ev.Type {
				case "tool_call":
					args := toolArgsEG(ev.ToolArgs)
					if !isDiscoveryToolEG(ev.ToolName) || isBookkeepingCommandEG(args) {
						// Its result must not be credited to the agent's
						// previous discovery call.
						delete(lastCall, ev.AgentID)
						skipResult[ev.AgentID] = true
						break
					}
					skipResult[ev.AgentID] = false
					eid := ev.EventID
					if eid == "" {
						eid = fmt.Sprintf("line-%d", lineNo)
					}
					call = callInfo{eid, ev.ToolName, commandFromArgsEG(args), ev.Timestamp, ev.AgentID}
					lastCall[ev.AgentID] = call
					var sb strings.Builder
					keys := make([]string, 0, len(args))
					for k := range args {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					for _, k := range keys {
						sb.WriteString(args[k])
						sb.WriteByte('\n')
					}
					sb.WriteString(ev.Content)
					hay = sb.String()
				case "tool_result":
					if (!isDiscoveryToolEG(ev.ToolName) && ev.ToolName != "") || skipResult[ev.AgentID] {
						break
					}
					c, ok := lastCall[ev.AgentID]
					if !ok {
						eid := ev.EventID
						if eid == "" {
							eid = fmt.Sprintf("line-%d", lineNo)
						}
						c = callInfo{eid, firstNonEmptyEG(ev.ToolName, "tool"), "", ev.Timestamp, ev.AgentID}
					}
					call = c
					hay = ev.Output + "\n" + ev.Content
				}
				if hay != "" {
					if len(hay) > explorationMaxHaystack {
						hay = hay[:explorationMaxHaystack]
					}
					kept := pending[:0]
					for _, nd := range pending {
						hit := false
						for _, t := range nd.texts {
							if strings.Contains(hay, t) {
								hit = true
								break
							}
						}
						if !hit {
							kept = append(kept, nd)
							continue
						}
						d := byEvent[call.eventID]
						if d == nil {
							d = &discoveryEG{
								nodeID: "discovery:" + call.eventID, tool: call.tool, command: call.command,
								eventID: call.eventID, timestamp: call.timestamp, agentID: call.agentID,
							}
							byEvent[call.eventID] = d
							out = append(out, d)
						}
						d.endpoints = append(d.endpoints, nd.endpoint)
					}
					pending = kept
				}
			}
		}
		if err != nil {
			break
		}
	}
	return out
}

// ---- finishing: finding_ids propagation, pruning, stats ----

var severityRankEG = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

func normalizeSeverityEG(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "critical", "high", "medium", "low", "info":
		return s
	case "informational", "information", "none":
		return "info"
	case "moderate":
		return "medium"
	}
	return ""
}

func (b *explorationBuilder) propagateFindingIDs() {
	incoming := map[string][]string{}
	for _, e := range b.edges {
		if e.Kind == "reveals" {
			continue
		}
		incoming[e.Target] = append(incoming[e.Target], e.Source)
	}
	sets := map[string]map[string]bool{}
	sevs := map[string]string{}
	for _, n := range b.nodes {
		if n.Type != "finding" {
			continue
		}
		fid, _ := n.Data["id"].(string)
		sev := n.Severity
		visited := map[string]bool{n.ID: true}
		queue := []string{n.ID}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			if sets[cur] == nil {
				sets[cur] = map[string]bool{}
			}
			sets[cur][fid] = true
			if severityRankEG[sev] > severityRankEG[sevs[cur]] {
				sevs[cur] = sev
			}
			for _, src := range incoming[cur] {
				if !visited[src] {
					visited[src] = true
					queue = append(queue, src)
				}
			}
		}
	}
	// backend nodes: findings that reveal them (directly or via evidence)
	for _, e := range b.edges {
		if e.Kind != "reveals" {
			continue
		}
		for fid := range sets[e.Source] {
			if sets[e.Target] == nil {
				sets[e.Target] = map[string]bool{}
			}
			sets[e.Target][fid] = true
		}
	}
	for _, n := range b.nodes {
		if ids := sets[n.ID]; len(ids) > 0 {
			n.FindingIDs = sortedKeysEG(ids)
			if n.Severity == "" && n.Type != "backend" && n.Type != "target" {
				n.Severity = sevs[n.ID]
			}
			if n.Status == "" && (n.Type == "endpoint" || n.Type == "parameter") {
				n.Status = "proven"
			}
		}
	}
}

var nodeTypePriorityEG = map[string]int{
	"target": 0, "finding": 1, "endpoint": 2, "parameter": 3, "attempt": 4,
	"evidence": 5, "backend": 6, "agent": 7, "discovery": 8,
}

func (b *explorationBuilder) finish(rec *ScanRecord, scope string) *ExplorationGraph {
	g := &ExplorationGraph{
		ScanID: rec.ID, Target: rec.Target, Status: rec.Status, Scope: scope,
		Nodes: []ExplorationNode{}, Edges: []ExplorationEdge{},
	}
	nodes := b.nodes
	if len(nodes) > explorationMaxNodes {
		g.Truncated = true
		sorted := append([]*ExplorationNode(nil), nodes...)
		sort.SliceStable(sorted, func(i, j int) bool {
			a, c := sorted[i], sorted[j]
			if (a.Type == "target") != (c.Type == "target") {
				return a.Type == "target"
			}
			if (len(a.FindingIDs) > 0) != (len(c.FindingIDs) > 0) {
				return len(a.FindingIDs) > 0
			}
			if nodeTypePriorityEG[a.Type] != nodeTypePriorityEG[c.Type] {
				return nodeTypePriorityEG[a.Type] < nodeTypePriorityEG[c.Type]
			}
			return a.order < c.order
		})
		sorted = sorted[:explorationMaxNodes]
		sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].order < sorted[j].order })
		nodes = sorted
	}
	kept := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		kept[n.ID] = true
		g.Nodes = append(g.Nodes, *n)
		switch n.Type {
		case "endpoint":
			g.Stats.Endpoints++
		case "parameter":
			g.Stats.Parameters++
		case "attempt":
			g.Stats.Attempts++
			if n.Status == "proven" {
				g.Stats.Proven++
			}
		case "finding":
			g.Stats.Findings++
			if n.Verified != nil && *n.Verified {
				g.Stats.Verified++
			}
		case "agent":
			g.Stats.Agents++
		case "backend":
			g.Stats.Backend++
		}
	}
	for _, e := range b.edges {
		if kept[e.Source] && kept[e.Target] {
			g.Edges = append(g.Edges, e)
		}
	}
	return g
}

// ---- file readers ----

func readBoundedEG(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s too large: %d bytes", filepath.Base(path), info.Size())
	}
	return os.ReadFile(path)
}

func readLedgerEG(scanDir string) egLedgerFile {
	var l egLedgerFile
	if scanDir == "" {
		return l
	}
	data, err := readBoundedEG(filepath.Join(scanDir, "ledger.json"), explorationMaxLedgerBytes)
	if err != nil {
		return l
	}
	if json.Unmarshal(data, &l) != nil {
		return egLedgerFile{}
	}
	return l
}

func readExecGraphEG(scanDir string) egExecGraph {
	var g egExecGraph
	if scanDir == "" {
		return g
	}
	data, err := readBoundedEG(filepath.Join(scanDir, "execution-graph.json"), explorationMaxExecGraph)
	if err != nil {
		return g
	}
	if json.Unmarshal(data, &g) != nil {
		return egExecGraph{}
	}
	return g
}

// ---- small helpers ----

func truncateRunesEG(s string, n int) string {
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

func firstNonEmptyEG(vals ...string) string {
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

func firstLineEG(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func sortedKeysEG(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var egSlugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slugEG(s string) string {
	return strings.Trim(egSlugRe.ReplaceAllString(strings.ToLower(s), "-"), "-")
}

// ---- HTTP handler ----

func writeGraphJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// handleScanGraph serves GET /api/scans/{id}/graph?scope=findings|all.
func (s *Server) handleScanGraph(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeGraphJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	scanID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/scans/"), "/graph")
	if scanID == "" || strings.Contains(scanID, "/") || scanID == "." || scanID == ".." {
		writeGraphJSONError(w, http.StatusNotFound, "scan not found")
		return
	}
	scope := explorationScopeFindings
	if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("scope")), explorationScopeAll) {
		scope = explorationScopeAll
	}

	var rec *ScanRecord
	dir, ok := s.resolveScanDirByID(scanID)
	if ok {
		if loaded, ok2 := s.loadScanRecordForDetail(dir, 0); ok2 && loaded != nil {
			rec = loaded
		} else {
			rec = &ScanRecord{ID: scanID}
		}
		s.applyInstanceSnapshot(rec, false)
	} else {
		// A scan that exists only in memory (no directory yet) still gets a
		// findings-only graph from its live record.
		s.instancesMu.RLock()
		inst := s.instances[scanID]
		s.instancesMu.RUnlock()
		rec = s.scanRecordFromInstance(inst)
		if rec == nil {
			writeGraphJSONError(w, http.StatusNotFound, "scan not found")
			return
		}
		dir = ""
	}
	finalizeScanRecordForResponse(rec)

	graph, err := buildExplorationGraph(dir, rec, scope)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeGraphJSONError(w, http.StatusNotFound, "scan not found")
			return
		}
		writeGraphJSONError(w, http.StatusInternalServerError, "failed to build graph")
		return
	}
	if graph.ScanID == "" {
		graph.ScanID = scanID
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(graph)
}
