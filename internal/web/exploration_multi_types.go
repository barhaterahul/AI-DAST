package web

// Shared API contract for the multi-target Exploration views. Handlers live in
// exploration_overview.go (GET /api/exploration/overview) and
// exploration_combined.go (GET /api/exploration/combined).

// ExplorationOverview is the portfolio view: one entry per target (host),
// cross-target links and a target × vuln-class matrix.
type ExplorationOverview struct {
	GeneratedAt string              `json:"generated_at"`
	Targets     []OverviewTarget    `json:"targets"`
	Links       []OverviewLink      `json:"links"`
	Matrix      OverviewMatrix      `json:"matrix"`
	Totals      OverviewTotals      `json:"totals"`
	Truncated   bool                `json:"truncated"` // more targets than the limit
	Filters     OverviewFiltersEcho `json:"filters"`
}

// OverviewTarget aggregates every scan of one target. Key is the normalized
// host (e.g. "api.shop.test" or "localhost:8080"), stable across scans.
type OverviewTarget struct {
	Key           string            `json:"key"`
	Label         string            `json:"label"`          // display (first scan's target URL)
	LatestScanID  string            `json:"latest_scan_id"` // record id usable with /api/scans/{id}/graph
	LatestStatus  string            `json:"latest_status"`
	LastScanned   string            `json:"last_scanned"` // RFC3339
	Scans         []OverviewScanRef `json:"scans"`        // newest first, max 20
	Endpoints     int               `json:"endpoints"`    // from the latest scan's graph
	Parameters    int               `json:"parameters"`
	Attempts      int               `json:"attempts"`
	Findings      int               `json:"findings"` // latest scan
	Verified      int               `json:"verified"`
	Severity      SeverityCounts    `json:"severity"`     // latest scan's findings
	TopSeverity   string            `json:"top_severity"` // critical|high|medium|low|info|"" (none)
	VulnClasses   map[string]int    `json:"vuln_classes"` // class -> count (latest scan)
	Backend       []OverviewTech    `json:"backend"`      // detected technology
	TokenProvider string            `json:"token_provider,omitempty"`
}

type OverviewScanRef struct {
	ID          string `json:"id"`
	InstanceID  string `json:"instance_id,omitempty"`
	Status      string `json:"status"`
	StartedAt   string `json:"started_at"`
	Findings    int    `json:"findings"`
	TopSeverity string `json:"top_severity"`
}

type OverviewTech struct {
	Name     string `json:"name"`
	Category string `json:"category"` // database|server|framework|language|parser|os|waf|other
}

type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// OverviewLink connects two targets that share something.
//
//	kind: shared_backend      same technology (evidence: tech names)
//	      shared_vuln_class   same vulnerability class found on both
//	      shared_auth         same token provider / identical default credential finding
//	      shared_infra        same resolved host/port family or server banner
type OverviewLink struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Source   string   `json:"source"` // OverviewTarget.Key
	Target   string   `json:"target"` // OverviewTarget.Key
	Label    string   `json:"label"`  // short, e.g. "Apache Derby" or "sqli"
	Weight   int      `json:"weight"` // >=1; how many shared items
	Evidence []string `json:"evidence,omitempty"`
}

type OverviewMatrix struct {
	Classes []string             `json:"classes"` // column order (most frequent first)
	Cells   []OverviewMatrixCell `json:"cells"`
}

type OverviewMatrixCell struct {
	Target      string `json:"target"` // OverviewTarget.Key
	Class       string `json:"class"`
	Count       int    `json:"count"`
	TopSeverity string `json:"top_severity"`
}

type OverviewTotals struct {
	Targets  int            `json:"targets"`
	Scans    int            `json:"scans"`
	Findings int            `json:"findings"`
	Severity SeverityCounts `json:"severity"`
}

type OverviewFiltersEcho struct {
	Q           string `json:"q,omitempty"`
	MinSeverity string `json:"min_severity,omitempty"`
	Status      string `json:"status,omitempty"`
	Since       string `json:"since,omitempty"`
	Limit       int    `json:"limit"`
}

// ExplorationCombined merges several scans' graphs for side-by-side lanes.
// Node and edge IDs are prefixed "<group index>:" so they never collide, and
// every node carries Group = the lane's id.
type ExplorationCombined struct {
	Scope     string            `json:"scope"`
	Groups    []CombinedGroup   `json:"groups"`
	Nodes     []CombinedNode    `json:"nodes"`
	Edges     []ExplorationEdge `json:"edges"`
	Links     []OverviewLink    `json:"links"` // cross-lane links (Source/Target are group ids)
	Truncated bool              `json:"truncated"`
}

type CombinedGroup struct {
	ID          string           `json:"id"` // "g0", "g1", …
	ScanID      string           `json:"scan_id"`
	Target      string           `json:"target"`
	Key         string           `json:"key"` // normalized host
	Status      string           `json:"status"`
	Stats       ExplorationStats `json:"stats"`
	Severity    SeverityCounts   `json:"severity"`
	TopSeverity string           `json:"top_severity"`
	Truncated   bool             `json:"truncated"`
	Error       string           `json:"error,omitempty"` // scan not found / unreadable
}

type CombinedNode struct {
	ExplorationNode
	Group string `json:"group"`
}
