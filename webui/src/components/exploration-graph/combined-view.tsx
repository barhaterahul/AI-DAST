import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  MarkerType,
  MiniMap,
  Panel,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge,
  type EdgeTypes,
  type Node,
  type NodeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  AlertTriangle,
  ChevronsDownUp,
  ChevronsUpDown,
  Eye,
  EyeOff,
  Link2,
  Link2Off,
  Loader2,
  Maximize,
  Network,
  RefreshCw,
  Search,
  X,
} from "lucide-react";
import { useExplorationCombined } from "@/api/queries";
import { HttpError } from "@/api/client";
import type { CombinedGroup, ExplorationCombined, ExplorationScope } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState, ErrorState } from "@/components/states";
import { cn } from "@/lib/utils";
import { useDebounced } from "@/lib/use-debounced";
import { useI18n } from "@/i18n";
import { useTheme } from "@/store/theme";
import { DetailPanel, type NeighborRef } from "./detail-panel";
import { GraphLegend } from "./legend";
import { buildAdjacency, traceSet } from "./layout";
import { NODE_META, NODE_TYPES, accentFor, edgeMeta, str, truncate } from "./meta";
import { nodeTypes as graphNodeTypes, type FlowNodeData } from "./nodes";
import { edgeTypes as graphEdgeTypes, type FlowEdgeData } from "./edges";
import {
  LANE_HEADER_H,
  LANE_PAD_X,
  LINK_KINDS,
  SUMMARY_H,
  SUMMARY_MAX_W,
  displayId,
  haystack,
  laneNodeId,
  laneTitle,
  layoutLanes,
  linkColor,
  linkLabel,
  stackLanes,
  summaryNodeId,
  typeCountsOf,
  type CombinedGraphNode,
  type LaneLayout,
} from "./lanes";
import {
  laneAccent,
  laneEdgeTypes,
  laneNodeTypes,
  type LaneLabels,
  type LaneNodeData,
  type LinkEdgeData,
  type SummaryNodeData,
} from "./lane-nodes";

// Combined Exploration Graph: several scans' graphs side by side, one
// collapsible horizontal lane per target, with dashed cross-lane links for
// what the targets share. Every scan-derived string is untrusted and is
// rendered as React text only.

const ALL_NODE_TYPES: NodeTypes = { ...graphNodeTypes, ...laneNodeTypes };
const ALL_EDGE_TYPES: EdgeTypes = { ...graphEdgeTypes, ...laneEdgeTypes };

/** Above this many nodes React Flow only renders what is on screen. */
const VIRTUALIZE_AT = 250;
/** Above this many total nodes, lanes after the first two start collapsed. */
const AUTO_COLLAPSE_AT = 400;
/** Show link captions permanently only while they stay readable. */
const LINK_LABEL_LIMIT = 12;

function useTr() {
  const { t } = useI18n();
  return useCallback((k: string, f: string) => (t(k) === k ? f : t(k)), [t]);
}

export function CombinedGraphView({
  scanIds,
  scope: scopeProp,
  onScopeChange,
  onOpenScan,
  className,
}: {
  scanIds: string[];
  scope?: ExplorationScope;
  onScopeChange?: (s: ExplorationScope) => void;
  onOpenScan?: (scanId: string) => void;
  className?: string;
}) {
  const tr = useTr();
  const [localScope, setLocalScope] = useState<ExplorationScope>("findings");
  const scope = scopeProp ?? localScope;
  const setScope = useCallback(
    (s: ExplorationScope) => {
      setLocalScope(s);
      onScopeChange?.(s);
    },
    [onScopeChange],
  );
  const { data, isLoading, isFetching, error, refetch } = useExplorationCombined(scanIds, scope);
  const canvasKey = scanIds.join(",");

  if (scanIds.length === 0) {
    return (
      <EmptyState
        className={className}
        icon={<Network className="h-6 w-6" />}
        title={tr("exploration.combined.noSelection", "No targets selected")}
        description={tr(
          "exploration.combined.noSelectionHint",
          "Pick two or more targets in the overview to compare their exploration graphs side by side.",
        )}
      />
    );
  }

  const groups = data?.groups ?? [];
  const anyTruncated = !!data && (data.truncated || groups.some((g) => g.truncated));

  return (
    <div className={cn("space-y-3", className)}>
      <div className="flex flex-wrap items-center gap-2">
        <ScopeToggle scope={scope} onChange={setScope} />
        {data && (
          <span className="text-[11px] text-muted-foreground">
            <span className="font-semibold tabular-nums text-foreground">{groups.length}</span>{" "}
            {tr("exploration.combined.lanes", "targets")}
            {" · "}
            <span className="font-semibold tabular-nums text-foreground">{(data.nodes ?? []).length}</span>{" "}
            {tr("exploration.combined.nodes", "nodes")}
          </span>
        )}
        <div className="ml-auto flex items-center gap-2">
          {anyTruncated && (
            <span
              className="inline-flex items-center gap-1 rounded-md border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-[11px] text-amber-700 dark:text-amber-400"
              role="status"
            >
              <AlertTriangle className="h-3 w-3" aria-hidden />
              {data?.truncated
                ? tr("exploration.combined.truncated", "Combined graph truncated at node limit")
                : tr("exploration.combined.lanesTruncated", "Some lanes truncated at node limit")}
            </span>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            disabled={isFetching}
            aria-label={tr("common.refresh", "Refresh")}
          >
            {isFetching ? <Loader2 className="animate-spin" /> : <RefreshCw />}
          </Button>
        </div>
      </div>

      {isLoading && !data ? (
        <LoadingSkeleton count={Math.min(scanIds.length, 4)} />
      ) : error && !data ? (
        <ErrorState
          title={
            error instanceof HttpError && error.status === 404
              ? tr("exploration.combined.notFound", "Scans not found")
              : tr("exploration.combined.loadFailed", "Could not load the combined graph")
          }
          description={error instanceof Error ? truncate(error.message, 300) : undefined}
          action={
            <Button size="sm" variant="outline" onClick={() => refetch()}>
              {tr("common.retry", "Retry")}
            </Button>
          }
        />
      ) : !data || groups.length === 0 ? (
        <EmptyState
          icon={<Network className="h-6 w-6" />}
          title={tr("exploration.combined.empty", "Nothing to compare")}
          description={tr("exploration.combined.emptyHint", "None of the selected scans returned a graph.")}
        />
      ) : (
        <>
          {(data.nodes ?? []).length === 0 && scope === "findings" && (
            <div className="flex flex-wrap items-center gap-2 rounded-md border border-dashed border-border bg-card/50 px-3 py-2 text-xs text-muted-foreground">
              {tr(
                "exploration.combined.emptyFindings",
                "None of these scans has a finding with a recorded path yet.",
              )}
              <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => setScope("all")}>
                {tr("exploration.showEverything", "Show everything")}
              </Button>
            </div>
          )}
          <ReactFlowProvider>
            <CombinedCanvas key={canvasKey} combined={data} onOpenScan={onOpenScan} />
          </ReactFlowProvider>
        </>
      )}
    </div>
  );
}

function ScopeToggle({ scope, onChange }: { scope: ExplorationScope; onChange: (s: ExplorationScope) => void }) {
  const tr = useTr();
  const opts: { value: ExplorationScope; label: string }[] = [
    { value: "findings", label: tr("exploration.scope.findings", "Findings path") },
    { value: "all", label: tr("exploration.scope.all", "Everything") },
  ];
  return (
    <div
      className="inline-flex rounded-md border border-border bg-card p-0.5"
      role="radiogroup"
      aria-label={tr("exploration.scope", "Scope")}
    >
      {opts.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={scope === o.value}
          onClick={() => onChange(o.value)}
          className={cn(
            "rounded px-2.5 py-1 text-xs font-medium transition-colors",
            scope === o.value ? "bg-secondary text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

function LoadingSkeleton({ count }: { count: number }) {
  const tr = useTr();
  return (
    <div
      className="eg-canvas h-[70vh] min-h-[520px] space-y-4 overflow-hidden rounded-xl border border-border p-4"
      aria-busy="true"
      aria-label={tr("exploration.combined.loading", "Loading combined graph")}
    >
      <Skeleton className="h-8 w-72" />
      {Array.from({ length: Math.max(2, count) }, (_, i) => (
        <div key={i} className="space-y-3 rounded-2xl border border-border/60 p-3">
          <div className="flex items-center gap-3">
            <Skeleton className="h-7 w-7" />
            <Skeleton className="h-4 w-48" />
            <Skeleton className="h-4 w-20" />
            <Skeleton className="ml-auto h-7 w-28" />
          </div>
          <div className="flex gap-6">
            {Array.from({ length: 5 }, (_, j) => (
              <Skeleton key={j} className="h-14 w-40" />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function CombinedCanvas({
  combined,
  onOpenScan,
}: {
  combined: ExplorationCombined;
  onOpenScan?: (scanId: string) => void;
}) {
  const tr = useTr();
  const { resolved } = useTheme();
  const rf = useReactFlow();

  const allNodes = useMemo(() => (combined.nodes ?? []) as CombinedGraphNode[], [combined.nodes]);
  const allEdges = useMemo(() => combined.edges ?? [], [combined.edges]);
  const groups = useMemo(() => combined.groups ?? [], [combined.groups]);
  const byId = useMemo(() => new Map(allNodes.map((n) => [n.id, n])), [allNodes]);
  const groupById = useMemo(() => new Map(groups.map((g) => [g.id, g])), [groups]);
  const adjacency = useMemo(() => buildAdjacency(allEdges), [allEdges]);

  const [hidden, setHidden] = useState<Set<string>>(() => new Set());
  const [collapsedState, setCollapsedState] = useState<Set<string> | null>(null);
  const [showLinks, setShowLinks] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [hoverEdge, setHoverEdge] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const q = useDebounced(search.trim().toLowerCase(), 200);

  useEffect(() => {
    if (selectedId && !byId.has(selectedId)) setSelectedId(null);
  }, [byId, selectedId]);

  // Per-lane layouts, cached across refetches / filter changes per group.
  const layoutCache = useRef(new Map<string, { key: unknown[]; layout: LaneLayout }>());
  const layouts = useMemo(() => layoutLanes(combined, hidden, layoutCache.current), [combined, hidden]);

  // Until the user collapses/expands anything, big comparisons start with
  // only the first two lanes open.
  const collapsed = useMemo(() => {
    if (collapsedState) return collapsedState;
    if (allNodes.length <= AUTO_COLLAPSE_AT) return new Set<string>();
    return new Set(groups.slice(2).map((g) => g.id));
  }, [collapsedState, allNodes.length, groups]);

  const placed = useMemo(() => stackLanes(layouts, collapsed), [layouts, collapsed]);

  const toggleLane = useCallback(
    (groupId: string) =>
      setCollapsedState((prev) => {
        const next = new Set(prev ?? collapsed);
        if (next.has(groupId)) next.delete(groupId);
        else next.add(groupId);
        return next;
      }),
    [collapsed],
  );

  const refit = useCallback(
    (delay = 60) => window.setTimeout(() => rf.fitView({ duration: 400, padding: 0.08 }), delay),
    [rf],
  );

  const setAllCollapsed = (value: boolean) => {
    setCollapsedState(value ? new Set(groups.filter((g) => !g.error).map((g) => g.id)) : new Set());
    refit();
  };

  // Refit when the scope (and so the node set) changes.
  const firstScope = useRef(combined.scope);
  useEffect(() => {
    if (firstScope.current === combined.scope) return;
    firstScope.current = combined.scope;
    const t = refit();
    return () => window.clearTimeout(t);
  }, [combined.scope, refit]);

  const typeCounts = useMemo(() => typeCountsOf(allNodes), [allNodes]);

  const traced = useMemo(() => {
    if (!selectedId) return null;
    const n = byId.get(selectedId);
    if (!n) return null;
    return traceSet(selectedId, n.type, adjacency, (id) => byId.get(id)?.type);
  }, [selectedId, byId, adjacency]);
  const selected = selectedId ? byId.get(selectedId) : undefined;
  const selGroup = selected?.group ?? null;

  const searchIndex = useMemo(() => new Map(allNodes.map((n) => [n.id, haystack(n)])), [allNodes]);
  const matches = useMemo(() => {
    if (q.length < 2) return null;
    const s = new Set<string>();
    for (const [id, h] of searchIndex) if (h.includes(q)) s.add(id);
    return s;
  }, [q, searchIndex]);

  const visibleIds = useMemo(() => {
    const s = new Set<string>();
    for (const l of placed) if (!l.collapsed) for (const p of l.positioned) s.add(p.node.id);
    return s;
  }, [placed]);

  // Hits per lane among nodes of visible types (collapsed lanes still count).
  const hitsByGroup = useMemo(() => {
    if (!matches) return null;
    const m = new Map<string, number>();
    for (const l of layouts) {
      let c = 0;
      for (const p of l.positioned) if (matches.has(p.node.id)) c++;
      m.set(l.group.id, c);
    }
    return m;
  }, [matches, layouts]);
  const totalHits = useMemo(
    () => (hitsByGroup ? [...hitsByGroup.values()].reduce((a, b) => a + b, 0) : 0),
    [hitsByGroup],
  );

  const labels: LaneLabels = useMemo(
    () => ({
      collapse: tr("exploration.combined.collapse", "Collapse lane"),
      expand: tr("exploration.combined.expand", "Expand"),
      openScan: tr("exploration.combined.openScan", "Open scan graph"),
      endpoints: tr("exploration.stats.endpoints", "endpoints"),
      attempts: tr("exploration.stats.attempts", "attempts"),
      findings: tr("exploration.stats.findings", "findings"),
      truncated: tr("exploration.combined.laneTruncated", "truncated"),
      emptyLane: tr("exploration.combined.emptyLane", "No nodes for this target in the current scope and filters."),
      laneError: tr("exploration.combined.laneError", "This scan's graph could not be loaded"),
      hits: tr("exploration.matches", "hits"),
      nodes: tr("exploration.combined.nodes", "nodes"),
    }),
    [tr],
  );

  const manyEdges = useMemo(() => placed.reduce((a, l) => a + (l.collapsed ? 0 : l.edges.length), 0) > 300, [placed]);

  const flowNodes: Node[] = useMemo(() => {
    const out: Node[] = [];
    for (const l of placed) {
      const g = l.group;
      const laneId = laneNodeId(g.id);
      const hits = hitsByGroup ? (hitsByGroup.get(g.id) ?? 0) : null;
      const laneData: LaneNodeData = {
        group: g,
        title: laneTitle(g),
        collapsed: l.collapsed,
        stages: l.stages,
        visible: l.positioned.length,
        hits,
        dim: hits === 0,
        labels,
        onToggle: toggleLane,
        onOpenScan,
      };
      out.push({
        id: laneId,
        type: "lane",
        position: { x: l.x, y: l.y },
        width: l.width,
        height: l.height,
        draggable: false,
        selectable: false,
        focusable: false,
        data: laneData,
      });
      if (g.error) continue;
      if (l.collapsed) {
        const summaryData: SummaryNodeData = {
          group: g,
          counts: typeCountsOf(l.allNodes),
          total: l.allNodes.length,
          hits,
          labels,
          onToggle: toggleLane,
        };
        out.push({
          id: summaryNodeId(g.id),
          type: "laneSummary",
          parentId: laneId,
          position: { x: LANE_PAD_X, y: LANE_HEADER_H + 10 },
          width: Math.min(SUMMARY_MAX_W, l.width - LANE_PAD_X * 2),
          height: SUMMARY_H,
          draggable: false,
          selectable: false,
          data: summaryData,
        });
        continue;
      }
      for (const p of l.positioned) {
        const id = p.node.id;
        const inTraceLane = !!traced && selGroup === g.id;
        const nodeData: FlowNodeData = {
          node: p.node,
          traced: inTraceLane && traced!.has(id),
          dim: (inTraceLane && !traced!.has(id)) || (matches ? !matches.has(id) : false),
          match: !!matches?.has(id),
          delay: Math.min(600, Math.round((p.x / Math.max(1, l.width)) * 600)),
        };
        out.push({
          id,
          type: p.node.type in graphNodeTypes ? p.node.type : "target",
          parentId: laneId,
          position: { x: p.x, y: p.y },
          width: p.width,
          height: p.height,
          draggable: false,
          selected: id === selectedId,
          data: nodeData,
        });
      }
    }
    return out;
  }, [placed, hitsByGroup, labels, toggleLane, onOpenScan, traced, selGroup, matches, selectedId]);

  const links = useMemo(
    () => (combined.links ?? []).filter((k) => groupById.has(k.source) && groupById.has(k.target) && k.source !== k.target),
    [combined.links, groupById],
  );

  const flowEdges: Edge[] = useMemo(() => {
    const out: Edge[] = [];
    for (const l of placed) {
      if (l.collapsed || l.group.error) continue;
      const inTraceLane = !!traced && selGroup === l.group.id;
      for (const e of l.edges) {
        const src = byId.get(e.source);
        const dst = byId.get(e.target);
        const from = src ? accentFor(src.type, src.severity) : edgeMeta(e.kind).color;
        const to = dst ? accentFor(dst.type, dst.severity) : edgeMeta(e.kind).color;
        const active = inTraceLane && traced!.has(e.source) && traced!.has(e.target);
        const dim = (inTraceLane && !active) || (!!matches && !(matches.has(e.source) || matches.has(e.target)));
        const hovered = hoverEdge === e.id;
        const particles = dim
          ? 0
          : active && e.kind !== "assigned"
            ? 2
            : !manyEdges && !traced && (e.kind === "proves" || e.kind === "injected")
              ? 1
              : 0;
        const data: FlowEdgeData = { from, to, kind: e.kind, bridged: e.bridged, active, dim, hovered, particles };
        out.push({
          id: e.id,
          source: e.source,
          target: e.target,
          type: "flow",
          zIndex: active || hovered ? 10 : 0,
          markerEnd: { type: MarkerType.ArrowClosed, color: to, width: 14, height: 14 },
          data,
        });
      }
    }
    if (showLinks) {
      const pairCount = new Map<string, number>();
      for (const k of links) {
        const pair = [k.source, k.target].sort().join("\u0000");
        const idx = pairCount.get(pair) ?? 0;
        pairCount.set(pair, idx + 1);
        const id = `link:${k.id || `${pair}:${idx}`}`;
        const data: LinkEdgeData = {
          kind: k.kind,
          label: str(k.label),
          weight: Math.max(1, Number(k.weight) || 1),
          evidence: Array.isArray(k.evidence) ? k.evidence.map(str) : [],
          color: linkColor(k.kind),
          offset: idx * 26,
          hovered: hoverEdge === id,
          dim: !!selGroup && k.source !== selGroup && k.target !== selGroup,
          showLabel: links.length <= LINK_LABEL_LIMIT,
        };
        out.push({
          id,
          source: laneNodeId(k.source),
          target: laneNodeId(k.target),
          sourceHandle: "link-out",
          targetHandle: "link-in",
          type: "laneLink",
          zIndex: 1000,
          data,
        });
      }
    }
    return out;
  }, [placed, byId, traced, selGroup, matches, hoverEdge, manyEdges, showLinks, links]);

  const focusNodes = useCallback(
    (ids: string[]) => {
      if (ids.length === 0) return;
      // Wait a frame so React Flow has the (possibly new) nodes measured.
      window.setTimeout(
        () => rf.fitView({ nodes: ids.map((id) => ({ id })), duration: 500, padding: 0.25, maxZoom: 1.2 }),
        60,
      );
    },
    [rf],
  );

  const selectAndTrace = useCallback(
    (id: string) => {
      setSelectedId(id);
      const n = byId.get(id);
      if (!n) return;
      const set = traceSet(id, n.type, adjacency, (x) => byId.get(x)?.type);
      focusNodes([...set].filter((x) => visibleIds.has(x)));
    },
    [byId, adjacency, visibleIds, focusNodes],
  );

  const focusMatches = () => {
    if (!matches || !hitsByGroup) return;
    const toOpen = [...hitsByGroup.entries()].filter(([gid, c]) => c > 0 && collapsed.has(gid)).map(([gid]) => gid);
    if (toOpen.length) {
      setCollapsedState((prev) => {
        const next = new Set(prev ?? collapsed);
        for (const gid of toOpen) next.delete(gid);
        return next;
      });
    }
    const ids: string[] = [];
    for (const l of layouts) for (const p of l.positioned) if (matches.has(p.node.id)) ids.push(p.node.id);
    focusNodes(ids);
  };

  const neighbors = useMemo(() => {
    if (!selectedId) return { up: [] as NeighborRef[], down: [] as NeighborRef[] };
    const up: NeighborRef[] = [];
    const down: NeighborRef[] = [];
    for (const e of allEdges) {
      if (e.target === selectedId) {
        const n = byId.get(e.source);
        if (n) up.push({ node: n, kind: e.kind });
      } else if (e.source === selectedId) {
        const n = byId.get(e.target);
        if (n) down.push({ node: n, kind: e.kind });
      }
    }
    return { up, down };
  }, [selectedId, allEdges, byId]);

  // The inspector shows the original (unprefixed) node id.
  const panelNode = useMemo(
    () => (selected ? { ...selected, id: displayId(selected.id, selected.group) } : undefined),
    [selected],
  );
  const panelGroup: CombinedGroup | undefined = selGroup ? groupById.get(selGroup) : undefined;

  const toggleType = (type: string) =>
    setHidden((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });

  const allCollapsed = groups.every((g) => g.error || collapsed.has(g.id));
  const visibleCount = layouts.reduce((a, l) => a + l.positioned.length, 0);
  const kindsPresent = LINK_KINDS.filter((k) => links.some((l) => l.kind === k));

  return (
    <div className="space-y-2">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-64">
          <Search
            className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") focusMatches();
              if (e.key === "Escape") setSearch("");
            }}
            placeholder={tr("exploration.combined.search", "Search all targets…")}
            aria-label={tr("exploration.combined.search", "Search all targets…")}
            className="h-8 pl-8 pr-16 text-xs"
            maxLength={200}
          />
          {matches && (
            <span
              className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] tabular-nums text-muted-foreground"
              aria-live="polite"
            >
              {totalHits} {tr("exploration.matches", "hits")}
            </span>
          )}
        </div>

        <Button
          size="sm"
          variant="outline"
          className="h-8 text-xs"
          onClick={() => setAllCollapsed(!allCollapsed)}
          aria-label={
            allCollapsed
              ? tr("exploration.combined.expandAll", "Expand all")
              : tr("exploration.combined.collapseAll", "Collapse all")
          }
        >
          {allCollapsed ? <ChevronsUpDown className="h-3.5 w-3.5" /> : <ChevronsDownUp className="h-3.5 w-3.5" />}
          {allCollapsed
            ? tr("exploration.combined.expandAll", "Expand all")
            : tr("exploration.combined.collapseAll", "Collapse all")}
        </Button>

        {links.length > 0 && (
          <Button
            size="sm"
            variant="outline"
            className="h-8 text-xs"
            onClick={() => setShowLinks((v) => !v)}
            aria-pressed={showLinks}
            title={kindsPresent.map(linkLabel).join(" · ")}
          >
            {showLinks ? <Link2 className="h-3.5 w-3.5" /> : <Link2Off className="h-3.5 w-3.5" />}
            {tr("exploration.combined.links", "Shared links")}
            <span className="tabular-nums text-muted-foreground">{links.length}</span>
            <span className="flex items-center gap-0.5" aria-hidden>
              {kindsPresent.map((k) => (
                <span key={k} className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: linkColor(k) }} />
              ))}
            </span>
          </Button>
        )}

        {selectedId && (
          <Button size="sm" variant="ghost" className="h-8 text-xs" onClick={() => setSelectedId(null)}>
            <X className="h-3.5 w-3.5" />
            {tr("exploration.clearTrace", "Clear trace")}
          </Button>
        )}

        <div className="flex flex-wrap items-center gap-1 lg:ml-auto">
          {NODE_TYPES.filter((t) => typeCounts[t]).map((type) => {
            const m = NODE_META[type];
            const Icon = m.icon;
            const off = hidden.has(type);
            return (
              <button
                key={type}
                type="button"
                onClick={() => toggleType(type)}
                aria-pressed={!off}
                aria-label={`${off ? "Show" : "Hide"} ${m.label.toLowerCase()} nodes`}
                title={`${off ? "Show" : "Hide"} ${m.label.toLowerCase()} nodes`}
                className={cn(
                  "inline-flex h-7 items-center gap-1 rounded-md border px-1.5 text-[11px] transition-colors",
                  off
                    ? "border-dashed border-border text-muted-foreground/60 line-through"
                    : "border-border bg-card text-foreground hover:bg-accent",
                )}
              >
                <Icon className="h-3 w-3" style={{ color: off ? undefined : m.color }} />
                <span className="hidden xl:inline">{m.label}</span>
                <span className="tabular-nums text-muted-foreground">{typeCounts[type]}</span>
                {off ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3 opacity-40" />}
              </button>
            );
          })}
        </div>
      </div>

      {/* Canvas + inspector */}
      <div className={cn("grid gap-3", panelNode && "lg:grid-cols-[minmax(0,1fr)_400px]")}>
        <div className="eg-canvas relative h-[70vh] min-h-[520px] overflow-hidden rounded-xl border border-border shadow-inner">
          <ReactFlow
            nodes={flowNodes}
            edges={flowEdges}
            nodeTypes={ALL_NODE_TYPES}
            edgeTypes={ALL_EDGE_TYPES}
            onNodeClick={(_, n) => {
              if (n.type === "lane" || n.type === "laneSummary") return;
              setSelectedId((cur) => (cur === n.id ? null : n.id));
            }}
            onPaneClick={() => setSelectedId(null)}
            onEdgeMouseEnter={(_, e) => setHoverEdge(e.id)}
            onEdgeMouseLeave={() => setHoverEdge(null)}
            nodesConnectable={false}
            nodesDraggable={false}
            elementsSelectable={false}
            onlyRenderVisibleElements={flowNodes.length > VIRTUALIZE_AT}
            colorMode={resolved}
            fitView
            fitViewOptions={{ padding: 0.08, minZoom: 0.2 }}
            minZoom={0.03}
            maxZoom={2}
            aria-label={tr("exploration.combined.canvas", "Combined exploration graph")}
          >
            <Background
              id="egc-dots"
              variant={BackgroundVariant.Dots}
              gap={18}
              size={1}
              color={resolved === "dark" ? "#ffffff1f" : "#0000001f"}
            />
            <Controls showInteractive={false} position="bottom-left" />
            <MiniMap
              pannable
              zoomable
              position="bottom-right"
              nodeColor={(n) => {
                if (n.type === "lane" || n.type === "laneSummary") {
                  const g = (n.data as LaneNodeData | SummaryNodeData | undefined)?.group;
                  return g ? `${laneAccent(g)}${n.type === "lane" ? "26" : "88"}` : "#71717a26";
                }
                const gn = (n.data as FlowNodeData | undefined)?.node;
                return gn ? accentFor(gn.type, gn.severity) : "#71717a";
              }}
              nodeStrokeWidth={0}
              nodeBorderRadius={6}
              maskColor={resolved === "dark" ? "rgba(0,0,0,0.6)" : "rgba(255,255,255,0.6)"}
              className="!rounded-md !border !border-border"
            />
            <Panel position="top-left">
              <GraphLegend />
            </Panel>
            <Panel position="top-right" className="flex gap-1">
              <Button
                size="sm"
                variant="secondary"
                className="h-7 text-xs"
                onClick={() => rf.fitView({ duration: 400, padding: 0.08 })}
              >
                <Maximize className="h-3.5 w-3.5" />
                {tr("exploration.fitView", "Fit")}
              </Button>
            </Panel>
            {showLinks && kindsPresent.length > 0 && (
              <Panel position="bottom-center" className="!mb-3">
                <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-card/90 px-2 py-1 text-[10px] shadow-sm backdrop-blur">
                  {kindsPresent.map((k) => (
                    <span key={k} className="inline-flex items-center gap-1">
                      <svg width="18" height="6" aria-hidden>
                        <line x1="0" y1="3" x2="18" y2="3" stroke={linkColor(k)} strokeWidth="2" strokeDasharray="4 3" />
                      </svg>
                      {linkLabel(k)}
                    </span>
                  ))}
                </div>
              </Panel>
            )}
          </ReactFlow>
        </div>

        {panelNode && selected && (
          <div className="flex min-w-0 flex-col gap-2">
            {panelGroup && (
              <p className="truncate px-1 font-mono text-[11px] text-muted-foreground" title={panelGroup.target}>
                {laneTitle(panelGroup)}
              </p>
            )}
            <DetailPanel
              className="h-[70vh] min-h-[520px]"
              node={panelNode}
              scanId={panelGroup?.scan_id ?? ""}
              upstream={neighbors.up}
              downstream={neighbors.down}
              onSelect={selectAndTrace}
              onClose={() => setSelectedId(null)}
            />
          </div>
        )}
      </div>
      {visibleCount === 0 && hidden.size > 0 && (
        <p className="text-xs text-muted-foreground">
          {tr("exploration.allHidden", "All node types are hidden — re-enable some filters above.")}
        </p>
      )}
    </div>
  );
}
