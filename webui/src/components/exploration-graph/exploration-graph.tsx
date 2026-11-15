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
  ViewportPortal,
  useReactFlow,
  type NodeChange,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  AlertTriangle,
  BadgeCheck,
  Crosshair,
  Eye,
  EyeOff,
  Expand,
  Shrink,
  Loader2,
  Maximize,
  Network,
  Play,
  RefreshCw,
  RotateCcw,
  Search,
  Square,
  X,
} from "lucide-react";
import { useScanGraph } from "@/api/queries";
import type {
  ExplorationGraph,
  ExplorationGraphNode,
  ExplorationGraphStats,
  ExplorationScope,
} from "@/types/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { EmptyState, ErrorState } from "@/components/states";
import { HttpError } from "@/api/client";
import { cn, normalizeSeverity } from "@/lib/utils";
import { useDebounced } from "@/lib/use-debounced";
import { useI18n } from "@/i18n";
import { useTheme } from "@/store/theme";
import { DetailPanel, type NeighborRef } from "./detail-panel";
import { GraphLegend } from "./legend";
import { buildAdjacency, filterGraph, layoutGraph, traceSet } from "./layout";
import { NODE_META, NODE_TYPES, SEVERITY_COLORS, accentFor, edgeMeta, nodeMeta, str, truncate } from "./meta";
import { nodeTypes, type FlowNode } from "./nodes";
import { edgeTypes, type FlowEdge } from "./edges";
import type { PositionedNode } from "./layout";

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const RUNNING = new Set(["running", "pending", "paused"]);

function useTr() {
  const { t } = useI18n();
  return useCallback((k: string, f: string) => (t(k) === k ? f : t(k)), [t]);
}

/**
 * Exploration Graph for one scan: fetches GET /api/scans/{id}/graph and
 * renders the discovery -> injection -> proof chain. Scope can be controlled
 * by the parent (page toolbar) or left to the component (scan-detail tab).
 */
export function ExplorationGraphView({
  scanId,
  scope: scopeProp,
  onScopeChange,
  className,
}: {
  scanId: string;
  scope?: ExplorationScope;
  onScopeChange?: (s: ExplorationScope) => void;
  className?: string;
}) {
  const tr = useTr();
  const [localScope, setLocalScope] = useState<ExplorationScope>("findings");
  const scope = scopeProp ?? localScope;
  const setScope = (s: ExplorationScope) => {
    setLocalScope(s);
    onScopeChange?.(s);
  };
  const { data, isLoading, isFetching, error, refetch } = useScanGraph(scanId, scope);
  const running = RUNNING.has((data?.status || "").toLowerCase());

  return (
    <div className={cn("space-y-3", className)}>
      <div className="flex flex-wrap items-center gap-2">
        <ScopeToggle scope={scope} onChange={setScope} />
        {data && <StatsBar stats={data.stats} />}
        {data && <SeverityStrip nodes={data.nodes ?? []} />}
        <div className="ml-auto flex items-center gap-2">
          {data?.truncated && (
            <span className="inline-flex items-center gap-1 rounded-md border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-[11px] text-amber-700 dark:text-amber-400">
              <AlertTriangle className="h-3 w-3" />
              {tr("exploration.truncated", "Graph truncated at node limit")}
            </span>
          )}
          {running && (
            <span className="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-500" />
              {tr("exploration.live", "Live — refreshes every 15s")}
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
        <Skeleton className="h-[70vh] min-h-[520px] w-full" />
      ) : error && !data ? (
        <ErrorState
          title={
            error instanceof HttpError && error.status === 404
              ? tr("exploration.notFound", "Scan not found")
              : tr("exploration.loadFailed", "Could not load the exploration graph")
          }
          description={error instanceof Error ? truncate(error.message, 300) : undefined}
          action={
            <Button size="sm" variant="outline" onClick={() => refetch()}>
              {tr("common.retry", "Retry")}
            </Button>
          }
        />
      ) : !data || !data.nodes || data.nodes.length === 0 ? (
        <EmptyState
          icon={<Network className="h-6 w-6" />}
          title={
            scope === "findings"
              ? tr("exploration.emptyFindings", "No finding paths yet")
              : tr("exploration.emptyAll", "Nothing explored yet")
          }
          description={
            scope === "findings"
              ? tr(
                  "exploration.emptyFindingsHint",
                  "This scan has no findings with a recorded path. Switch to “Everything” to see rejected and blocked attempts.",
                )
              : running
                ? tr("exploration.emptyRunning", "The scan is running — attempts will appear here as agents work.")
                : tr("exploration.emptyAllHint", "No attempts were recorded for this scan.")
          }
          action={
            scope === "findings" ? (
              <Button size="sm" variant="outline" onClick={() => setScope("all")}>
                {tr("exploration.showEverything", "Show everything")}
              </Button>
            ) : undefined
          }
        />
      ) : (
        <ReactFlowProvider>
          <GraphCanvas key={data.scan_id || scanId} graph={data} scanId={scanId} />
        </ReactFlowProvider>
      )}
    </div>
  );
}

function ScopeToggle({
  scope,
  onChange,
}: {
  scope: ExplorationScope;
  onChange: (s: ExplorationScope) => void;
}) {
  const tr = useTr();
  const opts: { value: ExplorationScope; label: string }[] = [
    { value: "findings", label: tr("exploration.scope.findings", "Findings path") },
    { value: "all", label: tr("exploration.scope.all", "Everything") },
  ];
  return (
    <div className="inline-flex rounded-md border border-border bg-card p-0.5" role="radiogroup">
      {opts.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={scope === o.value}
          onClick={() => onChange(o.value)}
          className={cn(
            "rounded px-2.5 py-1 text-xs font-medium transition-colors",
            scope === o.value
              ? "bg-secondary text-foreground shadow-sm"
              : "text-muted-foreground hover:text-foreground",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

function StatsBar({ stats }: { stats?: ExplorationGraphStats }) {
  const tr = useTr();
  if (!stats) return null;
  const items: { key: keyof ExplorationGraphStats; label: string; color: string }[] = [
    { key: "agents", label: tr("exploration.stats.agents", "agents"), color: NODE_META.agent.color },
    { key: "endpoints", label: tr("exploration.stats.endpoints", "endpoints"), color: NODE_META.endpoint.color },
    { key: "parameters", label: tr("exploration.stats.parameters", "params"), color: NODE_META.parameter.color },
    { key: "attempts", label: tr("exploration.stats.attempts", "attempts"), color: NODE_META.attempt.color },
    { key: "proven", label: tr("exploration.stats.proven", "proven"), color: "#10b981" },
    { key: "findings", label: tr("exploration.stats.findings", "findings"), color: NODE_META.finding.color },
    { key: "verified", label: tr("exploration.stats.verified", "verified"), color: "#22c55e" },
    { key: "backend", label: tr("exploration.stats.backend", "backend"), color: NODE_META.backend.color },
  ];
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {items.map((i) => (
        <span
          key={i.key}
          className="inline-flex items-center gap-1.5 rounded-md border border-border bg-card px-2 py-1 text-[11px]"
        >
          <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: i.color }} />
          <span className="font-semibold tabular-nums">{Number(stats[i.key] ?? 0)}</span>
          <span className="text-muted-foreground">{i.label}</span>
        </span>
      ))}
    </div>
  );
}

function SeverityStrip({ nodes }: { nodes: ExplorationGraphNode[] }) {
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const n of nodes) if (n.type === "finding") c[normalizeSeverity(n.severity)] = (c[normalizeSeverity(n.severity)] ?? 0) + 1;
    return c;
  }, [nodes]);
  const order = ["critical", "high", "medium", "low", "info"] as const;
  const total = order.reduce((a, k) => a + (counts[k] ?? 0), 0);
  if (total === 0) return null;
  return (
    <div
      className="flex h-7 items-center gap-2 rounded-md border border-border bg-card px-2"
      title={order.map((k) => `${counts[k] ?? 0} ${k}`).join(" · ")}
    >
      <div className="flex h-1.5 w-28 overflow-hidden rounded-full bg-muted">
        {order.map((k) =>
          counts[k] ? (
            <span
              key={k}
              style={{
                width: `${(counts[k] / total) * 100}%`,
                background: `linear-gradient(90deg, ${SEVERITY_COLORS[k]}, ${SEVERITY_COLORS[k]}bb)`,
              }}
            />
          ) : null,
        )}
      </div>
      <div className="flex items-center gap-1.5 text-[10px] tabular-nums">
        {order.map((k) =>
          counts[k] ? (
            <span key={k} className="inline-flex items-center gap-0.5 font-semibold" style={{ color: SEVERITY_COLORS[k] }}>
              {counts[k]}
              <span className="font-normal uppercase opacity-80">{k[0]}</span>
            </span>
          ) : null,
        )}
      </div>
    </div>
  );
}

/** Groups positioned nodes into left-to-right layers (dagre ranks). */
function layerIndex(positioned: PositionedNode[]): Map<string, number> {
  const xs = [...new Set(positioned.map((p) => Math.round(p.x + p.width / 2)))].sort((a, b) => a - b);
  const buckets: number[] = [];
  for (const x of xs) if (buckets.length === 0 || x - buckets[buckets.length - 1] > 60) buckets.push(x);
  const out = new Map<string, number>();
  for (const p of positioned) {
    const cx = p.x + p.width / 2;
    let idx = 0;
    for (let i = 0; i < buckets.length; i++) if (cx >= buckets[i] - 30) idx = i;
    out.set(p.node.id, idx);
  }
  return out;
}

/** Column captions ("1 Target → 2 Agent → …") floating above the graph. */
function StageLabels({ positioned }: { positioned: PositionedNode[] }) {
  const labels = useMemo(() => {
    if (positioned.length === 0) return [];
    const minY = Math.min(...positioned.map((p) => p.y));
    const byType = new Map<string, number[]>();
    for (const p of positioned) {
      const list = byType.get(p.node.type) ?? [];
      list.push(p.x + p.width / 2);
      byType.set(p.node.type, list);
    }
    const cols = [...byType.entries()]
      .map(([type, xs]) => ({ type, x: xs.sort((a, b) => a - b)[Math.floor(xs.length / 2)] }))
      .sort((a, b) => a.x - b.x);
    const out: { type: string; x: number; y: number; step: number }[] = [];
    for (const c of cols) {
      if (out.length && c.x - out[out.length - 1].x < 150) continue;
      out.push({ ...c, y: minY - 44, step: out.length + 1 });
    }
    return out;
  }, [positioned]);
  return (
    <ViewportPortal>
      {labels.map((l, i) => {
        const m = nodeMeta(l.type);
        const Icon = m.icon;
        return (
          <div
            key={l.type}
            className="eg-pop pointer-events-none absolute flex items-center gap-1.5 whitespace-nowrap rounded-full border bg-card/80 py-0.5 pl-0.5 pr-2.5 text-[11px] font-semibold shadow-sm backdrop-blur"
            style={{
              transform: `translate(-50%, 0) translate(${l.x}px, ${l.y}px)`,
              borderColor: `${m.color}55`,
              color: m.color,
              animationDelay: `${i * 70}ms`,
            }}
          >
            <span
              className="flex h-5 w-5 items-center justify-center rounded-full text-[10px] text-white"
              style={{ background: `linear-gradient(135deg, ${m.color}, ${m.color}aa)` }}
            >
              {l.step}
            </span>
            <Icon className="h-3 w-3" aria-hidden />
            {m.label}
          </div>
        );
      })}
    </ViewportPortal>
  );
}

function haystack(n: ExplorationGraphNode): string {
  const parts = [n.id, n.label, n.subtitle ?? ""];
  const d = n.data && typeof n.data === "object" ? n.data : {};
  for (const v of Object.values(d)) {
    const s = Array.isArray(v) ? v.map(str).join(" ") : str(v);
    parts.push(s.length > 4000 ? s.slice(0, 4000) : s);
  }
  return parts.join("\n").toLowerCase();
}

function GraphCanvas({ graph, scanId }: { graph: ExplorationGraph; scanId: string }) {
  const tr = useTr();
  const { resolved } = useTheme();
  const rf = useReactFlow();

  const allNodes = useMemo(() => graph.nodes ?? [], [graph.nodes]);
  const allEdges = useMemo(() => graph.edges ?? [], [graph.edges]);
  const byId = useMemo(() => new Map(allNodes.map((n) => [n.id, n])), [allNodes]);
  const adjacency = useMemo(() => buildAdjacency(allEdges), [allEdges]);

  const [hidden, setHidden] = useState<Set<string>>(() => new Set());
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [hoverEdge, setHoverEdge] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const q = useDebounced(search.trim().toLowerCase(), 200);
  const [overrides, setOverrides] = useState<Record<string, { x: number; y: number }>>({});
  const [replay, setReplay] = useState<{ order: string[][]; step: number; playing: boolean } | null>(null);

  // Drop the selection if a refresh removed the node.
  useEffect(() => {
    if (selectedId && !byId.has(selectedId)) setSelectedId(null);
  }, [byId, selectedId]);

  const typeCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const n of allNodes) c[n.type] = (c[n.type] ?? 0) + 1;
    return c;
  }, [allNodes]);

  const findings = useMemo(
    () =>
      allNodes
        .filter((n) => n.type === "finding")
        .sort(
          (a, b) =>
            (SEV_RANK[normalizeSeverity(a.severity)] ?? 9) - (SEV_RANK[normalizeSeverity(b.severity)] ?? 9) ||
            a.label.localeCompare(b.label),
        ),
    [allNodes],
  );

  const filtered = useMemo(() => filterGraph(allNodes, allEdges, hidden), [allNodes, allEdges, hidden]);
  // "Isolate" lays out only the traced path, as a compact left-to-right chain.
  const [isolated, setIsolated] = useState<Set<string> | null>(null);
  const view = useMemo(() => {
    if (!isolated) return filtered;
    return {
      nodes: filtered.nodes.filter((n) => isolated.has(n.id)),
      edges: filtered.edges.filter((e) => isolated.has(e.source) && isolated.has(e.target)),
    };
  }, [filtered, isolated]);
  const positioned = useMemo(() => layoutGraph(view.nodes, view.edges, !!isolated), [view, isolated]);

  const layers = useMemo(() => layerIndex(positioned), [positioned]);

  // A new layout discards manual drags.
  useEffect(() => setOverrides({}), [positioned]);

  const traced = useMemo(() => {
    if (!selectedId) return null;
    const n = byId.get(selectedId);
    if (!n) return null;
    return traceSet(selectedId, n.type, adjacency, (id) => byId.get(id)?.type);
  }, [selectedId, byId, adjacency]);

  const searchIndex = useMemo(() => new Map(allNodes.map((n) => [n.id, haystack(n)])), [allNodes]);
  const matches = useMemo(() => {
    if (q.length < 2) return null;
    const s = new Set<string>();
    for (const [id, h] of searchIndex) if (h.includes(q)) s.add(id);
    return s;
  }, [q, searchIndex]);
  const visibleMatches = useMemo(
    () => (matches ? filtered.nodes.filter((n) => matches.has(n.id)).map((n) => n.id) : []),
    [matches, filtered.nodes],
  );

  // During a replay only the steps reached so far are lit.
  const revealed = useMemo(() => {
    if (!replay) return null;
    return new Set(replay.order.slice(0, replay.step + 1).flat());
  }, [replay]);
  const spotlight = useMemo(
    () => (replay?.playing ? new Set(replay.order[replay.step] ?? []) : null),
    [replay],
  );
  const lit = revealed ?? traced;

  const flowNodes: FlowNode[] = useMemo(
    () =>
      positioned.map((p) => ({
        id: p.node.id,
        type: p.node.type in nodeTypes ? p.node.type : "target",
        position: overrides[p.node.id] ?? { x: p.x, y: p.y },
        width: p.width,
        height: p.height,
        selected: p.node.id === selectedId,
        data: {
          node: p.node,
          traced: !!lit?.has(p.node.id),
          dim: (lit ? !lit.has(p.node.id) : false) || (matches ? !matches.has(p.node.id) : false),
          match: !!matches?.has(p.node.id),
          spotlight: !!spotlight?.has(p.node.id),
          delay: Math.min(900, (layers.get(p.node.id) ?? 0) * 80),
        },
      })),
    [positioned, overrides, selectedId, lit, matches, spotlight, layers],
  );

  const manyEdges = filtered.edges.length > 300;
  const flowEdges: FlowEdge[] = useMemo(
    () =>
      filtered.edges.map((e) => {
        const src = byId.get(e.source);
        const dst = byId.get(e.target);
        const from = src ? accentFor(src.type, src.severity) : edgeMeta(e.kind).color;
        const to = dst ? accentFor(dst.type, dst.severity) : edgeMeta(e.kind).color;
        const active = !!lit && lit.has(e.source) && lit.has(e.target);
        const dim = (!!lit && !active) || (!!matches && !(matches.has(e.source) || matches.has(e.target)));
        const hovered = hoverEdge === e.id;
        const particles = dim
          ? 0
          : active && e.kind !== "assigned"
            ? 2
            : !manyEdges && !lit && (e.kind === "proves" || e.kind === "injected")
              ? 1
              : 0;
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          type: "flow",
          zIndex: active || hovered ? 10 : 0,
          markerEnd: { type: MarkerType.ArrowClosed, color: to, width: 14, height: 14 },
          data: { from, to, kind: e.kind, bridged: e.bridged, active, dim, hovered, particles },
        };
      }),
    [filtered.edges, byId, lit, matches, hoverEdge, manyEdges],
  );

  const onNodesChange = useCallback((changes: NodeChange<FlowNode>[]) => {
    const moves = changes.filter(
      (c): c is Extract<NodeChange<FlowNode>, { type: "position" }> => c.type === "position" && !!c.position,
    );
    if (moves.length === 0) return;
    setOverrides((prev) => {
      const next = { ...prev };
      for (const m of moves) if (m.position) next[m.id] = m.position;
      return next;
    });
  }, []);

  const focusNodes = useCallback(
    (ids: string[]) => {
      if (ids.length === 0) return;
      // Wait a frame so React Flow has the (possibly new) nodes measured.
      requestAnimationFrame(() =>
        rf.fitView({ nodes: ids.map((id) => ({ id })), duration: 500, padding: 0.25, maxZoom: 1.2 }),
      );
    },
    [rf],
  );

  const selectAndTrace = useCallback(
    (id: string) => {
      setReplay(null);
      setIsolated(null);
      setSelectedId(id);
      const n = byId.get(id);
      if (!n) return;
      const set = traceSet(id, n.type, adjacency, (x) => byId.get(x)?.type);
      const visible = new Set(filtered.nodes.map((v) => v.id));
      focusNodes([...set].filter((x) => visible.has(x)));
    },
    [byId, adjacency, filtered.nodes, focusNodes],
  );

  const startReplay = useCallback(
    (id: string) => {
      const n = byId.get(id);
      if (!n) return;
      const visible = new Set(filtered.nodes.map((v) => v.id));
      const set = new Set(
        [...traceSet(id, n.type, adjacency, (x) => byId.get(x)?.type)].filter((x) => visible.has(x)),
      );
      if (set.size === 0) return;
      // Step order = longest-path depth inside the traced subgraph.
      const parents = new Map<string, string[]>();
      for (const e of filtered.edges) {
        if (!set.has(e.source) || !set.has(e.target) || e.source === e.target) continue;
        (parents.get(e.target) ?? parents.set(e.target, []).get(e.target)!).push(e.source);
      }
      const depth = new Map<string, number>();
      const visiting = new Set<string>();
      const depthOf = (x: string): number => {
        const known = depth.get(x);
        if (known !== undefined) return known;
        if (visiting.has(x)) return 0; // cycle guard
        visiting.add(x);
        const d = Math.max(-1, ...(parents.get(x) ?? []).map(depthOf)) + 1;
        visiting.delete(x);
        depth.set(x, d);
        return d;
      };
      const groups = new Map<number, string[]>();
      for (const x of set) {
        const d = depthOf(x);
        (groups.get(d) ?? groups.set(d, []).get(d)!).push(x);
      }
      const order = [...groups.entries()].sort((a, b) => a[0] - b[0]).map(([, ids]) => ids);
      setSelectedId(id);
      setIsolated(set);
      setReplay({ order, step: 0, playing: true });
    },
    [byId, adjacency, filtered],
  );

  // Advance the replay one step at a time, with the camera following.
  useEffect(() => {
    if (!replay) return;
    const shown = replay.order.slice(0, replay.step + 1).flat();
    const focus = replay.playing
      ? replay.order.slice(Math.max(0, replay.step - 1), replay.step + 1).flat()
      : shown;
    // Give React Flow a moment to place a freshly isolated layout.
    const cam = window.setTimeout(
      () =>
        rf.fitView({
          nodes: focus.map((id) => ({ id })),
          duration: 700,
          padding: replay.playing ? 0.45 : 0.2,
          maxZoom: 1.05,
        }),
      60,
    );
    if (!replay.playing) return () => window.clearTimeout(cam);
    const t = window.setTimeout(
      () =>
        setReplay((r) =>
          !r ? r : r.step + 1 >= r.order.length ? { ...r, playing: false } : { ...r, step: r.step + 1 },
        ),
      1300,
    );
    return () => {
      window.clearTimeout(cam);
      window.clearTimeout(t);
    };
  }, [replay, rf]);

  const replayNode =
    replay && replay.playing ? byId.get((replay.order[replay.step] ?? [])[0] ?? "") : undefined;

  // Refit when the scope (and so the node set) changes.
  const firstScope = useRef(graph.scope);
  useEffect(() => {
    if (firstScope.current === graph.scope) return;
    firstScope.current = graph.scope;
    requestAnimationFrame(() => rf.fitView({ duration: 400, padding: 0.1 }));
  }, [graph.scope, rf]);

  const selected = selectedId ? byId.get(selectedId) : undefined;
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

  const toggleType = (type: string) =>
    setHidden((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });

  const selectedFinding = selected?.type === "finding" ? selected.id : "";

  return (
    <div className="space-y-2">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-64">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") focusNodes(visibleMatches);
              if (e.key === "Escape") setSearch("");
            }}
            placeholder={tr("exploration.search", "Search path, param, payload…")}
            className="h-8 pl-8 pr-16 text-xs"
            maxLength={200}
          />
          {matches && (
            <span className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] tabular-nums text-muted-foreground">
              {visibleMatches.length} {tr("exploration.matches", "hits")}
            </span>
          )}
        </div>

        {findings.length > 0 && (
          <Select value={selectedFinding} onValueChange={(v) => v && startReplay(v)}>
            <SelectTrigger className="h-8 w-full text-xs sm:w-72">
              <SelectValue placeholder={tr("exploration.traceFinding", "Replay how a finding was found…")} />
            </SelectTrigger>
            <SelectContent className="max-w-[min(90vw,28rem)]">
              {findings.map((f) => (
                <SelectItem key={f.id} value={f.id} className="text-xs">
                  <span className="flex min-w-0 items-center gap-2">
                    <span
                      className="h-2 w-2 shrink-0 rounded-full"
                      style={{ backgroundColor: accentFor("finding", f.severity) }}
                    />
                    <span className="truncate">{truncate(f.label, 70)}</span>
                    {f.verified && <BadgeCheck className="h-3 w-3 shrink-0 text-emerald-500" />}
                  </span>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}

        {selectedId && (
          <Button
            size="sm"
            variant="ghost"
            className="h-8 text-xs"
            onClick={() => {
              setSelectedId(null);
              setReplay(null);
              setIsolated(null);
            }}
          >
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
      <div className={cn("grid gap-3", selected && "lg:grid-cols-[minmax(0,1fr)_400px]")}>
        <div className="eg-canvas relative h-[70vh] min-h-[520px] overflow-hidden rounded-xl border border-border shadow-inner">
          <ReactFlow<FlowNode, FlowEdge>
            nodes={flowNodes}
            edges={flowEdges}
            nodeTypes={nodeTypes}
            edgeTypes={edgeTypes}
            onNodesChange={onNodesChange}
            onNodeClick={(_, n) => {
              // Inspecting a node keeps an isolated path on screen.
              setReplay(null);
              setSelectedId((cur) => (cur === n.id ? null : n.id));
            }}
            onPaneClick={() => {
              setReplay(null);
              setIsolated(null);
              setSelectedId(null);
            }}
            onEdgeMouseEnter={(_, e) => setHoverEdge(e.id)}
            onEdgeMouseLeave={() => setHoverEdge(null)}
            nodesConnectable={false}
            elementsSelectable={false}
            nodesDraggable
            onlyRenderVisibleElements={flowNodes.length > 250}
            colorMode={resolved}
            fitView
            fitViewOptions={{ padding: 0.15, minZoom: 0.4 }}
            minZoom={0.05}
            maxZoom={2}
          >
            <Background id="eg-dots" variant={BackgroundVariant.Dots} gap={18} size={1} color={resolved === "dark" ? "#ffffff1f" : "#0000001f"} />
            <Background id="eg-grid" variant={BackgroundVariant.Lines} gap={180} lineWidth={0.5} color={resolved === "dark" ? "#ffffff0d" : "#0000000a"} />
            <StageLabels positioned={positioned} />
            <Controls showInteractive={false} position="bottom-left" />
            <MiniMap
              pannable
              zoomable
              position="bottom-right"
              nodeColor={(n) => {
                const gn = (n.data as FlowNode["data"] | undefined)?.node;
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
              {selectedId &&
                (replay?.playing ? (
                  <Button size="sm" variant="secondary" className="h-7 text-xs" onClick={() => setReplay((r) => (r ? { ...r, playing: false, step: r.order.length - 1 } : r))}>
                    <Square className="h-3.5 w-3.5" />
                    {tr("exploration.stopReplay", "Skip")}
                  </Button>
                ) : (
                  <Button size="sm" className="h-7 text-xs" onClick={() => startReplay(selectedId)}>
                    {replay ? <RotateCcw className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
                    {replay ? tr("exploration.replayAgain", "Replay again") : tr("exploration.replay", "Replay path")}
                  </Button>
                ))}
              {traced && !replay?.playing && (
                <Button
                  size="sm"
                  variant="secondary"
                  className="h-7 text-xs"
                  onClick={() => {
                    setIsolated((cur) => {
                      if (cur) return null;
                      const visible = new Set(filtered.nodes.map((n) => n.id));
                      return new Set([...traced].filter((id) => visible.has(id)));
                    });
                    window.setTimeout(() => rf.fitView({ duration: 500, padding: 0.2 }), 60);
                  }}
                >
                  {isolated ? <Expand className="h-3.5 w-3.5" /> : <Shrink className="h-3.5 w-3.5" />}
                  {isolated ? tr("exploration.showAll", "Full graph") : tr("exploration.isolate", "Isolate path")}
                </Button>
              )}
              {traced && !replay?.playing && (
                <Button
                  size="sm"
                  variant="secondary"
                  className="h-7 text-xs"
                  onClick={() => focusNodes([...traced].filter((id) => filtered.nodes.some((n) => n.id === id)))}
                >
                  <Crosshair className="h-3.5 w-3.5" />
                  {tr("exploration.focusTrace", "Focus trace")}
                </Button>
              )}
              <Button
                size="sm"
                variant="secondary"
                className="h-7 text-xs"
                onClick={() => rf.fitView({ duration: 400, padding: 0.1 })}
              >
                <Maximize className="h-3.5 w-3.5" />
                {tr("exploration.fitView", "Fit")}
              </Button>
            </Panel>
            {replay?.playing && replayNode && (
              <Panel position="bottom-center" className="!mb-6">
                <ReplayCaption node={replayNode} step={replay.step} total={replay.order.length} />
              </Panel>
            )}
          </ReactFlow>
        </div>

        {selected && (
          <DetailPanel
            className="h-[70vh] min-h-[520px]"
            node={selected}
            scanId={scanId}
            upstream={neighbors.up}
            downstream={neighbors.down}
            onSelect={selectAndTrace}
            onClose={() => setSelectedId(null)}
          />
        )}
      </div>
      {filtered.nodes.length === 0 && (
        <p className="text-xs text-muted-foreground">
          {tr("exploration.allHidden", "All node types are hidden — re-enable some filters above.")}
        </p>
      )}
    </div>
  );
}

function ReplayCaption({ node, step, total }: { node: ExplorationGraphNode; step: number; total: number }) {
  const m = nodeMeta(node.type);
  const accent = accentFor(node.type, node.severity);
  const Icon = m.icon;
  return (
    <div
      key={node.id}
      className="eg-pop flex min-w-72 max-w-[min(80vw,34rem)] items-center gap-3 rounded-xl border bg-card/90 px-3 py-2 shadow-xl backdrop-blur"
      style={{ borderColor: `${accent}66`, boxShadow: `0 12px 40px -12px ${accent}88` }}
      role="status"
      aria-live="polite"
    >
      <span
        className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-white"
        style={{ background: `linear-gradient(135deg, ${accent}, ${accent}aa)` }}
      >
        <Icon className="h-4 w-4" aria-hidden />
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-[10px] font-semibold uppercase tracking-[0.14em]" style={{ color: accent }}>
          Step {step + 1} of {total} · {m.label}
        </p>
        <p className="truncate font-mono text-xs text-foreground">{truncate(node.label, 90)}</p>
        <div className="mt-1 h-1 overflow-hidden rounded-full bg-muted">
          <div
            className="h-full rounded-full transition-[width] duration-700"
            style={{ width: `${((step + 1) / total) * 100}%`, background: `linear-gradient(90deg, #8b5cf6, ${accent})` }}
          />
        </div>
      </div>
    </div>
  );
}
