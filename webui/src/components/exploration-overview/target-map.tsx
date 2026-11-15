import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type NodeChange,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Eye, EyeOff } from "lucide-react";
import type { OverviewLink, OverviewTarget } from "@/types/api";
import { cn } from "@/lib/utils";
import { useTheme } from "@/store/theme";
import { layoutTargets } from "./layout";
import { linkEdgeTypes, type LinkFlowEdge } from "./link-edge";
import { LinksPanel, aggregateLinks, type SharedItem } from "./links-panel";
import { TargetPanel } from "./target-panel";
import { TARGET_NODE_H, TARGET_NODE_W, targetNodeTypes, type TargetFlowNode } from "./target-node";
import { LINK_KINDS, LINK_META, SEV_ORDER, hostLabel, topSeverityColor, useTr } from "./shared";
import { SEVERITY_COLORS } from "@/components/exploration-graph/meta";

// Portfolio map: one card per target on concentric severity rings, edges for
// everything two targets share (backend tech, vuln class, auth, infra).

export interface TargetMapProps {
  targets: OverviewTarget[];
  links: OverviewLink[];
  compare: Set<string>;
  compareFull: boolean;
  onToggleCompare: (key: string) => void;
  onOpenScan: (scanId: string) => void;
  className?: string;
}

export function TargetMap(props: TargetMapProps) {
  return (
    <ReactFlowProvider>
      <TargetMapInner {...props} />
    </ReactFlowProvider>
  );
}

function TargetMapInner({
  targets,
  links,
  compare,
  compareFull,
  onToggleCompare,
  onOpenScan,
  className,
}: TargetMapProps) {
  const tr = useTr();
  const { resolved } = useTheme();
  const { fitView, setCenter, getNode } = useReactFlow<TargetFlowNode, LinkFlowEdge>();
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [hiddenKinds, setHiddenKinds] = useState<Set<string>>(() => new Set());
  const [hoverEdge, setHoverEdge] = useState<string | null>(null);
  const [highlight, setHighlight] = useState<SharedItem | null>(null);

  const targetsByKey = useMemo(() => new Map(targets.map((t) => [t.key, t])), [targets]);

  // Only links whose two endpoints are on the map.
  const validLinks = useMemo(
    () => links.filter((l) => l.source !== l.target && targetsByKey.has(l.source) && targetsByKey.has(l.target)),
    [links, targetsByKey],
  );
  const visibleLinks = useMemo(() => validLinks.filter((l) => !hiddenKinds.has(l.kind)), [validLinks, hiddenKinds]);
  const kindCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const l of validLinks) m.set(l.kind, (m.get(l.kind) ?? 0) + 1);
    return m;
  }, [validLinks]);
  const shared = useMemo(() => aggregateLinks(visibleLinks), [visibleLinks]);

  // Drop a selection / highlight that no longer exists after a refetch.
  useEffect(() => {
    if (selectedKey && !targetsByKey.has(selectedKey)) setSelectedKey(null);
  }, [selectedKey, targetsByKey]);
  useEffect(() => {
    if (highlight && !shared.some((s) => s.id === highlight.id)) setHighlight(null);
  }, [highlight, shared]);

  // Focus sets: a shared-item highlight wins over the node selection.
  const focus = useMemo(() => {
    if (highlight) {
      const ids = new Set(highlight.linkIds);
      return { targets: new Set(highlight.targets), links: ids };
    }
    if (selectedKey) {
      const ts = new Set([selectedKey]);
      const ls = new Set<string>();
      for (const l of visibleLinks) {
        if (l.source === selectedKey || l.target === selectedKey) {
          ts.add(l.source);
          ts.add(l.target);
          ls.add(l.id);
        }
      }
      return { targets: ts, links: ls };
    }
    return null;
  }, [highlight, selectedKey, visibleLinks]);

  const { positions, kind: layoutKind } = useMemo(() => layoutTargets(targets), [targets]);

  // Positions the user dragged nodes to (cleared when the target set changes).
  const [overrides, setOverrides] = useState<Record<string, { x: number; y: number }>>({});

  const nodes = useMemo<TargetFlowNode[]>(() => {
    const order = [...targets].sort((a, b) => {
      const pa = positions.get(a.key);
      const pb = positions.get(b.key);
      return Math.hypot(pa?.x ?? 0, pa?.y ?? 0) - Math.hypot(pb?.x ?? 0, pb?.y ?? 0);
    });
    const delayOf = new Map(order.map((t, i) => [t.key, Math.min(i * 25, 900)]));
    return targets.map((t) => ({
      id: t.key,
      type: "target" as const,
      position: overrides[t.key] ?? positions.get(t.key) ?? { x: 0, y: 0 },
      width: TARGET_NODE_W,
      height: TARGET_NODE_H,
      selected: t.key === selectedKey,
      ariaLabel: `${hostLabel(t)}: ${t.findings} findings${t.top_severity ? `, top severity ${t.top_severity}` : ""}`,
      data: {
        target: t,
        dim: focus ? !focus.targets.has(t.key) : false,
        highlight: focus ? focus.targets.has(t.key) && !!highlight : false,
        compared: compare.has(t.key),
        compareFull,
        delay: delayOf.get(t.key) ?? 0,
        onToggleCompare,
      },
    }));
  }, [targets, positions, overrides, selectedKey, focus, highlight, compare, compareFull, onToggleCompare]);

  const onNodesChange = useCallback((changes: NodeChange<TargetFlowNode>[]) => {
    const moves = changes.filter(
      (c): c is Extract<NodeChange<TargetFlowNode>, { type: "position" }> => c.type === "position" && !!c.position,
    );
    if (moves.length === 0) return;
    setOverrides((prev) => {
      const next = { ...prev };
      for (const m of moves) if (m.position) next[m.id] = m.position;
      return next;
    });
  }, []);

  const edges = useMemo<LinkFlowEdge[]>(() => {
    // Fan out parallel links of the same (unordered) pair.
    const pairs = new Map<string, OverviewLink[]>();
    for (const l of visibleLinks) {
      const k = l.source < l.target ? `${l.source}\u0000${l.target}` : `${l.target}\u0000${l.source}`;
      const arr = pairs.get(k);
      if (arr) arr.push(l);
      else pairs.set(k, [l]);
    }
    const out: LinkFlowEdge[] = [];
    for (const arr of pairs.values()) {
      arr.forEach((l, i) => {
        const centred = i - (arr.length - 1) / 2;
        const lane = l.source < l.target ? centred : -centred;
        out.push({
          id: l.id,
          source: l.source,
          target: l.target,
          type: "link",
          ariaLabel: `${LINK_META[l.kind]?.label ?? l.kind}: ${l.label}`,
          data: {
            link: l,
            lane,
            dim: focus ? !focus.links.has(l.id) : false,
            hovered: hoverEdge === l.id,
            highlight: focus ? focus.links.has(l.id) : false,
          },
        });
      });
    }
    return out;
  }, [visibleLinks, focus, hoverEdge]);

  // Re-fit when the set of targets changes (filters), not on every refetch.
  const signature = useMemo(() => targets.map((t) => t.key).sort().join("|"), [targets]);
  const firstFit = useRef(true);
  useEffect(() => {
    if (firstFit.current) {
      firstFit.current = false;
      return;
    }
    setOverrides({});
    const id = window.setTimeout(() => void fitView({ padding: 0.2, duration: 300 }), 30);
    return () => window.clearTimeout(id);
  }, [signature, fitView]);

  const selectTarget = useCallback(
    (key: string | null) => {
      setHighlight(null);
      setSelectedKey((cur) => (cur === key ? null : key));
      if (key) {
        const n = getNode(key);
        if (n) {
          const w = n.width ?? TARGET_NODE_W;
          const h = n.height ?? TARGET_NODE_H;
          void setCenter(n.position.x + w / 2, n.position.y + h / 2, { zoom: 1, duration: 300 });
        }
      }
    },
    [getNode, setCenter],
  );

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    const el = (e.target as HTMLElement).closest?.(".react-flow__node");
    const id = el?.getAttribute("data-id");
    if (!id || !targetsByKey.has(id)) return;
    e.preventDefault();
    if (e.shiftKey || e.ctrlKey || e.metaKey) onToggleCompare(id);
    else {
      setHighlight(null);
      setSelectedKey((cur) => (cur === id ? null : id));
    }
  };

  const toggleKind = (k: string) =>
    setHiddenKinds((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });

  const selected = selectedKey ? targetsByKey.get(selectedKey) : undefined;

  return (
    <div className={cn("flex flex-col gap-3 lg:flex-row", className)}>
      <div
        className="eg-canvas relative h-[70vh] min-h-[420px] flex-1 overflow-hidden rounded-md border border-border"
        role="region"
        aria-label={tr("exploration.overview.mapLabel", "Target map")}
      >
        <ReactFlow<TargetFlowNode, LinkFlowEdge>
          nodes={nodes}
          edges={edges}
          nodeTypes={targetNodeTypes}
          edgeTypes={linkEdgeTypes}
          onNodesChange={onNodesChange}
          onNodeClick={(e, n) => {
            if (e.shiftKey || e.ctrlKey || e.metaKey) {
              onToggleCompare(n.id);
              return;
            }
            setHighlight(null);
            setSelectedKey((cur) => (cur === n.id ? null : n.id));
          }}
          onPaneClick={() => {
            setSelectedKey(null);
            setHighlight(null);
          }}
          onEdgeMouseEnter={(_, e) => setHoverEdge(e.id)}
          onEdgeMouseLeave={() => setHoverEdge(null)}
          onKeyDown={onKeyDown}
          nodesConnectable={false}
          elementsSelectable={false}
          nodesDraggable
          onlyRenderVisibleElements={nodes.length > 150}
          colorMode={resolved}
          fitView
          fitViewOptions={{ padding: 0.2, maxZoom: 1.1 }}
          minZoom={0.05}
          maxZoom={2}
          proOptions={{ hideAttribution: true }}
        >
          <Background
            id="eo-dots"
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
              const t = (n.data as TargetFlowNode["data"] | undefined)?.target;
              return t ? topSeverityColor(t.top_severity) : "#71717a";
            }}
            nodeStrokeWidth={0}
            maskColor={resolved === "dark" ? "rgba(0,0,0,0.6)" : "rgba(255,255,255,0.6)"}
            ariaLabel={tr("exploration.overview.minimap", "Target map overview")}
          />
        </ReactFlow>

        <MapLegend
          className="absolute left-3 top-3 z-10"
          hidden={hiddenKinds}
          counts={kindCounts}
          onToggle={toggleKind}
          rings={layoutKind === "rings"}
        />
      </div>

      <aside className="flex w-full shrink-0 flex-col gap-3 lg:h-[70vh] lg:w-80 lg:overflow-y-auto">
        {selected && (
          <TargetPanel
            target={selected}
            links={visibleLinks}
            targetsByKey={targetsByKey}
            compared={compare.has(selected.key)}
            compareFull={compareFull}
            onClose={() => setSelectedKey(null)}
            onOpenScan={onOpenScan}
            onToggleCompare={onToggleCompare}
            onSelectTarget={(k) => {
              if (k !== selectedKey) selectTarget(k);
            }}
          />
        )}
        <LinksPanel
          items={shared}
          activeId={highlight?.id ?? null}
          onSelect={(it) => {
            setHighlight(it);
            if (it) {
              setSelectedKey(null);
              const ids = it.targets.filter((k) => targetsByKey.has(k)).map((id) => ({ id }));
              if (ids.length) void fitView({ nodes: ids, padding: 0.35, duration: 300, maxZoom: 1.1 });
            }
          }}
        />
      </aside>
    </div>
  );
}

function MapLegend({
  hidden,
  counts,
  onToggle,
  rings,
  className,
}: {
  hidden: Set<string>;
  counts: Map<string, number>;
  onToggle: (kind: string) => void;
  rings: boolean;
  className?: string;
}) {
  const tr = useTr();
  return (
    <div
      className={cn(
        "w-52 space-y-2 rounded-md border border-border bg-card/95 px-2.5 py-2 text-card-foreground shadow-sm backdrop-blur",
        className,
      )}
    >
      <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
        {tr("exploration.overview.legendLinks", "Links")}
      </p>
      <ul className="space-y-0.5" role="group" aria-label={tr("exploration.overview.toggleLinks", "Toggle link kinds")}>
        {LINK_KINDS.map((k) => {
          const m = LINK_META[k];
          const on = !hidden.has(k);
          const n = counts.get(k) ?? 0;
          return (
            <li key={k}>
              <button
                type="button"
                aria-pressed={on}
                onClick={() => onToggle(k)}
                title={m.description}
                className={cn(
                  "flex w-full items-center gap-2 rounded px-1 py-0.5 text-left text-[11px] transition-opacity",
                  "hover:bg-accent/60 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
                  !on && "opacity-50",
                )}
              >
                <span
                  className="h-0.5 w-4 shrink-0 rounded"
                  style={{ backgroundColor: m.color }}
                  aria-hidden
                />
                <span className="flex-1 truncate">{m.label}</span>
                <span className="tabular-nums text-muted-foreground">{n}</span>
                {on ? (
                  <Eye className="h-3 w-3 text-muted-foreground" aria-hidden />
                ) : (
                  <EyeOff className="h-3 w-3 text-muted-foreground" aria-hidden />
                )}
              </button>
            </li>
          );
        })}
      </ul>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 border-t border-border pt-1.5 text-[10px] text-muted-foreground">
        {SEV_ORDER.map((s) => (
          <span key={s} className="inline-flex items-center gap-1">
            <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: SEVERITY_COLORS[s] }} aria-hidden />
            {s}
          </span>
        ))}
      </div>
      <p className="text-[10px] leading-snug text-muted-foreground">
        {rings
          ? tr("exploration.overview.ringsHint", "Most severe targets in the centre. Shift/Ctrl-click to select for compare.")
          : tr("exploration.overview.gridHint", "Grid layout (many targets), most severe first. Shift/Ctrl-click to select for compare.")}
      </p>
    </div>
  );
}
