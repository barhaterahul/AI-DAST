import { memo, type CSSProperties } from "react";
import {
  BaseEdge,
  EdgeLabelRenderer,
  Handle,
  Position,
  type Edge,
  type EdgeProps,
  type EdgeTypes,
  type Node,
  type NodeProps,
  type NodeTypes,
} from "@xyflow/react";
import { AlertTriangle, ChevronDown, ChevronRight, ExternalLink, Search } from "lucide-react";
import type { CombinedGroup, SeverityCounts } from "@/types/api";
import { ScanStatusPill } from "@/components/scan-status-pill";
import { cn } from "@/lib/utils";
import { LANE_HEADER_H, LANE_STAGE_H, linkLabel, type LaneStage } from "./lanes";
import { NODE_META, NODE_TYPES, SEVERITY_COLORS, nodeMeta, oneLine, severityColor, truncate } from "./meta";

// Lane background node, collapsed-lane summary node and the dashed cross-lane
// link edge of the combined Exploration Graph. All scan-derived strings are
// rendered as plain React text (untrusted).

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const NONE_ACCENT = "#64748b";

export function laneAccent(g: CombinedGroup): string {
  if (g.error) return "#f59e0b";
  return g.top_severity ? severityColor(g.top_severity) : NONE_ACCENT;
}

export interface LaneLabels {
  collapse: string;
  expand: string;
  openScan: string;
  endpoints: string;
  attempts: string;
  findings: string;
  truncated: string;
  emptyLane: string;
  laneError: string;
  hits: string;
  nodes: string;
}

export type LaneNodeData = {
  group: CombinedGroup;
  title: string;
  collapsed: boolean;
  stages: LaneStage[];
  /** Visible nodes in the lane (0 shows the empty notice). */
  visible: number;
  /** Search hits inside this lane (null when no search is active). */
  hits: number | null;
  dim: boolean;
  labels: LaneLabels;
  onToggle: (groupId: string) => void;
  onOpenScan?: (scanId: string) => void;
  [key: string]: unknown;
};

export type LaneFlowNode = Node<LaneNodeData, "lane">;

function stop(e: { stopPropagation: () => void }) {
  e.stopPropagation();
}

export function SeverityMiniBar({ counts, className }: { counts?: SeverityCounts; className?: string }) {
  const c = counts ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const total = SEV_ORDER.reduce((a, k) => a + (Number(c[k]) || 0), 0);
  const title = SEV_ORDER.map((k) => `${Number(c[k]) || 0} ${k}`).join(" · ");
  return (
    <div className={cn("flex items-center gap-1.5", className)} title={title} aria-label={title}>
      <div className="flex h-1.5 w-20 overflow-hidden rounded-full bg-muted">
        {total > 0 &&
          SEV_ORDER.map((k) =>
            c[k] ? (
              <span
                key={k}
                style={{
                  width: `${(c[k] / total) * 100}%`,
                  background: `linear-gradient(90deg, ${SEVERITY_COLORS[k]}, ${SEVERITY_COLORS[k]}bb)`,
                }}
              />
            ) : null,
          )}
      </div>
      <div className="flex items-center gap-1 text-[10px] tabular-nums">
        {SEV_ORDER.map((k) =>
          c[k] ? (
            <span key={k} className="inline-flex items-center font-semibold" style={{ color: SEVERITY_COLORS[k] }}>
              {c[k]}
              <span className="font-normal uppercase opacity-80">{k[0]}</span>
            </span>
          ) : null,
        )}
      </div>
    </div>
  );
}

function Stat({ value, label, color }: { value: number; label: string; color: string }) {
  return (
    <span className="inline-flex items-center gap-1 text-[11px]">
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} aria-hidden />
      <span className="font-semibold tabular-nums">{Number(value) || 0}</span>
      <span className="text-muted-foreground">{label}</span>
    </span>
  );
}

const LaneNodeImpl = memo(function LaneNodeImpl({ data, width, height }: NodeProps<LaneFlowNode>) {
  const { group: g, labels: L, collapsed } = data;
  const accent = laneAccent(g);
  const stats = g.stats ?? ({} as CombinedGroup["stats"]);
  return (
    <div
      className={cn(
        "relative h-full w-full rounded-2xl border bg-card/40 shadow-sm backdrop-blur-[2px] transition-opacity duration-300",
        data.dim && "opacity-60",
      )}
      style={{ width, height, borderColor: `${accent}55`, "--eg-accent": accent } as CSSProperties}
      role="group"
      aria-label={data.title}
    >
      {/* soft accent wash */}
      <div
        className="pointer-events-none absolute inset-0 rounded-2xl"
        style={{ background: `linear-gradient(180deg, ${accent}14 0%, transparent ${LANE_HEADER_H * 2}px)` }}
        aria-hidden
      />
      {/* header */}
      <div
        className="relative flex items-center gap-3 rounded-t-2xl border-b px-4"
        style={{ height: LANE_HEADER_H, borderColor: `${accent}33`, boxShadow: `inset 4px 0 0 ${accent}` }}
      >
        <button
          type="button"
          className="nodrag nopan flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-border bg-card text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-40"
          onClick={(e) => {
            stop(e);
            data.onToggle(g.id);
          }}
          onDoubleClick={stop}
          disabled={!!g.error}
          aria-expanded={!collapsed}
          aria-label={`${collapsed ? L.expand : L.collapse}: ${data.title}`}
          title={collapsed ? L.expand : L.collapse}
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
        </button>
        <div className="min-w-0 flex-1">
          <div className="flex min-w-0 items-center gap-2">
            <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ backgroundColor: accent, boxShadow: `0 0 8px ${accent}` }} aria-hidden />
            <span className="truncate font-mono text-sm font-semibold text-foreground" title={g.target || data.title}>
              {truncate(data.title, 80)}
            </span>
            {g.status && <ScanStatusPill status={g.status} className="shrink-0 !px-1.5 !text-[10px]" />}
            {g.truncated && (
              <span className="inline-flex shrink-0 items-center gap-1 rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-px text-[10px] text-amber-700 dark:text-amber-400">
                <AlertTriangle className="h-3 w-3" aria-hidden />
                {L.truncated}
              </span>
            )}
            {data.hits !== null && (
              <span
                className={cn(
                  "inline-flex shrink-0 items-center gap-1 rounded border px-1.5 py-px text-[10px] tabular-nums",
                  data.hits > 0
                    ? "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300"
                    : "border-border text-muted-foreground",
                )}
              >
                <Search className="h-3 w-3" aria-hidden />
                {data.hits} {L.hits}
              </span>
            )}
          </div>
          {!g.error && (
            <div className="mt-1 flex min-w-0 flex-wrap items-center gap-x-3 gap-y-0.5">
              <Stat value={stats.endpoints} label={L.endpoints} color={NODE_META.endpoint.color} />
              <Stat value={stats.attempts} label={L.attempts} color={NODE_META.attempt.color} />
              <Stat value={stats.findings} label={L.findings} color={NODE_META.finding.color} />
              <SeverityMiniBar counts={g.severity} />
            </div>
          )}
        </div>
        {data.onOpenScan && g.scan_id && !g.error && (
          <button
            type="button"
            className="nodrag nopan inline-flex h-7 shrink-0 items-center gap-1.5 rounded-md border border-border bg-card px-2 text-[11px] font-medium text-foreground hover:bg-accent"
            onClick={(e) => {
              stop(e);
              data.onOpenScan?.(g.scan_id);
            }}
            onDoubleClick={stop}
            aria-label={`${L.openScan}: ${data.title}`}
          >
            <ExternalLink className="h-3.5 w-3.5" aria-hidden />
            <span className="hidden sm:inline">{L.openScan}</span>
          </button>
        )}
      </div>

      {/* body */}
      {g.error ? (
        <div className="relative flex items-start gap-2 px-4 py-3 text-xs text-amber-700 dark:text-amber-400" role="alert">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
          <div className="min-w-0">
            <p className="font-medium">{L.laneError}</p>
            <p className="mt-0.5 break-words text-muted-foreground">{truncate(oneLine(g.error, 300), 300)}</p>
          </div>
        </div>
      ) : !collapsed && data.visible === 0 ? (
        <p className="relative px-4 py-4 text-xs text-muted-foreground">{L.emptyLane}</p>
      ) : !collapsed ? (
        <div className="pointer-events-none absolute inset-x-0" style={{ top: LANE_HEADER_H + 8, height: LANE_STAGE_H - 8 }}>
          {data.stages.map((s) => {
            const m = nodeMeta(s.type);
            const Icon = m.icon;
            return (
              <div
                key={s.type}
                className="absolute flex items-center gap-1.5 whitespace-nowrap rounded-full border bg-card/80 py-0.5 pl-0.5 pr-2.5 text-[11px] font-semibold shadow-sm"
                style={{ transform: `translate(-50%, 0) translateX(${s.x}px)`, borderColor: `${m.color}55`, color: m.color }}
              >
                <span
                  className="flex h-5 w-5 items-center justify-center rounded-full text-[10px] text-white"
                  style={{ background: `linear-gradient(135deg, ${m.color}, ${m.color}aa)` }}
                >
                  {s.step}
                </span>
                <Icon className="h-3 w-3" aria-hidden />
                {m.label}
              </div>
            );
          })}
        </div>
      ) : null}

      {/* cross-lane link anchors (right edge of the header) */}
      <Handle
        id="link-out"
        type="source"
        position={Position.Right}
        isConnectable={false}
        className="!h-2 !w-2 !min-h-0 !min-w-0 !border-2 !border-background"
        style={{ top: LANE_HEADER_H / 2, backgroundColor: accent }}
      />
      <Handle
        id="link-in"
        type="target"
        position={Position.Right}
        isConnectable={false}
        className="!h-2 !w-2 !min-h-0 !min-w-0 !border-2 !border-background !opacity-0"
        style={{ top: LANE_HEADER_H / 2 }}
      />
    </div>
  );
});

export type SummaryNodeData = {
  group: CombinedGroup;
  counts: Record<string, number>;
  total: number;
  hits: number | null;
  labels: LaneLabels;
  onToggle: (groupId: string) => void;
  [key: string]: unknown;
};

export type SummaryFlowNode = Node<SummaryNodeData, "laneSummary">;

const SummaryNodeImpl = memo(function SummaryNodeImpl({ data, width, height }: NodeProps<SummaryFlowNode>) {
  const accent = laneAccent(data.group);
  const types = NODE_TYPES.filter((t) => data.counts[t]);
  return (
    <button
      type="button"
      className={cn(
        "nodrag eg-pop group relative flex h-full w-full items-center gap-3 overflow-hidden rounded-xl border bg-card/85 px-3 text-left shadow-sm backdrop-blur-sm",
        "transition-[transform,box-shadow] duration-300 hover:-translate-y-0.5 hover:shadow-lg",
        data.hits ? "ring-2 ring-sky-400 ring-offset-2 ring-offset-background" : "",
      )}
      style={{ width, height, borderColor: `${accent}55` }}
      onClick={(e) => {
        e.stopPropagation();
        data.onToggle(data.group.id);
      }}
      aria-label={`${data.labels.expand}: ${data.total} ${data.labels.nodes}`}
    >
      <div
        className="pointer-events-none absolute inset-0"
        style={{ background: `linear-gradient(120deg, ${accent}22 0%, transparent 60%)` }}
        aria-hidden
      />
      <span className="relative text-xs font-semibold tabular-nums text-foreground">
        {data.total} <span className="font-normal text-muted-foreground">{data.labels.nodes}</span>
      </span>
      <span className="relative flex min-w-0 flex-1 flex-wrap items-center gap-1 overflow-hidden" style={{ maxHeight: 44 }}>
        {types.map((t) => {
          const m = NODE_META[t];
          const Icon = m.icon;
          return (
            <span
              key={t}
              className="inline-flex items-center gap-1 rounded border px-1 py-px text-[10px]"
              style={{ borderColor: `${m.color}44`, color: m.color }}
              title={m.label}
            >
              <Icon className="h-2.5 w-2.5" aria-hidden />
              <span className="tabular-nums">{data.counts[t]}</span>
            </span>
          );
        })}
      </span>
      {data.hits !== null && data.hits > 0 && (
        <span className="relative shrink-0 text-[10px] tabular-nums text-sky-700 dark:text-sky-300">
          {data.hits} {data.labels.hits}
        </span>
      )}
      <span className="relative inline-flex shrink-0 items-center gap-1 text-[11px] font-medium text-muted-foreground group-hover:text-foreground">
        <ChevronDown className="h-3.5 w-3.5" aria-hidden />
        {data.labels.expand}
      </span>
    </button>
  );
});

export const laneNodeTypes: NodeTypes = {
  lane: LaneNodeImpl,
  laneSummary: SummaryNodeImpl,
};

// ---- cross-lane link edge ---------------------------------------------------

export type LinkEdgeData = {
  kind: string;
  label: string;
  weight: number;
  evidence: string[];
  color: string;
  /** Extra outward bow so parallel links between the same lanes separate. */
  offset: number;
  hovered: boolean;
  dim: boolean;
  showLabel: boolean;
  [key: string]: unknown;
};

export type LinkFlowEdge = Edge<LinkEdgeData, "laneLink">;

const LinkEdgeImpl = memo(function LinkEdgeImpl({ id, sourceX, sourceY, targetX, targetY, data }: EdgeProps<LinkFlowEdge>) {
  if (!data) return null;
  const dy = Math.abs(targetY - sourceY);
  const bow = 56 + Math.min(260, dy * 0.22) + data.offset;
  const c1x = sourceX + bow;
  const c2x = targetX + bow;
  const path = `M ${sourceX},${sourceY} C ${c1x},${sourceY} ${c2x},${targetY} ${targetX},${targetY}`;
  // Bezier midpoint (t = 0.5).
  const mx = 0.125 * sourceX + 0.375 * c1x + 0.375 * c2x + 0.125 * targetX;
  const my = (sourceY + targetY) / 2;
  const { color, hovered, dim } = data;
  const title = `${linkLabel(data.kind)}: ${data.label}`;
  return (
    <>
      {hovered && !dim && (
        <path d={path} fill="none" stroke={color} strokeWidth={8} strokeOpacity={0.18} style={{ filter: "blur(3px)" }} pointerEvents="none" />
      )}
      <BaseEdge
        id={id}
        path={path}
        interactionWidth={16}
        className="eg-dash"
        style={{
          stroke: color,
          strokeWidth: hovered ? 2.6 : 1.4 + Math.min(1.6, (data.weight - 1) * 0.4),
          strokeDasharray: "6 5",
          opacity: dim ? 0.15 : hovered ? 1 : 0.75,
          transition: "opacity 250ms, stroke-width 200ms",
        }}
      />
      {(hovered || data.showLabel) && !dim && (
        <EdgeLabelRenderer>
          <div
            className={cn(
              "nodrag nopan pointer-events-none absolute rounded-lg border bg-card/95 shadow-md backdrop-blur",
              hovered ? "z-50 max-w-72 px-2.5 py-1.5" : "px-2 py-0.5",
            )}
            style={{ transform: `translate(-50%, -50%) translate(${mx}px, ${my}px)`, borderColor: `${color}77` }}
            role={hovered ? "tooltip" : undefined}
          >
            <p className="whitespace-nowrap font-mono text-[10px] font-semibold" style={{ color }}>
              {truncate(hovered ? title : data.label || linkLabel(data.kind), hovered ? 60 : 22)}
              {data.weight > 1 && <span className="ml-1 font-normal opacity-80">×{data.weight}</span>}
            </p>
            {hovered && data.evidence.length > 0 && (
              <ul className="mt-1 space-y-0.5 text-[10px] text-muted-foreground">
                {data.evidence.slice(0, 6).map((ev, i) => (
                  <li key={i} className="truncate">
                    {truncate(oneLine(ev, 80), 80)}
                  </li>
                ))}
                {data.evidence.length > 6 && <li>+{data.evidence.length - 6}</li>}
              </ul>
            )}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
});

export const laneEdgeTypes: EdgeTypes = { laneLink: LinkEdgeImpl };
