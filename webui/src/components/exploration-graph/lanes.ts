import type { CombinedGroup, ExplorationCombined, ExplorationGraphNode, OverviewLinkKind } from "@/types/api";
import { filterGraph, layoutGraph, type PositionedNode, type VisibleEdge } from "./layout";
import { str } from "./meta";

// Lane layout for the combined (multi-target) Exploration Graph. Each group
// (one scan) is laid out on its own with the single-scan dagre layout, then
// stacked vertically inside a lane panel. Node positions are relative to the
// lane so React Flow can parent them (parentId) and draw the lane behind.

export type CombinedGraphNode = ExplorationGraphNode & { group: string };

export const LANE_HEADER_H = 64;
/** Band below the header that holds the stage captions. */
export const LANE_STAGE_H = 40;
export const LANE_PAD_X = 24;
export const LANE_PAD_BOTTOM = 24;
export const LANE_GAP = 28;
export const LANE_MIN_W = 760;
export const LANE_EMPTY_BODY_H = 72;
export const SUMMARY_H = 64;
export const SUMMARY_MAX_W = 560;

export const LINK_COLORS: Record<OverviewLinkKind, string> = {
  shared_backend: "#10b981",
  shared_vuln_class: "#f97316",
  shared_auth: "#8b5cf6",
  shared_infra: "#64748b",
};

export const LINK_LABELS: Record<OverviewLinkKind, string> = {
  shared_backend: "Shared backend",
  shared_vuln_class: "Shared vuln class",
  shared_auth: "Shared auth",
  shared_infra: "Shared infra",
};

export const LINK_KINDS = Object.keys(LINK_COLORS) as OverviewLinkKind[];

export function linkColor(kind: string): string {
  return LINK_COLORS[kind as OverviewLinkKind] ?? LINK_COLORS.shared_infra;
}

export function linkLabel(kind: string): string {
  return LINK_LABELS[kind as OverviewLinkKind] ?? kind;
}

/** Stage caption ("1 Target", "2 Agent", …) in lane-relative coordinates. */
export interface LaneStage {
  type: string;
  /** Center x relative to the lane. */
  x: number;
  step: number;
}

/** One group's independent layout, before stacking. */
export interface LaneLayout {
  group: CombinedGroup;
  /** Visible nodes of this group with positions relative to the lane. */
  positioned: PositionedNode[];
  edges: VisibleEdge[];
  /** Every node of the group (including hidden types). */
  allNodes: CombinedGraphNode[];
  contentW: number;
  contentH: number;
  stages: LaneStage[];
}

/** A lane after stacking: absolute lane rect on the canvas. */
export interface PlacedLane extends LaneLayout {
  x: number;
  y: number;
  width: number;
  height: number;
  collapsed: boolean;
}

/** Splits the combined payload into per-group node/edge lists (by `group`). */
export function partitionCombined(combined: ExplorationCombined): Map<
  string,
  { nodes: CombinedGraphNode[]; edges: ExplorationCombined["edges"] }
> {
  const parts = new Map<string, { nodes: CombinedGraphNode[]; edges: ExplorationCombined["edges"] }>();
  for (const g of combined.groups ?? []) parts.set(g.id, { nodes: [], edges: [] });
  const groupOf = new Map<string, string>();
  for (const n of combined.nodes ?? []) {
    const p = parts.get(n.group);
    if (!p) continue;
    p.nodes.push(n);
    groupOf.set(n.id, n.group);
  }
  for (const e of combined.edges ?? []) {
    const gs = groupOf.get(e.source);
    // Edges never cross lanes; drop anything that would.
    if (!gs || gs !== groupOf.get(e.target)) continue;
    parts.get(gs)!.edges.push(e);
  }
  return parts;
}

function stagesFor(positioned: PositionedNode[]): LaneStage[] {
  if (positioned.length === 0) return [];
  const byType = new Map<string, number[]>();
  for (const p of positioned) {
    const list = byType.get(p.node.type) ?? [];
    list.push(p.x + p.width / 2);
    byType.set(p.node.type, list);
  }
  const cols = [...byType.entries()]
    .map(([type, xs]) => ({ type, x: xs.sort((a, b) => a - b)[Math.floor(xs.length / 2)] }))
    .sort((a, b) => a.x - b.x);
  const out: LaneStage[] = [];
  for (const c of cols) {
    if (out.length && c.x - out[out.length - 1].x < 150) continue;
    out.push({ ...c, step: out.length + 1 });
  }
  return out;
}

/**
 * Lays out one group with filterGraph + layoutGraph and normalizes the
 * positions so the content starts at the lane's inner top-left corner.
 */
export function layoutLane(
  group: CombinedGroup,
  nodes: CombinedGraphNode[],
  edges: ExplorationCombined["edges"],
  hidden: Set<string>,
): LaneLayout {
  if (group.error || nodes.length === 0) {
    return { group, positioned: [], edges: [], allNodes: nodes, contentW: 0, contentH: 0, stages: [] };
  }
  const filtered = filterGraph(nodes, edges, hidden);
  const raw = layoutGraph(filtered.nodes, filtered.edges);
  if (raw.length === 0) {
    return { group, positioned: [], edges: [], allNodes: nodes, contentW: 0, contentH: 0, stages: [] };
  }
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const p of raw) {
    minX = Math.min(minX, p.x);
    minY = Math.min(minY, p.y);
    maxX = Math.max(maxX, p.x + p.width);
    maxY = Math.max(maxY, p.y + p.height);
  }
  const positioned = raw.map((p) => ({
    ...p,
    x: LANE_PAD_X + p.x - minX,
    y: LANE_HEADER_H + LANE_STAGE_H + p.y - minY,
  }));
  return {
    group,
    positioned,
    edges: filtered.edges,
    allNodes: nodes,
    contentW: maxX - minX,
    contentH: maxY - minY,
    stages: stagesFor(positioned),
  };
}

/**
 * Lays out every lane. `cache` keeps the previous result per group so a lane
 * whose nodes, edges and hidden types did not change is not laid out again
 * (dagre is the expensive part).
 */
export function layoutLanes(
  combined: ExplorationCombined,
  hidden: Set<string>,
  cache: Map<string, { key: unknown[]; layout: LaneLayout }>,
): LaneLayout[] {
  const parts = partitionCombined(combined);
  const hiddenKey = [...hidden].sort().join(",");
  const out: LaneLayout[] = [];
  const live = new Set<string>();
  for (const g of combined.groups ?? []) {
    const part = parts.get(g.id) ?? { nodes: [], edges: [] };
    const key: unknown[] = [hiddenKey, g, part.nodes.length, part.edges.length, signature(part.nodes)];
    const prev = cache.get(g.id);
    live.add(g.id);
    if (prev && sameKey(prev.key, key)) {
      out.push(prev.layout);
      continue;
    }
    const layout = layoutLane(g, part.nodes, part.edges, hidden);
    cache.set(g.id, { key, layout });
    out.push(layout);
  }
  for (const id of [...cache.keys()]) if (!live.has(id)) cache.delete(id);
  return out;
}

/** Cheap content fingerprint of a group's nodes (ids, types, statuses, labels). */
function signature(nodes: CombinedGraphNode[]): string {
  let h = 0;
  for (const n of nodes) {
    const s = `${n.id}|${n.type}|${n.status ?? ""}|${n.severity ?? ""}|${n.label}`;
    for (let i = 0; i < s.length; i++) h = (Math.imul(h, 31) + s.charCodeAt(i)) | 0;
  }
  return String(h);
}

function sameKey(a: unknown[], b: unknown[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    const x = a[i];
    const y = b[i];
    if (x === y) continue;
    // Groups are fresh objects after every refetch; compare their content.
    if (typeof x === "object" && typeof y === "object" && JSON.stringify(x) === JSON.stringify(y)) continue;
    return false;
  }
  return true;
}

/** Stacks lanes vertically; every lane gets the same width. */
export function stackLanes(layouts: LaneLayout[], collapsed: Set<string>): PlacedLane[] {
  const width = Math.max(LANE_MIN_W, ...layouts.map((l) => l.contentW + LANE_PAD_X * 2));
  let y = 0;
  return layouts.map((l) => {
    const isCollapsed = collapsed.has(l.group.id) && !l.group.error;
    const height = isCollapsed
      ? LANE_HEADER_H + SUMMARY_H + 20
      : l.positioned.length === 0
        ? LANE_HEADER_H + LANE_EMPTY_BODY_H
        : LANE_HEADER_H + LANE_STAGE_H + l.contentH + LANE_PAD_BOTTOM;
    const placed: PlacedLane = { ...l, x: 0, y, width, height, collapsed: isCollapsed };
    y += height + LANE_GAP;
    return placed;
  });
}

export function laneNodeId(groupId: string): string {
  return `lane:${groupId}`;
}

export function summaryNodeId(groupId: string): string {
  return `summary:${groupId}`;
}

/** Strips the "<group>:" prefix the combined API adds to node ids. */
export function displayId(id: string, group?: string): string {
  if (group && id.startsWith(`${group}:`)) return id.slice(group.length + 1);
  return id.replace(/^g?\d+:/, "");
}

/** Lower-cased search text for a node (id, labels and data values). */
export function haystack(n: ExplorationGraphNode): string {
  const parts = [n.id, n.label, n.subtitle ?? ""];
  const d = n.data && typeof n.data === "object" ? n.data : {};
  for (const v of Object.values(d)) {
    const s = Array.isArray(v) ? v.map(str).join(" ") : str(v);
    parts.push(s.length > 4000 ? s.slice(0, 4000) : s);
  }
  return parts.join("\n").toLowerCase();
}

/** Host shown in a lane header. */
export function laneTitle(g: CombinedGroup): string {
  return g.key || g.target || g.scan_id || g.id;
}

/** Node-type counts of a group (for the collapsed summary). */
export function typeCountsOf(nodes: ExplorationGraphNode[]): Record<string, number> {
  const c: Record<string, number> = {};
  for (const n of nodes) c[n.type] = (c[n.type] ?? 0) + 1;
  return c;
}
