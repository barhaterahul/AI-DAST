import dagre from "@dagrejs/dagre";
import type { ExplorationGraphEdge, ExplorationGraphNode } from "@/types/api";
import { nodeMeta } from "./meta";

export interface PositionedNode {
  node: ExplorationGraphNode;
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface VisibleEdge {
  id: string;
  source: string;
  target: string;
  kind: string;
  bridged: boolean;
}

/**
 * Removes nodes whose type is hidden and reconnects their visible
 * predecessors to their visible successors with "bridged" edges, so hiding
 * e.g. parameters does not break the endpoint -> attempt chain apart.
 */
export function filterGraph(
  nodes: ExplorationGraphNode[],
  edges: ExplorationGraphEdge[],
  hidden: Set<string>,
): { nodes: ExplorationGraphNode[]; edges: VisibleEdge[] } {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const validEdges = edges.filter((e) => byId.has(e.source) && byId.has(e.target));
  if (hidden.size === 0) {
    return {
      nodes,
      edges: dedupeEdges(
        validEdges.map((e) => ({ ...e, kind: e.kind, bridged: false })),
      ),
    };
  }
  const isVisible = (id: string) => {
    const n = byId.get(id);
    return !!n && !hidden.has(n.type);
  };
  const out = new Map<string, ExplorationGraphEdge[]>();
  for (const e of validEdges) {
    const list = out.get(e.source);
    if (list) list.push(e);
    else out.set(e.source, [e]);
  }
  const result: VisibleEdge[] = [];
  for (const e of validEdges) {
    if (!isVisible(e.source)) continue;
    if (isVisible(e.target)) {
      result.push({ ...e, bridged: false });
      continue;
    }
    // Walk through hidden nodes to the next visible descendants.
    const seen = new Set<string>([e.target]);
    const stack = [e.target];
    while (stack.length) {
      const cur = stack.pop()!;
      for (const next of out.get(cur) ?? []) {
        if (seen.has(next.target)) continue;
        seen.add(next.target);
        if (isVisible(next.target)) {
          if (next.target !== e.source) {
            result.push({
              id: `bridge:${e.source}->${next.target}`,
              source: e.source,
              target: next.target,
              kind: next.kind,
              bridged: true,
            });
          }
        } else {
          stack.push(next.target);
        }
      }
    }
  }
  return {
    nodes: nodes.filter((n) => !hidden.has(n.type)),
    edges: dedupeEdges(result),
  };
}

function dedupeEdges(edges: VisibleEdge[]): VisibleEdge[] {
  const seen = new Set<string>();
  const ids = new Set<string>();
  const out: VisibleEdge[] = [];
  for (const e of edges) {
    const key = `${e.source}\u0000${e.target}\u0000${e.kind}`;
    if (seen.has(key)) continue;
    seen.add(key);
    // Edge ids must be unique for React Flow even if the API repeats one.
    const id = ids.has(e.id) || !e.id ? `${e.id || "edge"}#${out.length}` : e.id;
    ids.add(id);
    out.push(id === e.id ? e : { ...e, id });
  }
  return out;
}

/** Left-to-right layered layout (target on the left, backend on the right). */
export function layoutGraph(
  nodes: ExplorationGraphNode[],
  edges: VisibleEdge[],
  compact = false,
): PositionedNode[] {
  const g = new dagre.graphlib.Graph({ multigraph: false });
  g.setGraph({
    rankdir: "LR",
    nodesep: 18,
    ranksep: compact ? 44 : 90,
    edgesep: 10,
    marginx: 20,
    marginy: 20,
  });
  g.setDefaultEdgeLabel(() => ({}));
  for (const n of nodes) {
    const m = nodeMeta(n.type);
    g.setNode(n.id, { width: m.width, height: m.height });
  }
  for (const e of edges) {
    if (e.source === e.target) continue;
    g.setEdge(e.source, e.target);
  }
  dagre.layout(g);
  return nodes.map((n) => {
    const m = nodeMeta(n.type);
    const p = g.node(n.id) as { x?: number; y?: number } | undefined;
    return {
      node: n,
      width: m.width,
      height: m.height,
      // dagre returns centers; React Flow wants the top-left corner.
      x: (p?.x ?? 0) - m.width / 2,
      y: (p?.y ?? 0) - m.height / 2,
    };
  });
}

export interface Adjacency {
  parents: Map<string, string[]>;
  children: Map<string, string[]>;
}

export function buildAdjacency(edges: ExplorationGraphEdge[]): Adjacency {
  const parents = new Map<string, string[]>();
  const children = new Map<string, string[]>();
  for (const e of edges) {
    (children.get(e.source) ?? children.set(e.source, []).get(e.source)!).push(e.target);
    (parents.get(e.target) ?? parents.set(e.target, []).get(e.target)!).push(e.source);
  }
  return { parents, children };
}

function walk(start: string, next: Map<string, string[]>, into: Set<string>) {
  const stack = [start];
  while (stack.length) {
    const cur = stack.pop()!;
    for (const n of next.get(cur) ?? []) {
      if (into.has(n)) continue;
      into.add(n);
      stack.push(n);
    }
  }
}

/**
 * The set of nodes highlighted when tracing `id`: every ancestor back to the
 * target, plus descendants. For a finding, descendants are only what it
 * reveals (backend tech); for any other node, everything downstream of it.
 */
export function traceSet(
  id: string,
  type: string,
  adj: Adjacency,
  typeOf: (id: string) => string | undefined,
): Set<string> {
  const set = new Set<string>([id]);
  walk(id, adj.parents, set);
  if (type === "finding") {
    for (const c of adj.children.get(id) ?? []) {
      if (typeOf(c) === "backend") set.add(c);
    }
  } else {
    walk(id, adj.children, set);
  }
  return set;
}
