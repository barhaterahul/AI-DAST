import type { OverviewTarget } from "@/types/api";
import { normalizeSeverity } from "@/lib/utils";
import { GRID_THRESHOLD, TARGET_NODE_H, TARGET_NODE_W, bySeverity } from "./shared";

// Deterministic target-map layout without extra dependencies.
//
// Rings: the most severe targets sit in the centre ring, then high, medium,
// and low/info/no-findings outermost. Each ring is at least big enough to fit
// its nodes side by side and is rotated a little so spokes do not line up.
// Above GRID_THRESHOLD targets a compact grid (sorted by severity) is used.

export interface Point {
  x: number;
  y: number;
}

export type MapLayout = "rings" | "grid";

const RING_OF: Record<string, number> = { critical: 0, high: 1, medium: 2 };

function ringIndex(t: OverviewTarget): number {
  if (!t.top_severity) return 3;
  return RING_OF[normalizeSeverity(t.top_severity)] ?? 3;
}

/** Returns top-left positions keyed by target key. */
export function layoutTargets(targets: OverviewTarget[]): { positions: Map<string, Point>; kind: MapLayout } {
  const positions = new Map<string, Point>();
  const sorted = [...targets].sort(bySeverity);
  if (sorted.length > GRID_THRESHOLD) {
    const cols = Math.max(1, Math.ceil(Math.sqrt(sorted.length * 1.6)));
    const gx = TARGET_NODE_W + 36;
    const gy = TARGET_NODE_H + 36;
    sorted.forEach((t, i) => {
      positions.set(t.key, { x: (i % cols) * gx, y: Math.floor(i / cols) * gy });
    });
    return { positions, kind: "grid" };
  }

  const rings: OverviewTarget[][] = [[], [], [], []];
  for (const t of sorted) rings[ringIndex(t)].push(t);
  const nonEmpty = rings.filter((r) => r.length > 0);

  // Arc length one node needs along a ring (diagonal-ish footprint + gap).
  const spacing = TARGET_NODE_W + 48;
  const ringGap = TARGET_NODE_H + TARGET_NODE_W * 0.75;
  let radius = 0;
  nonEmpty.forEach((ring, ri) => {
    const n = ring.length;
    if (ri === 0 && n === 1) {
      radius = 0;
    } else {
      const fit = (n * spacing) / (2 * Math.PI);
      const min = ri === 0 ? (n <= 1 ? 0 : Math.max(spacing * 0.6, fit)) : radius + ringGap;
      radius = Math.max(min, fit);
    }
    const offset = ri * 0.55 - Math.PI / 2;
    ring.forEach((t, i) => {
      const a = offset + (i / n) * Math.PI * 2;
      const cx = radius * Math.cos(a);
      // Squash vertically a little: cards are wider than tall.
      const cy = radius * Math.sin(a) * 0.82;
      positions.set(t.key, { x: Math.round(cx - TARGET_NODE_W / 2), y: Math.round(cy - TARGET_NODE_H / 2) });
    });
  });
  return { positions, kind: "rings" };
}
