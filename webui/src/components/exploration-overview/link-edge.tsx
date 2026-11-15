import { memo } from "react";
import { BaseEdge, EdgeLabelRenderer, type Edge, type EdgeProps, type EdgeTypes } from "@xyflow/react";
import type { OverviewLink } from "@/types/api";
import { truncate } from "@/components/exploration-graph/meta";
import { linkMeta } from "./shared";

// Cross-target link edge. Several links between the same pair of targets are
// fanned out as quadratic curves (offset = lane); the label and evidence only
// appear while the edge is hovered or highlighted.

export type LinkEdgeData = {
  link: OverviewLink;
  /** Position among parallel links of the same pair, centred on 0. */
  lane: number;
  dim: boolean;
  hovered: boolean;
  highlight: boolean;
  [key: string]: unknown;
};

export type LinkFlowEdge = Edge<LinkEdgeData, "link">;

const LinkEdgeImpl = memo(function LinkEdgeImpl({ id, sourceX, sourceY, targetX, targetY, data }: EdgeProps<LinkFlowEdge>) {
  if (!data) return null;
  const { link, lane, dim, hovered, highlight } = data;
  const meta = linkMeta(link.kind);
  const dx = targetX - sourceX;
  const dy = targetY - sourceY;
  const len = Math.hypot(dx, dy) || 1;
  // Perpendicular offset for parallel links (and a slight bow for all).
  const bend = lane * 34 + 12;
  const cx = (sourceX + targetX) / 2 + (-dy / len) * bend;
  const cy = (sourceY + targetY) / 2 + (dx / len) * bend;
  const path = `M ${sourceX},${sourceY} Q ${cx},${cy} ${targetX},${targetY}`;
  const lx = 0.25 * sourceX + 0.5 * cx + 0.25 * targetX;
  const ly = 0.25 * sourceY + 0.5 * cy + 0.25 * targetY;
  const weight = Math.max(1, link.weight || 1);
  const base = 1 + Math.min(weight, 8) * 0.55;
  const active = hovered || highlight;
  const width = active ? base + 1.2 : base;
  const opacity = dim ? 0.06 : active ? 0.95 : 0.45;
  const evidence = (link.evidence ?? []).slice(0, 4);
  const more = (link.evidence?.length ?? 0) - evidence.length;

  return (
    <>
      <BaseEdge
        id={id}
        path={path}
        interactionWidth={18}
        style={{
          stroke: meta.color,
          strokeWidth: width,
          strokeOpacity: opacity,
          strokeDasharray: link.kind === "shared_infra" ? "5 4" : undefined,
          filter: active && !dim ? `drop-shadow(0 0 4px ${meta.color})` : undefined,
          transition: "stroke-opacity 200ms, stroke-width 200ms",
        }}
      />
      {hovered && !dim && (
        <EdgeLabelRenderer>
          <div
            className="nodrag nopan pointer-events-none absolute z-10 max-w-64 rounded-md border bg-popover/95 px-2 py-1.5 text-[11px] text-popover-foreground shadow-lg backdrop-blur"
            style={{
              transform: `translate(-50%, -50%) translate(${lx}px, ${ly}px)`,
              borderColor: `${meta.color}66`,
            }}
            role="tooltip"
          >
            <div className="flex items-center gap-1.5 font-medium">
              <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: meta.color }} aria-hidden />
              <span className="truncate">{truncate(link.label || meta.label, 48)}</span>
              {weight > 1 && <span className="shrink-0 tabular-nums text-muted-foreground">×{weight}</span>}
            </div>
            <div className="text-[10px] text-muted-foreground">{meta.label}</div>
            {evidence.length > 0 && (
              <ul className="mt-1 space-y-0.5 border-t border-border pt-1 text-[10px] text-muted-foreground">
                {evidence.map((e, i) => (
                  <li key={i} className="truncate">
                    {truncate(e, 80)}
                  </li>
                ))}
                {more > 0 && <li>+{more} more</li>}
              </ul>
            )}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
});

export const linkEdgeTypes: EdgeTypes = { link: LinkEdgeImpl };
