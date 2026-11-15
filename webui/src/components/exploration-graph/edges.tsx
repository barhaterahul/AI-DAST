import { memo, useId } from "react";
import {
  BaseEdge,
  EdgeLabelRenderer,
  getBezierPath,
  type Edge,
  type EdgeProps,
  type EdgeTypes,
} from "@xyflow/react";

// Gradient "data flow" edge: the stroke fades from the source node's accent to
// the target's, traced edges get a soft glow, and particles travel along the
// path to show the direction the attack moved in.

export type FlowEdgeData = {
  from: string;
  to: string;
  kind: string;
  bridged: boolean;
  /** On the selected trace (or revealed so far during replay). */
  active: boolean;
  dim: boolean;
  hovered: boolean;
  /** Number of travelling particles (0 = none). */
  particles: number;
  [key: string]: unknown;
};

export type FlowEdge = Edge<FlowEdgeData>;

const FlowEdgeImpl = memo(function FlowEdgeImpl({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  markerEnd,
  data,
}: EdgeProps<FlowEdge>) {
  const rawId = useId();
  const gid = `eg-grad-${rawId.replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const [path, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
    curvature: 0.35,
  });
  if (!data) return <BaseEdge id={id} path={path} markerEnd={markerEnd} />;

  const { from, to, active, dim, hovered, bridged, particles, kind } = data;
  const width = active || hovered ? 2.6 : 1.5;
  const opacity = dim ? 0.08 : active || hovered ? 1 : 0.7;
  // Longer edges get slower particles so the apparent speed stays constant.
  const len = Math.hypot(targetX - sourceX, targetY - sourceY);
  const dur = Math.min(4.5, Math.max(1.4, len / 160));

  return (
    <>
      <defs>
        <linearGradient id={gid} gradientUnits="userSpaceOnUse" x1={sourceX} y1={sourceY} x2={targetX} y2={targetY}>
          <stop offset="0%" stopColor={from} />
          <stop offset="100%" stopColor={to} />
        </linearGradient>
      </defs>
      {(active || hovered) && !dim && (
        <path
          d={path}
          fill="none"
          stroke={`url(#${gid})`}
          strokeWidth={9}
          strokeOpacity={0.18}
          strokeLinecap="round"
          style={{ filter: "blur(3px)" }}
          pointerEvents="none"
        />
      )}
      <BaseEdge
        id={id}
        path={path}
        markerEnd={markerEnd}
        interactionWidth={14}
        className={bridged || kind === "proves" ? "eg-dash" : undefined}
        style={{
          stroke: `url(#${gid})`,
          strokeWidth: width,
          strokeDasharray: bridged ? "4 4" : kind === "proves" ? "7 5" : undefined,
          opacity,
          transition: "opacity 250ms, stroke-width 200ms",
        }}
      />
      {!dim &&
        Array.from({ length: particles }, (_, i) => (
          <circle key={i} className="eg-particle" r={active ? 3 : 2.2} fill={to} pointerEvents="none">
            <animateMotion
              dur={`${dur}s`}
              begin={`${(i * dur) / particles}s`}
              repeatCount="indefinite"
              path={path}
              rotate="auto"
            />
            <animate
              attributeName="opacity"
              values="0;1;1;0"
              keyTimes="0;0.1;0.85;1"
              dur={`${dur}s`}
              begin={`${(i * dur) / particles}s`}
              repeatCount="indefinite"
            />
          </circle>
        ))}
      {hovered && (
        <EdgeLabelRenderer>
          <div
            className="nodrag nopan pointer-events-none absolute rounded-full border bg-card/95 px-2 py-0.5 font-mono text-[10px] shadow-md backdrop-blur"
            style={{
              transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
              borderColor: `${to}66`,
              color: to,
            }}
          >
            {bridged ? `${kind} · via hidden` : kind}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
});

export const edgeTypes: EdgeTypes = { flow: FlowEdgeImpl };
