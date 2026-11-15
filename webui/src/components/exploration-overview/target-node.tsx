import { memo, type CSSProperties } from "react";
import { Handle, Position, type Node, type NodeProps, type NodeTypes } from "@xyflow/react";
import { Route } from "lucide-react";
import type { OverviewTarget } from "@/types/api";
import { cn, normalizeSeverity } from "@/lib/utils";
import { CompareCheckbox, SeverityBar, StatusDot, TechChips } from "./primitives";
import { TARGET_NODE_H, TARGET_NODE_W, hostLabel, topSeverityColor } from "./shared";

// One React Flow node per target. All content is plain React text: hosts,
// tech names and labels come from scanned targets and are untrusted.

export { TARGET_NODE_H, TARGET_NODE_W };

export type TargetNodeData = {
  target: OverviewTarget;
  dim: boolean;
  highlight: boolean;
  compared: boolean;
  compareFull: boolean;
  delay: number;
  onToggleCompare: (key: string) => void;
  [key: string]: unknown;
};

export type TargetFlowNode = Node<TargetNodeData, "target">;

// A single invisible handle pair in the centre: edges are drawn centre to
// centre by the custom link edge, so handle position does not matter.
const handleStyle: CSSProperties = {
  top: "50%",
  left: "50%",
  width: 1,
  height: 1,
  minWidth: 0,
  minHeight: 0,
  border: 0,
  background: "transparent",
  opacity: 0,
  pointerEvents: "none",
  transform: "translate(-50%, -50%)",
};

const TargetNodeImpl = memo(function TargetNodeImpl({ data, selected }: NodeProps<TargetFlowNode>) {
  const t = data.target;
  const accent = topSeverityColor(t.top_severity);
  const sev = t.top_severity ? normalizeSeverity(t.top_severity) : "";
  const hot = sev === "critical" || sev === "high";
  const glow = hot && !data.dim ? "eg-halo" : "";
  const host = hostLabel(t);
  const emphasised = selected || data.highlight;
  return (
    <div
      className={cn("eg-pop relative transition-[opacity,filter] duration-300", data.dim && "opacity-20 saturate-50")}
      style={{ animationDelay: `${data.delay}ms`, width: TARGET_NODE_W, height: TARGET_NODE_H }}
    >
      <Handle type="target" position={Position.Top} style={handleStyle} isConnectable={false} />
      <Handle type="source" position={Position.Top} style={handleStyle} isConnectable={false} />
      <div
        className={cn(
          "group relative flex h-full cursor-pointer flex-col gap-1.5 overflow-hidden rounded-xl border bg-card/90 p-2.5 text-card-foreground shadow-sm backdrop-blur-sm",
          "transition-[transform,box-shadow,border-color] duration-300 hover:-translate-y-0.5 hover:shadow-lg",
          data.compared && "ring-2 ring-sky-500 ring-offset-2 ring-offset-background",
          glow,
        )}
        style={
          {
            "--eg-accent": accent,
            borderColor: emphasised ? accent : `${accent}55`,
            boxShadow:
              !glow && emphasised ? `0 0 0 1px ${accent}66, 0 8px 28px -6px ${accent}66` : undefined,
          } as CSSProperties
        }
        title={t.label || host}
      >
        <div
          className="pointer-events-none absolute inset-0"
          style={{ background: `linear-gradient(120deg, ${accent}26 0%, ${accent}0a 40%, transparent 72%)` }}
          aria-hidden
        />
        <div className="pointer-events-none absolute inset-y-0 left-0 w-1" style={{ backgroundColor: accent }} aria-hidden />

        <div className="relative flex min-w-0 items-center gap-1.5 pl-1">
          <StatusDot status={t.latest_status} />
          <span className="min-w-0 flex-1 truncate font-mono text-xs font-semibold">{host}</span>
          <span
            className="shrink-0 rounded-full px-1.5 py-px text-[10px] font-semibold tabular-nums text-white"
            style={{ backgroundColor: accent }}
            aria-label={`${t.findings} findings`}
          >
            {t.findings}
          </span>
          <CompareCheckbox
            checked={data.compared}
            disabled={data.compareFull}
            onToggle={() => data.onToggleCompare(t.key)}
            label={`${data.compared ? "Remove" : "Add"} ${host} ${data.compared ? "from" : "to"} compare`}
          />
        </div>

        <SeverityBar counts={t.severity} className="relative ml-1 w-[calc(100%-0.25rem)]" />

        <div className="relative flex items-center gap-2 pl-1 text-[10px] text-muted-foreground">
          <span className="inline-flex items-center gap-1 tabular-nums" title="Endpoints">
            <Route className="h-3 w-3" aria-hidden />
            {t.endpoints} endpoints
          </span>
          {sev ? (
            <span className="font-medium uppercase tracking-wide" style={{ color: accent }}>
              {sev}
            </span>
          ) : (
            <span>no findings</span>
          )}
          {(t.scans?.length ?? 0) > 1 && <span className="ml-auto tabular-nums">{t.scans.length} scans</span>}
        </div>

        <TechChips backend={t.backend} max={2} className="relative pl-1" />
      </div>
    </div>
  );
});

export const targetNodeTypes: NodeTypes = { target: TargetNodeImpl };
