import { memo, type CSSProperties, type ReactNode } from "react";
import { Handle, Position, type Node, type NodeProps, type NodeTypes } from "@xyflow/react";
import { BadgeCheck } from "lucide-react";
import type { ExplorationGraphNode } from "@/types/api";
import { cn, normalizeSeverity } from "@/lib/utils";
import {
  BACKEND_ICONS,
  METHOD_STYLES,
  STATUS_STYLES,
  accentFor,
  nodeMeta,
  oneLine,
  str,
  truncate,
} from "./meta";

// Custom React Flow nodes. All content is rendered as plain React text: the
// strings come from the attacked target and the LLM and are untrusted.

export type FlowNodeData = {
  node: ExplorationGraphNode;
  dim: boolean;
  traced: boolean;
  match: boolean;
  /** Current step of an attack-path replay. */
  spotlight?: boolean;
  /** Entrance animation delay in ms (staggered left to right). */
  delay?: number;
  [key: string]: unknown;
};

export type FlowNode = Node<FlowNodeData>;

function Shell({
  data,
  selected,
  icon,
  children,
}: {
  data: FlowNodeData;
  selected: boolean;
  icon?: ReactNode;
  children: ReactNode;
}) {
  const n = data.node;
  const meta = nodeMeta(n.type);
  const accent = accentFor(n.type, n.severity);
  const Icon = meta.icon;
  const sev = n.type === "finding" ? normalizeSeverity(n.severity) : "";
  const hot = sev === "critical" || sev === "high";
  const glow = data.spotlight ? "eg-spot" : hot && !data.dim ? "eg-halo" : "";
  return (
    <div
      className={cn("eg-pop relative h-full transition-[opacity,filter] duration-300", data.dim && "opacity-20 saturate-50")}
      style={{ animationDelay: `${data.delay ?? 0}ms`, width: meta.width, height: meta.height }}
    >
      <div
        className={cn(
          "group relative flex h-full overflow-hidden rounded-xl border bg-card/85 text-card-foreground shadow-sm backdrop-blur-sm",
          "transition-[opacity,transform,box-shadow,border-color] duration-300 hover:-translate-y-0.5 hover:shadow-lg",
          data.match && "ring-2 ring-sky-400 ring-offset-2 ring-offset-background",
          glow,
        )}
        style={
          {
            "--eg-accent": accent,
            borderColor: selected || data.traced ? accent : `${accent}40`,
            boxShadow:
              !glow && (data.traced || selected)
                ? `0 0 0 1px ${accent}66, 0 8px 28px -6px ${accent}66`
                : undefined,
          } as CSSProperties
        }
        title={n.label}
      >
        {/* accent wash + top sheen */}
        <div
          className="pointer-events-none absolute inset-0"
          style={{ background: `linear-gradient(120deg, ${accent}26 0%, ${accent}0a 38%, transparent 70%)` }}
          aria-hidden
        />
        <div
          className="pointer-events-none absolute inset-x-0 top-0 h-px"
          style={{ background: `linear-gradient(90deg, transparent, ${accent}aa, transparent)` }}
          aria-hidden
        />
        <div
          className="w-1 shrink-0"
          style={{ background: `linear-gradient(180deg, ${accent}, ${accent}55)` }}
          aria-hidden
        />
        <div className="relative flex min-w-0 flex-1 flex-col justify-center gap-1 px-2.5 py-1.5">
          <div className="flex min-w-0 items-center gap-1.5">
            <span className="relative flex h-5 w-5 shrink-0 items-center justify-center">
              {(data.spotlight || (hot && !data.dim)) && (
                <span className="eg-ping absolute inset-0 rounded-md" style={{ backgroundColor: accent }} aria-hidden />
              )}
              <span
                className="relative flex h-5 w-5 items-center justify-center rounded-md text-white"
                style={{
                  background: `linear-gradient(135deg, ${accent}, ${accent}b3)`,
                  boxShadow: `0 2px 8px -1px ${accent}99`,
                }}
              >
                {icon ?? <Icon className="h-3 w-3" aria-hidden />}
              </span>
            </span>
            <span className="text-[10px] font-semibold uppercase tracking-[0.12em]" style={{ color: accent }}>
              {meta.label}
            </span>
          </div>
          {children}
        </div>
      </div>
      <Handle
        type="target"
        position={Position.Left}
        isConnectable={false}
        className="!h-2 !w-2 !min-h-0 !min-w-0 !border-2 !border-background"
        style={{ backgroundColor: accent }}
      />
      <Handle
        type="source"
        position={Position.Right}
        isConnectable={false}
        className="!h-2 !w-2 !min-h-0 !min-w-0 !border-2 !border-background"
        style={{ backgroundColor: accent }}
      />
    </div>
  );
}

function Title({ children, mono }: { children: ReactNode; mono?: boolean }) {
  return (
    <div className={cn("truncate text-xs font-medium text-foreground", mono && "font-mono")}>
      {children}
    </div>
  );
}

function Sub({ children, mono }: { children: ReactNode; mono?: boolean }) {
  return (
    <div className={cn("truncate text-[11px] text-muted-foreground", mono && "font-mono")}>
      {children}
    </div>
  );
}

function Chip({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center rounded border px-1 py-px text-[9px] font-semibold uppercase leading-none tracking-wide",
        className,
      )}
    >
      {children}
    </span>
  );
}

function StatusPill({ status }: { status?: string }) {
  if (!status) return null;
  return (
    <Chip className={STATUS_STYLES[status] ?? STATUS_STYLES.rejected}>{truncate(status, 12)}</Chip>
  );
}

const TargetNode = memo(({ data, selected }: NodeProps<FlowNode>) => (
  <Shell data={data} selected={selected}>
    <Title mono>{truncate(str(data.node.data.url) || data.node.label, 60)}</Title>
  </Shell>
));

const AgentNode = memo(({ data, selected }: NodeProps<FlowNode>) => {
  const d = data.node.data;
  const lanes = Array.isArray(d.lane_classes) ? (d.lane_classes as unknown[]).map(str) : [];
  return (
    <Shell data={data} selected={selected}>
      <Title>{data.node.label}</Title>
      <div className="flex min-w-0 gap-1 overflow-hidden">
        {lanes.slice(0, 4).map((l) => (
          <Chip key={l} className="border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-300">
            {truncate(l, 14)}
          </Chip>
        ))}
        {lanes.length === 0 && <Sub>{oneLine(d.task_summary || data.node.subtitle, 40)}</Sub>}
      </div>
    </Shell>
  );
});

const DiscoveryNode = memo(({ data, selected }: NodeProps<FlowNode>) => {
  const d = data.node.data;
  return (
    <Shell data={data} selected={selected}>
      <Title mono>{str(d.tool) || data.node.label}</Title>
      <Sub mono>{oneLine(d.command || data.node.subtitle, 44)}</Sub>
    </Shell>
  );
});

const EndpointNode = memo(({ data, selected }: NodeProps<FlowNode>) => {
  const d = data.node.data;
  const method = str(d.method).toUpperCase();
  const path = str(d.path) || data.node.label;
  return (
    <Shell data={data} selected={selected}>
      <div className="flex min-w-0 items-center gap-1.5">
        <Chip className={METHOD_STYLES[method] ?? "border-border bg-muted text-muted-foreground"}>
          {method ? truncate(method, 7) : "ANY"}
        </Chip>
        <Title mono>{path}</Title>
      </div>
      {data.node.subtitle && <Sub>{data.node.subtitle}</Sub>}
    </Shell>
  );
});

const ParameterNode = memo(({ data, selected }: NodeProps<FlowNode>) => {
  const d = data.node.data;
  const loc = str(d.location) || "unknown";
  return (
    <Shell data={data} selected={selected}>
      <div className="flex min-w-0 items-center gap-1.5">
        <Title mono>{str(d.name) || data.node.label}</Title>
        <Chip className="border-teal-500/30 bg-teal-500/10 text-teal-700 dark:text-teal-300">
          {truncate(loc, 10)}
        </Chip>
      </div>
    </Shell>
  );
});

const AttemptNode = memo(({ data, selected }: NodeProps<FlowNode>) => {
  const d = data.node.data;
  const vc = str(d.vuln_class);
  const status = data.node.status || str(d.status);
  const conf = typeof d.confidence === "number" ? d.confidence : undefined;
  return (
    <Shell data={data} selected={selected}>
      <div className="flex min-w-0 items-center gap-1.5">
        <Chip className="border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300">
          {truncate(vc || "test", 14)}
        </Chip>
        <StatusPill status={status} />
        {conf !== undefined && (
          <span className="ml-auto shrink-0 text-[10px] tabular-nums text-muted-foreground">
            {conf <= 1 ? `${Math.round(conf * 100)}%` : conf}
          </span>
        )}
      </div>
      <Sub>{str(d.title) || data.node.label}</Sub>
    </Shell>
  );
});

const EvidenceNode = memo(({ data, selected }: NodeProps<FlowNode>) => {
  const d = data.node.data;
  const kind = str(d.kind) || "evidence";
  const payload = oneLine(d.payload, 48);
  return (
    <Shell data={data} selected={selected}>
      <div className="flex min-w-0 items-center gap-1.5">
        <Chip
          className={
            kind === "exploit"
              ? "border-orange-500/30 bg-orange-500/10 text-orange-700 dark:text-orange-300"
              : "border-border bg-muted text-muted-foreground"
          }
        >
          {truncate(kind, 10)}
        </Chip>
        <Title mono>{str(d.source) || data.node.label}</Title>
      </div>
      {payload ? (
        <div className="truncate rounded bg-muted/70 px-1 py-px font-mono text-[10px] text-foreground/90">
          {payload}
        </div>
      ) : (
        <Sub>{oneLine(d.summary || data.node.subtitle, 48)}</Sub>
      )}
    </Shell>
  );
});

const SEV_TEXT: Record<string, string> = {
  critical: "text-red-600 dark:text-red-400",
  high: "text-orange-600 dark:text-orange-400",
  medium: "text-amber-700 dark:text-amber-400",
  low: "text-blue-600 dark:text-blue-400",
  info: "text-neutral-600 dark:text-neutral-400",
};

const FindingNode = memo(({ data, selected }: NodeProps<FlowNode>) => {
  const n = data.node;
  const d = n.data;
  const sev = normalizeSeverity(n.severity || str(d.severity));
  const cvss = typeof d.cvss === "number" ? d.cvss.toFixed(1) : str(d.cvss);
  const verified = n.verified ?? d.verified === true;
  return (
    <Shell data={data} selected={selected}>
      <div className="flex min-w-0 items-center gap-1.5">
        <span className={cn("text-[10px] font-bold uppercase tracking-wide", SEV_TEXT[sev])}>{sev}</span>
        {cvss && <span className="text-[10px] tabular-nums text-muted-foreground">CVSS {truncate(cvss, 5)}</span>}
        {verified && (
          <BadgeCheck className="ml-auto h-3.5 w-3.5 shrink-0 text-emerald-500" aria-label="verified" />
        )}
      </div>
      <Title>{str(d.title) || n.label}</Title>
    </Shell>
  );
});

const BackendNode = memo(({ data, selected }: NodeProps<FlowNode>) => {
  const d = data.node.data;
  const cat = str(d.category) || "other";
  const Icon = BACKEND_ICONS[cat] ?? BACKEND_ICONS.other;
  return (
    <Shell data={data} selected={selected} icon={<Icon className="h-3 w-3" aria-hidden />}>
      <Title>{str(d.name) || data.node.label}</Title>
      <Sub mono>{oneLine(d.indicator || cat, 40)}</Sub>
    </Shell>
  );
});

export const nodeTypes: NodeTypes = {
  target: TargetNode,
  agent: AgentNode,
  discovery: DiscoveryNode,
  endpoint: EndpointNode,
  parameter: ParameterNode,
  attempt: AttemptNode,
  evidence: EvidenceNode,
  finding: FindingNode,
  backend: BackendNode,
};
