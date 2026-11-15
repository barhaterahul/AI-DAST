import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, ArrowRight, BadgeCheck, ExternalLink, ShieldAlert, X } from "lucide-react";
import type { ExplorationGraphNode } from "@/types/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CopyButton } from "@/components/copy-button";
import { SeverityBadge } from "@/components/severity-badge";
import { cn } from "@/lib/utils";
import { useI18n } from "@/i18n";
import { STATUS_STYLES, accentFor, edgeMeta, nodeMeta, safeHttpUrl, str, truncate } from "./meta";

// Right-hand inspector for the selected node. Every value is untrusted
// target/LLM output: rendered as text only, links restricted to http(s).

const BLOCK_FIELDS = new Set([
  "payload",
  "request",
  "response",
  "command",
  "summary",
  "technical_analysis",
  "poc_description",
  "impact",
  "indicator",
  "task_summary",
  "next_action",
]);

// Preferred display order; remaining keys follow alphabetically.
const FIELD_ORDER = [
  "id",
  "title",
  "name",
  "method",
  "path",
  "url",
  "location",
  "vuln_class",
  "status",
  "confidence",
  "attempts",
  "kind",
  "source",
  "tool",
  "category",
  "severity",
  "cvss",
  "cwe",
  "owasp",
  "verified",
  "verification_method",
  "hypothesis_id",
  "evidence_id",
  "event_id",
  "agent_id",
  "timestamp",
  "created_at",
  "lane_classes",
  "payload",
  "request",
  "response",
  "indicator",
  "command",
  "summary",
  "impact",
  "poc_description",
  "technical_analysis",
  "next_action",
  "task_summary",
];

function humanize(key: string): string {
  return key.replace(/_/g, " ");
}

function orderedKeys(data: Record<string, unknown>): string[] {
  const keys = Object.keys(data);
  const rank = (k: string) => {
    const i = FIELD_ORDER.indexOf(k);
    return i === -1 ? FIELD_ORDER.length : i;
  };
  return keys.sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
}

export interface NeighborRef {
  node: ExplorationGraphNode;
  kind: string;
}

export function DetailPanel({
  node,
  scanId,
  upstream,
  downstream,
  onSelect,
  onClose,
  className,
}: {
  node: ExplorationGraphNode;
  scanId: string;
  upstream: NeighborRef[];
  downstream: NeighborRef[];
  onSelect: (id: string) => void;
  onClose: () => void;
  className?: string;
}) {
  const { t } = useI18n();
  const tr = (k: string, f: string) => (t(k) === k ? f : t(k));
  const meta = nodeMeta(node.type);
  const Icon = meta.icon;
  const accent = accentFor(node.type, node.severity);
  const data = node.data && typeof node.data === "object" ? node.data : {};
  const findingId = node.type === "finding" ? str(data.id) : "";

  return (
    <aside
      className={cn(
        "flex min-h-0 flex-col overflow-hidden rounded-md border border-border bg-card text-card-foreground",
        className,
      )}
    >
      <div className="flex items-start gap-2 border-b border-border p-3" style={{ boxShadow: `inset 3px 0 0 ${accent}` }}>
        <span
          className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded"
          style={{ backgroundColor: `${accent}22`, color: accent }}
        >
          <Icon className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{meta.label}</p>
          <p className="break-words text-sm font-medium leading-snug">{node.label}</p>
          {node.subtitle && <p className="mt-0.5 break-words text-xs text-muted-foreground">{node.subtitle}</p>}
          <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
            {node.severity && <SeverityBadge severity={node.severity} />}
            {node.status && (
              <span
                className={cn(
                  "rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                  STATUS_STYLES[node.status] ?? STATUS_STYLES.rejected,
                )}
              >
                {truncate(node.status, 16)}
              </span>
            )}
            {node.verified && (
              <Badge variant="success" className="gap-1 text-[10px]">
                <BadgeCheck className="h-3 w-3" /> {tr("exploration.verified", "verified")}
              </Badge>
            )}
          </div>
        </div>
        <Button variant="ghost" size="icon" className="h-7 w-7" onClick={onClose} aria-label="Close">
          <X className="h-4 w-4" />
        </Button>
      </div>

      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-3">
        {findingId && (
          <Button asChild size="sm" variant="secondary" className="w-full">
            <Link
              to={`/scans/${encodeURIComponent(scanId)}#finding-${encodeURIComponent(
                JSON.stringify([scanId, findingId]),
              )}`}
            >
              <ShieldAlert className="h-3.5 w-3.5" />
              {tr("exploration.openFinding", "Open finding in scan")}
            </Link>
          </Button>
        )}

        <dl className="space-y-2.5">
          {orderedKeys(data).map((key) => (
            <Field key={key} name={key} value={data[key]} />
          ))}
          {node.finding_ids && node.finding_ids.length > 0 && (
            <Field name="finding_ids" value={node.finding_ids} />
          )}
          <Field name="node_id" value={node.id} />
        </dl>

        <Neighbors
          title={tr("exploration.upstream", "Upstream")}
          icon={<ArrowLeft className="h-3 w-3" />}
          items={upstream}
          onSelect={onSelect}
        />
        <Neighbors
          title={tr("exploration.downstream", "Downstream")}
          icon={<ArrowRight className="h-3 w-3" />}
          items={downstream}
          onSelect={onSelect}
        />
      </div>
    </aside>
  );
}

function Field({ name, value }: { name: string; value: unknown }) {
  if (value === null || value === undefined || value === "") return null;
  if (Array.isArray(value)) {
    if (value.length === 0) return null;
    return (
      <div>
        <dt className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{humanize(name)}</dt>
        <dd className="mt-1 flex flex-wrap gap-1">
          {value.map((v, i) => (
            <span key={i} className="max-w-full truncate rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[11px]">
              {truncate(str(v), 80)}
            </span>
          ))}
        </dd>
      </div>
    );
  }
  const text = str(value);
  const isBlock = BLOCK_FIELDS.has(name) || typeof value === "object" || text.length > 90 || text.includes("\n");
  if (isBlock) {
    return (
      <div>
        <div className="flex items-center justify-between">
          <dt className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{humanize(name)}</dt>
          <CopyButton value={text} className="h-6 w-6" />
        </div>
        <dd>
          <pre className="mt-1 max-h-72 overflow-auto whitespace-pre-wrap break-all rounded border border-border bg-muted/60 p-2 font-mono text-[11px] leading-relaxed text-foreground">
            {text}
          </pre>
        </dd>
      </div>
    );
  }
  const href = name === "url" ? safeHttpUrl(value) : null;
  return (
    <div className="grid grid-cols-[110px_1fr] items-start gap-2">
      <dt className="pt-px text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{humanize(name)}</dt>
      <dd className="flex min-w-0 items-start gap-1">
        <span
          className={cn(
            "min-w-0 break-all text-xs",
            /(_id|^id|path|url|method|event|tool|source)$/.test(name) && "font-mono",
          )}
        >
          {typeof value === "boolean" ? (value ? "yes" : "no") : text}
        </span>
        {href && (
          <a
            href={href}
            target="_blank"
            rel="noopener noreferrer nofollow"
            className="shrink-0 text-muted-foreground hover:text-foreground"
            aria-label="Open URL"
          >
            <ExternalLink className="h-3 w-3" />
          </a>
        )}
      </dd>
    </div>
  );
}

function Neighbors({
  title,
  icon,
  items,
  onSelect,
}: {
  title: string;
  icon: ReactNode;
  items: NeighborRef[];
  onSelect: (id: string) => void;
}) {
  if (items.length === 0) return null;
  return (
    <div>
      <p className="mb-1 flex items-center gap-1 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
        {icon} {title} ({items.length})
      </p>
      <ul className="space-y-1">
        {items.slice(0, 40).map(({ node, kind }) => {
          const m = nodeMeta(node.type);
          const NIcon = m.icon;
          const accent = accentFor(node.type, node.severity);
          return (
            <li key={`${kind}:${node.id}`}>
              <button
                type="button"
                onClick={() => onSelect(node.id)}
                className="flex w-full min-w-0 items-center gap-2 rounded px-1.5 py-1 text-left text-xs hover:bg-accent"
              >
                <NIcon className="h-3 w-3 shrink-0" style={{ color: accent }} />
                <span className="min-w-0 flex-1 truncate">{node.label}</span>
                <span className="shrink-0 font-mono text-[10px]" style={{ color: edgeMeta(kind).color }}>
                  {kind}
                </span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
