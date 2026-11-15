import { useMemo } from "react";
import { GitCompare, Network, X } from "lucide-react";
import type { OverviewLink, OverviewTarget } from "@/types/api";
import { cn, formatTime, timeAgo } from "@/lib/utils";
import { truncate } from "@/components/exploration-graph/meta";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/severity-badge";
import { SeverityBar, StatusDot, TechChips } from "./primitives";
import { hostLabel, linkMeta, statusLabel, topClasses, useTr } from "./shared";

// Details for the target selected on the map.

export function TargetPanel({
  target,
  links,
  targetsByKey,
  compared,
  compareFull,
  onClose,
  onOpenScan,
  onToggleCompare,
  onSelectTarget,
  className,
}: {
  target: OverviewTarget;
  links: OverviewLink[];
  targetsByKey: Map<string, OverviewTarget>;
  compared: boolean;
  compareFull: boolean;
  onClose: () => void;
  onOpenScan: (scanId: string) => void;
  onToggleCompare: (key: string) => void;
  onSelectTarget: (key: string) => void;
  className?: string;
}) {
  const tr = useTr();
  const host = hostLabel(target);
  const own = useMemo(
    () => links.filter((l) => l.source === target.key || l.target === target.key),
    [links, target.key],
  );
  const classes = topClasses(target, 12);

  return (
    <section
      className={cn("rounded-md border border-border bg-card text-card-foreground", className)}
      aria-label={`${tr("exploration.overview.targetDetails", "Target details")}: ${host}`}
    >
      <div className="flex items-start gap-2 border-b border-border px-3 py-2.5">
        <StatusDot status={target.latest_status} className="mt-1.5" />
        <div className="min-w-0 flex-1">
          <p className="truncate font-mono text-sm font-semibold" title={target.label || host}>
            {host}
          </p>
          {target.label && target.label !== host && (
            <p className="truncate text-[11px] text-muted-foreground" title={target.label}>
              {target.label}
            </p>
          )}
        </div>
        <button
          type="button"
          onClick={onClose}
          className="rounded p-0.5 text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
          aria-label={tr("common.close", "Close")}
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="space-y-3 px-3 py-3 text-xs">
        <div className="flex flex-wrap gap-2">
          <Button
            size="sm"
            onClick={() => onOpenScan(target.latest_scan_id)}
            disabled={!target.latest_scan_id}
          >
            <Network className="h-3.5 w-3.5" />
            {tr("exploration.overview.openGraph", "Open graph")}
          </Button>
          <Button
            size="sm"
            variant="outline"
            aria-pressed={compared}
            disabled={(!compared && compareFull) || !target.latest_scan_id}
            onClick={() => onToggleCompare(target.key)}
          >
            <GitCompare className="h-3.5 w-3.5" />
            {compared
              ? tr("exploration.overview.removeCompare", "Remove from compare")
              : tr("exploration.overview.addCompare", "Add to compare")}
          </Button>
        </div>

        <div className="grid grid-cols-3 gap-2 text-center">
          {[
            [tr("exploration.overview.findings", "Findings"), target.findings],
            [tr("exploration.overview.verified", "Verified"), target.verified],
            [tr("exploration.overview.endpoints", "Endpoints"), target.endpoints],
          ].map(([k, v]) => (
            <div key={String(k)} className="rounded border border-border bg-muted/30 px-1 py-1.5">
              <div className="text-sm font-semibold tabular-nums">{v}</div>
              <div className="text-[10px] text-muted-foreground">{k}</div>
            </div>
          ))}
        </div>

        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-muted-foreground">{tr("exploration.overview.severity", "Severity")}</span>
            {target.top_severity ? (
              <SeverityBadge severity={target.top_severity} />
            ) : (
              <span className="text-muted-foreground">{tr("exploration.overview.none", "None")}</span>
            )}
          </div>
          <SeverityBar counts={target.severity} />
        </div>

        {(target.backend?.length ?? 0) > 0 && (
          <div className="space-y-1">
            <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
              {tr("exploration.overview.backend", "Backend")}
            </p>
            <TechChips backend={target.backend} max={12} />
          </div>
        )}

        {classes.length > 0 && (
          <div className="space-y-1">
            <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
              {tr("exploration.overview.classes", "Vulnerability classes")}
            </p>
            <div className="flex flex-wrap gap-1">
              {classes.map(([c, n]) => (
                <span key={c} className="rounded border border-border bg-muted/40 px-1.5 py-px font-mono text-[10px]">
                  {truncate(c, 24)} <span className="tabular-nums text-muted-foreground">{n}</span>
                </span>
              ))}
            </div>
          </div>
        )}

        {target.token_provider && (
          <p className="text-muted-foreground">
            {tr("exploration.overview.tokenProvider", "Token provider")}:{" "}
            <span className="font-mono text-foreground">{truncate(target.token_provider, 40)}</span>
          </p>
        )}

        <div className="space-y-1">
          <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
            {tr("exploration.overview.links", "Links")} ({own.length})
          </p>
          {own.length === 0 ? (
            <p className="text-muted-foreground">{tr("exploration.overview.noLinks", "Nothing shared with other targets.")}</p>
          ) : (
            <ul className="max-h-48 space-y-0.5 overflow-y-auto">
              {own.map((l) => {
                const other = l.source === target.key ? l.target : l.source;
                const ot = targetsByKey.get(other);
                const m = linkMeta(l.kind);
                return (
                  <li key={l.id}>
                    <button
                      type="button"
                      onClick={() => onSelectTarget(other)}
                      className="flex w-full items-center gap-2 rounded px-1 py-0.5 text-left hover:bg-accent/60 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                      title={[`${m.label}: ${l.label}`, ...(l.evidence ?? []).slice(0, 5)].join("\n")}
                    >
                      <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: m.color }} aria-hidden />
                      <span className="min-w-0 flex-1 truncate">{truncate(l.label || m.label, 32)}</span>
                      <span className="min-w-0 max-w-[45%] truncate font-mono text-[10px] text-muted-foreground">
                        {ot ? hostLabel(ot) : other}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>

        <div className="space-y-1">
          <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
            {tr("exploration.overview.scans", "Scans")} ({target.scans?.length ?? 0})
          </p>
          <ul className="max-h-56 space-y-0.5 overflow-y-auto">
            {(target.scans ?? []).map((s) => (
              <li key={s.id}>
                <button
                  type="button"
                  onClick={() => onOpenScan(s.id)}
                  className="flex w-full items-center gap-2 rounded px-1 py-1 text-left hover:bg-accent/60 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                  aria-label={`${tr("exploration.overview.openScanGraph", "Open scan graph")}: ${formatTime(s.started_at)}, ${statusLabel(s.status)}, ${s.findings} findings`}
                >
                  <StatusDot status={s.status} />
                  <span className="min-w-0 flex-1 truncate" title={formatTime(s.started_at)}>
                    {timeAgo(s.started_at)}
                  </span>
                  <span className="shrink-0 text-muted-foreground">{statusLabel(s.status)}</span>
                  <span className="w-8 shrink-0 text-right tabular-nums">{s.findings}</span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
