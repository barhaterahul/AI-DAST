import { useMemo, useState, type CSSProperties } from "react";
import { ArrowDownWideNarrow, Network, Route } from "lucide-react";
import type { OverviewTarget } from "@/types/api";
import { cn, formatTime, timeAgo } from "@/lib/utils";
import { truncate } from "@/components/exploration-graph/meta";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/severity-badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { CompareCheckbox, SeverityBar, StatusDot, TechChips } from "./primitives";
import { bySeverity, hostLabel, timeMs, topClasses, topSeverityColor, useTr } from "./shared";

// Responsive, sortable grid of target cards.

type SortKey = "severity" | "findings" | "last" | "name";

export function TargetCards({
  targets,
  compare,
  compareFull,
  onToggleCompare,
  onOpenScan,
  className,
}: {
  targets: OverviewTarget[];
  compare: Set<string>;
  compareFull: boolean;
  onToggleCompare: (key: string) => void;
  onOpenScan: (scanId: string) => void;
  className?: string;
}) {
  const tr = useTr();
  const [sort, setSort] = useState<SortKey>("severity");
  const sorted = useMemo(() => {
    const arr = [...targets];
    switch (sort) {
      case "findings":
        arr.sort((a, b) => (b.findings || 0) - (a.findings || 0) || bySeverity(a, b));
        break;
      case "last":
        arr.sort((a, b) => timeMs(b.last_scanned) - timeMs(a.last_scanned) || bySeverity(a, b));
        break;
      case "name":
        arr.sort((a, b) => hostLabel(a).localeCompare(hostLabel(b)));
        break;
      default:
        arr.sort(bySeverity);
    }
    return arr;
  }, [targets, sort]);

  return (
    <div className={cn("space-y-3", className)}>
      <div className="flex items-center justify-end gap-2">
        <ArrowDownWideNarrow className="h-4 w-4 text-muted-foreground" aria-hidden />
        <Select value={sort} onValueChange={(v) => setSort(v as SortKey)}>
          <SelectTrigger className="h-8 w-44 text-xs" aria-label={tr("exploration.overview.sortBy", "Sort by")}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="severity" className="text-xs">{tr("exploration.overview.sort.severity", "Severity")}</SelectItem>
            <SelectItem value="findings" className="text-xs">{tr("exploration.overview.sort.findings", "Findings")}</SelectItem>
            <SelectItem value="last" className="text-xs">{tr("exploration.overview.sort.last", "Last scanned")}</SelectItem>
            <SelectItem value="name" className="text-xs">{tr("exploration.overview.sort.name", "Name")}</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
        {sorted.map((t) => (
          <li key={t.key}>
            <TargetCard
              target={t}
              compared={compare.has(t.key)}
              compareFull={compareFull}
              onToggleCompare={onToggleCompare}
              onOpenScan={onOpenScan}
            />
          </li>
        ))}
      </ul>
    </div>
  );
}

function TargetCard({
  target: t,
  compared,
  compareFull,
  onToggleCompare,
  onOpenScan,
}: {
  target: OverviewTarget;
  compared: boolean;
  compareFull: boolean;
  onToggleCompare: (key: string) => void;
  onOpenScan: (scanId: string) => void;
}) {
  const tr = useTr();
  const accent = topSeverityColor(t.top_severity);
  const host = hostLabel(t);
  const classes = topClasses(t, 4);
  return (
    <article
      className={cn(
        "relative flex h-full flex-col gap-2.5 overflow-hidden rounded-lg border bg-card p-3 text-card-foreground shadow-sm transition-shadow hover:shadow-md",
        compared && "ring-2 ring-sky-500",
      )}
      style={{ borderColor: `${accent}55`, "--eg-accent": accent } as CSSProperties}
      aria-label={host}
    >
      <div
        className="pointer-events-none absolute inset-0"
        style={{ background: `linear-gradient(120deg, ${accent}1f 0%, transparent 55%)` }}
        aria-hidden
      />
      <div className="pointer-events-none absolute inset-y-0 left-0 w-1" style={{ backgroundColor: accent }} aria-hidden />

      <div className="relative flex min-w-0 items-center gap-2 pl-1">
        <CompareCheckbox
          checked={compared}
          disabled={compareFull || !t.latest_scan_id}
          onToggle={() => onToggleCompare(t.key)}
          label={`${compared ? "Remove" : "Add"} ${host} ${compared ? "from" : "to"} compare`}
        />
        <StatusDot status={t.latest_status} />
        <h3 className="min-w-0 flex-1 truncate font-mono text-sm font-semibold" title={t.label || host}>
          {host}
        </h3>
        {t.top_severity ? (
          <SeverityBadge severity={t.top_severity} />
        ) : (
          <span className="text-[11px] text-muted-foreground">{tr("exploration.overview.noFindings", "No findings")}</span>
        )}
      </div>

      <SeverityBar counts={t.severity} className="relative ml-1 w-[calc(100%-0.25rem)]" />

      <dl className="relative grid grid-cols-3 gap-1 pl-1 text-[11px]">
        <div>
          <dt className="text-muted-foreground">{tr("exploration.overview.findings", "Findings")}</dt>
          <dd className="font-semibold tabular-nums">{t.findings}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">{tr("exploration.overview.endpoints", "Endpoints")}</dt>
          <dd className="inline-flex items-center gap-1 font-semibold tabular-nums">
            <Route className="h-3 w-3 text-muted-foreground" aria-hidden />
            {t.endpoints}
          </dd>
        </div>
        <div>
          <dt className="text-muted-foreground">{tr("exploration.overview.scans", "Scans")}</dt>
          <dd className="font-semibold tabular-nums">{t.scans?.length ?? 0}</dd>
        </div>
      </dl>

      {classes.length > 0 && (
        <div className="relative flex flex-wrap gap-1 pl-1">
          {classes.map(([c, n]) => (
            <span key={c} className="rounded border border-border bg-muted/40 px-1.5 py-px font-mono text-[10px]">
              {truncate(c, 20)} <span className="tabular-nums text-muted-foreground">{n}</span>
            </span>
          ))}
        </div>
      )}

      <TechChips backend={t.backend} max={4} className="relative pl-1" />

      <div className="relative mt-auto flex items-center justify-between gap-2 pl-1 pt-1">
        <span className="text-[11px] text-muted-foreground" title={formatTime(t.last_scanned)}>
          {tr("exploration.overview.lastScanned", "Last scanned")} {timeAgo(t.last_scanned)}
        </span>
        <Button
          size="sm"
          variant="outline"
          className="h-7 px-2"
          disabled={!t.latest_scan_id}
          onClick={() => onOpenScan(t.latest_scan_id)}
        >
          <Network className="h-3.5 w-3.5" />
          {tr("exploration.overview.openGraph", "Open graph")}
        </Button>
      </div>
    </article>
  );
}
