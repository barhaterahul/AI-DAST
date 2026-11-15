import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  AlertTriangle,
  FilterX,
  GitCompare,
  Grid3x3,
  LayoutGrid,
  Loader2,
  Network,
  Search,
  Share2,
  X,
  type LucideIcon,
} from "lucide-react";
import { useExplorationOverview } from "@/api/queries";
import type { ExplorationOverview, OverviewQuery } from "@/types/api";
import { cn } from "@/lib/utils";
import { useDebounced } from "@/lib/use-debounced";
import { EmptyState, ErrorState } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { SEVERITY_COLORS } from "@/components/exploration-graph/meta";
import { SeverityBar } from "./primitives";
import { TargetMap } from "./target-map";
import { TargetCards } from "./target-cards";
import { OverviewMatrix } from "./matrix";
import { MAX_COMPARE, SEV_ORDER, hostLabel, parseMode, useTr, type OverviewMode } from "./shared";

// Multi-target overview: totals, filters (URL state) and three sub-modes —
// map, cards and matrix — plus a compare selection shared across modes.

const ANY = "any";
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const STATUSES = ["running", "finished", "stopped", "failed", "paused", "pending"] as const;

export interface OverviewViewProps {
  /** Open the single-scan graph for this scan record id. */
  onOpenScan: (scanId: string) => void;
  /** Open the combined (compare) view for these scan ids. */
  onCompare: (scanIds: string[]) => void;
  className?: string;
}

export function OverviewView({ onOpenScan, onCompare, className }: OverviewViewProps) {
  const tr = useTr();
  const [params, setParams] = useSearchParams();

  const urlQ = params.get("q") ?? "";
  const sev = params.get("sev") ?? "";
  const status = params.get("status") ?? "";
  const since = params.get("since") ?? "";
  const mode = parseMode(params.get("mode"));

  const setParam = useCallback(
    (entries: Record<string, string | null>) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          for (const [k, v] of Object.entries(entries)) {
            if (v) next.set(k, v);
            else next.delete(k);
          }
          return next;
        },
        { replace: true },
      );
    },
    [setParams],
  );

  // Search box: local state, debounced into the URL.
  const [qInput, setQInput] = useState(urlQ);
  const debouncedQ = useDebounced(qInput.trim(), 300);
  useEffect(() => {
    if (debouncedQ !== urlQ) setParam({ q: debouncedQ || null });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedQ]);
  // Follow external URL changes (back/forward, clear filters).
  useEffect(() => {
    setQInput((cur) => (cur.trim() === urlQ ? cur : urlQ));
  }, [urlQ]);

  const query = useMemo<OverviewQuery>(
    () => ({
      q: urlQ || undefined,
      min_severity: sev || undefined,
      status: status || undefined,
      since: since || undefined,
    }),
    [urlQ, sev, status, since],
  );
  const filtersActive = !!(urlQ || sev || status || since);
  const { data, isLoading, isFetching, error, refetch } = useExplorationOverview(query);

  // Compare selection: target key -> latest scan id (kept even if a filter
  // later hides the target).
  const [compare, setCompare] = useState<Map<string, string>>(() => new Map());
  const compareKeys = useMemo(() => new Set(compare.keys()), [compare]);
  const compareFull = compare.size >= MAX_COMPARE;
  const targetsByKey = useMemo(() => new Map((data?.targets ?? []).map((t) => [t.key, t])), [data]);

  const toggleCompare = useCallback(
    (key: string) => {
      setCompare((prev) => {
        const next = new Map(prev);
        if (next.has(key)) {
          next.delete(key);
          return next;
        }
        const scanId = targetsByKey.get(key)?.latest_scan_id;
        if (!scanId || next.size >= MAX_COMPARE) return prev;
        next.set(key, scanId);
        return next;
      });
    },
    [targetsByKey],
  );

  const clearFilters = () => {
    setQInput("");
    setParam({ q: null, sev: null, status: null, since: null });
  };

  const modes: { value: OverviewMode; label: string; icon: LucideIcon }[] = [
    { value: "map", label: tr("exploration.overview.mode.map", "Map"), icon: Share2 },
    { value: "cards", label: tr("exploration.overview.mode.cards", "Cards"), icon: LayoutGrid },
    { value: "matrix", label: tr("exploration.overview.mode.matrix", "Matrix"), icon: Grid3x3 },
  ];

  const targets = data?.targets ?? [];

  return (
    <div className={cn("space-y-4", className)}>
      <TotalsStrip data={data} loading={isLoading} />

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2" role="search" aria-label={tr("exploration.overview.filters", "Filter targets")}>
        <div className="relative w-full sm:w-64">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input
            value={qInput}
            onChange={(e) => setQInput(e.target.value)}
            placeholder={tr("exploration.overview.search", "Search targets, tech, classes…")}
            aria-label={tr("exploration.overview.search", "Search targets, tech, classes…")}
            className="h-9 pl-8"
            maxLength={200}
          />
        </div>
        <Select value={sev || ANY} onValueChange={(v) => setParam({ sev: v === ANY ? null : v })}>
          <SelectTrigger className="h-9 w-[calc(50%-0.25rem)] text-xs sm:w-40" aria-label={tr("exploration.overview.minSeverity", "Minimum severity")}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ANY} className="text-xs">{tr("exploration.overview.anySeverity", "Any severity")}</SelectItem>
            {SEVERITIES.map((s) => (
              <SelectItem key={s} value={s} className="text-xs">
                <span className="inline-flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: SEVERITY_COLORS[s] }} aria-hidden />
                  {s === "info" ? tr("exploration.overview.anyFinding", "Any finding") : `${s.charAt(0).toUpperCase()}${s.slice(1)}+`}
                </span>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={status || ANY} onValueChange={(v) => setParam({ status: v === ANY ? null : v })}>
          <SelectTrigger className="h-9 w-[calc(50%-0.25rem)] text-xs sm:w-36" aria-label={tr("exploration.overview.status", "Scan status")}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ANY} className="text-xs">{tr("exploration.overview.anyStatus", "Any status")}</SelectItem>
            {STATUSES.map((s) => (
              <SelectItem key={s} value={s} className="text-xs">
                {s === "finished" ? "Completed" : `${s.charAt(0).toUpperCase()}${s.slice(1)}`}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
          {tr("exploration.overview.since", "Since")}
          <Input
            type="date"
            value={since}
            onChange={(e) => setParam({ since: e.target.value || null })}
            className="h-9 w-40 text-xs"
            aria-label={tr("exploration.overview.sinceLabel", "Scanned since")}
          />
        </label>
        {filtersActive && (
          <Button size="sm" variant="ghost" onClick={clearFilters}>
            <FilterX className="h-3.5 w-3.5" />
            {tr("exploration.overview.clearFilters", "Clear filters")}
          </Button>
        )}
        <div className="ml-auto flex items-center gap-2">
          {isFetching && !isLoading && (
            <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" aria-label={tr("common.loading", "Loading")} />
          )}
          <div className="inline-flex rounded-md border border-border bg-card p-0.5" role="radiogroup" aria-label={tr("exploration.overview.mode", "Overview mode")}>
            {modes.map((m) => {
              const Icon = m.icon;
              const on = mode === m.value;
              return (
                <button
                  key={m.value}
                  type="button"
                  role="radio"
                  aria-checked={on}
                  onClick={() => setParam({ mode: m.value === "map" ? null : m.value })}
                  className={cn(
                    "inline-flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-medium transition-colors",
                    "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
                    on ? "bg-secondary text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
                  )}
                >
                  <Icon className="h-3.5 w-3.5" aria-hidden />
                  {m.label}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {error && data && (
        <ErrorState
          title={tr("exploration.overview.refreshFailed", "Could not refresh the overview")}
          description={error instanceof Error ? error.message : undefined}
          action={
            <Button size="sm" variant="outline" onClick={() => refetch()}>
              {tr("common.retry", "Retry")}
            </Button>
          }
        />
      )}

      {data?.truncated && (
        <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-amber-800 dark:text-amber-300" role="status">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
          <span>
            {tr("exploration.overview.truncated", "Showing the first")} {data.filters?.limit || targets.length}{" "}
            {tr("exploration.overview.truncatedTail", "targets. Narrow the filters to see the rest.")}
          </span>
        </div>
      )}

      {isLoading ? (
        <OverviewSkeleton mode={mode} />
      ) : error && !data ? (
        <ErrorState
          title={tr("exploration.overview.loadFailed", "Could not load the exploration overview")}
          description={error instanceof Error ? error.message : undefined}
          action={
            <Button size="sm" variant="outline" onClick={() => refetch()}>
              {tr("common.retry", "Retry")}
            </Button>
          }
        />
      ) : targets.length === 0 ? (
        filtersActive ? (
          <EmptyState
            icon={<FilterX className="h-6 w-6" />}
            title={tr("exploration.overview.noMatch", "No targets match these filters")}
            description={tr("exploration.overview.noMatchHint", "Try a broader search, a lower severity or an earlier date.")}
            action={
              <Button size="sm" variant="outline" onClick={clearFilters}>
                {tr("exploration.overview.clearFilters", "Clear filters")}
              </Button>
            }
          />
        ) : (
          <EmptyState
            icon={<Network className="h-6 w-6" />}
            title={tr("exploration.noScans", "No scans yet")}
            description={tr(
              "exploration.overview.noScansHint",
              "Run a scan and every target will appear here with its findings, backend and what it shares with other targets.",
            )}
            action={
              <Button asChild size="sm">
                <Link to="/scans/new">{tr("exploration.newScan", "New scan")}</Link>
              </Button>
            }
          />
        )
      ) : mode === "cards" ? (
        <TargetCards
          targets={targets}
          compare={compareKeys}
          compareFull={compareFull}
          onToggleCompare={toggleCompare}
          onOpenScan={onOpenScan}
        />
      ) : mode === "matrix" ? (
        <OverviewMatrix targets={targets} matrix={data?.matrix} onOpenScan={onOpenScan} />
      ) : (
        <TargetMap
          targets={targets}
          links={data?.links ?? []}
          compare={compareKeys}
          compareFull={compareFull}
          onToggleCompare={toggleCompare}
          onOpenScan={onOpenScan}
        />
      )}

      {compare.size > 0 && (
        <CompareBar
          compare={compare}
          labelOf={(k) => {
            const t = targetsByKey.get(k);
            return t ? hostLabel(t) : k;
          }}
          onRemove={toggleCompare}
          onClear={() => setCompare(new Map())}
          onCompare={() => onCompare([...compare.values()])}
        />
      )}
    </div>
  );
}

function TotalsStrip({ data, loading }: { data?: ExplorationOverview; loading: boolean }) {
  const tr = useTr();
  if (loading && !data) {
    return (
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-[68px]" />
        ))}
      </div>
    );
  }
  const totals = data?.totals;
  const sev = totals?.severity;
  const stats: [string, number][] = [
    [tr("exploration.overview.targets", "Targets"), totals?.targets ?? 0],
    [tr("exploration.overview.scans", "Scans"), totals?.scans ?? 0],
    [tr("exploration.overview.findings", "Findings"), totals?.findings ?? 0],
  ];
  return (
    <div className="grid grid-cols-3 gap-3 md:grid-cols-4" aria-label={tr("exploration.overview.totals", "Totals")}>
      {stats.map(([label, value]) => (
        <div key={label} className="rounded-md border border-border bg-card px-3 py-2.5">
          <div className="text-[11px] text-muted-foreground">{label}</div>
          <div className="text-xl font-semibold tabular-nums">{value.toLocaleString()}</div>
        </div>
      ))}
      <div className="col-span-3 space-y-2 rounded-md border border-border bg-card px-3 py-2.5 md:col-span-1">
        <div className="text-[11px] text-muted-foreground">{tr("exploration.overview.severity", "Severity")}</div>
        <SeverityBar counts={sev} className="h-2" />
        <div className="flex flex-wrap gap-x-2.5 gap-y-0.5 text-[10px] text-muted-foreground">
          {SEV_ORDER.map((s) => (
            <span key={s} className="inline-flex items-center gap-1 tabular-nums">
              <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: SEVERITY_COLORS[s] }} aria-hidden />
              {sev?.[s] ?? 0} {s}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

function OverviewSkeleton({ mode }: { mode: OverviewMode }) {
  if (mode === "cards") {
    return (
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3" aria-busy="true">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-44" />
        ))}
      </div>
    );
  }
  if (mode === "matrix") return <Skeleton className="h-96 w-full" aria-busy="true" />;
  return (
    <div className="flex flex-col gap-3 lg:flex-row" aria-busy="true">
      <Skeleton className="h-[70vh] min-h-[420px] flex-1" />
      <Skeleton className="h-64 w-full lg:h-[70vh] lg:w-80" />
    </div>
  );
}

function CompareBar({
  compare,
  labelOf,
  onRemove,
  onClear,
  onCompare,
}: {
  compare: Map<string, string>;
  labelOf: (key: string) => string;
  onRemove: (key: string) => void;
  onClear: () => void;
  onCompare: () => void;
}) {
  const tr = useTr();
  const n = compare.size;
  const canCompare = n >= 2;
  return (
    <div className="pointer-events-none sticky bottom-4 z-30 flex justify-center">
      <div
        className="pointer-events-auto flex max-w-full flex-wrap items-center gap-2 rounded-full border border-border bg-popover/95 px-3 py-1.5 text-popover-foreground shadow-lg backdrop-blur"
        role="region"
        aria-label={tr("exploration.overview.compareSelection", "Compare selection")}
      >
        <ul className="hidden max-w-[40vw] items-center gap-1 overflow-x-auto md:flex">
          {[...compare.keys()].map((k) => (
            <li key={k}>
              <span className="inline-flex max-w-[10rem] items-center gap-1 rounded-full border border-border bg-muted/50 py-0.5 pl-2 pr-1 font-mono text-[10px]">
                <span className="truncate">{labelOf(k)}</span>
                <button
                  type="button"
                  onClick={() => onRemove(k)}
                  className="rounded-full p-0.5 text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                  aria-label={`${tr("exploration.overview.remove", "Remove")} ${labelOf(k)}`}
                >
                  <X className="h-2.5 w-2.5" />
                </button>
              </span>
            </li>
          ))}
        </ul>
        {n >= MAX_COMPARE && (
          <span className="text-[11px] text-muted-foreground">
            {tr("exploration.overview.compareMax", "Max")} {MAX_COMPARE}
          </span>
        )}
        <Button
          size="sm"
          className="h-7 rounded-full"
          disabled={!canCompare}
          onClick={onCompare}
          title={canCompare ? undefined : tr("exploration.overview.compareMin", "Select at least 2 targets")}
        >
          <GitCompare className="h-3.5 w-3.5" />
          {tr("exploration.overview.compareSelected", "Compare selected")} ({n})
        </Button>
        <Button size="sm" variant="ghost" className="h-7 rounded-full px-2" onClick={onClear}>
          {tr("exploration.overview.clear", "Clear")}
        </Button>
      </div>
    </div>
  );
}
