import { useCallback, useEffect, useMemo } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowLeft, ExternalLink, GitCompare, LayoutDashboard, Network } from "lucide-react";
import { useScansList } from "@/api/queries";
import type { ExplorationScope, ScanListItem } from "@/types/api";
import { ExplorationGraphView } from "@/components/exploration-graph";
import { CombinedGraphView } from "@/components/exploration-graph/combined-view";
import { MAX_COMPARE, OverviewView } from "@/components/exploration-overview";
import { EmptyState, ErrorState } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ScanStatusPill } from "@/components/scan-status-pill";
import { formatTime } from "@/lib/utils";
import { useI18n } from "@/i18n";

// Exploration has three views, all deep-linkable through the URL:
//   ?view=overview  (default without ?scan=) — every target, links, matrix
//   ?view=scan&scan=<id>&scope=all            — one scan's exploration graph
//   ?view=compare&compare=<id1>,<id2>         — several scans side by side
// Old links carrying only ?scan=<id> open the scan view.

type View = "overview" | "scan" | "compare";

function parseView(params: URLSearchParams): View {
  const v = params.get("view");
  if (v === "overview" || v === "scan" || v === "compare") return v;
  return params.get("scan") ? "scan" : "overview";
}

function parseCompare(raw: string | null): string[] {
  if (!raw) return [];
  const out: string[] = [];
  for (const part of raw.split(",")) {
    const id = part.trim();
    if (id && !out.includes(id)) out.push(id);
    if (out.length >= MAX_COMPARE) break;
  }
  return out;
}

function byNewest(a: ScanListItem, b: ScanListItem) {
  return (new Date(b.started_at).getTime() || 0) - (new Date(a.started_at).getTime() || 0);
}

function hostOf(target: string): string {
  try {
    return new URL(target).host || target;
  } catch {
    return target;
  }
}

function useTr() {
  const { t } = useI18n();
  return useCallback((k: string, f: string) => (t(k) === k ? f : t(k)), [t]);
}

export default function ExplorationPage() {
  const tr = useTr();
  const [params, setParams] = useSearchParams();
  const view = parseView(params);
  const scope: ExplorationScope = params.get("scope") === "all" ? "all" : "findings";
  const compareRaw = params.get("compare");
  const compareIds = useMemo(() => parseCompare(compareRaw), [compareRaw]);

  const switchView = (v: string) => {
    if (v !== "overview" && v !== "scan" && v !== "compare") return;
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set("view", v);
      return next;
    });
  };

  const setScope = useCallback(
    (s: ExplorationScope) =>
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (s === "all") next.set("scope", "all");
          else next.delete("scope");
          return next;
        },
        { replace: true },
      ),
    [setParams],
  );

  const openScan = useCallback(
    (scanId: string) => {
      if (!scanId) return;
      const next = new URLSearchParams();
      next.set("view", "scan");
      next.set("scan", scanId);
      if (scope === "all") next.set("scope", "all");
      setParams(next);
    },
    [scope, setParams],
  );

  const openCompare = useCallback(
    (scanIds: string[]) => {
      const ids = parseCompare(scanIds.join(","));
      if (ids.length === 0) return;
      const next = new URLSearchParams();
      next.set("view", "compare");
      next.set("compare", ids.join(","));
      if (scope === "all") next.set("scope", "all");
      setParams(next);
    },
    [scope, setParams],
  );

  const subtitle =
    view === "overview"
      ? tr("exploration.overview.subtitle", "Every target you have scanned — what they expose and what they share.")
      : view === "compare"
        ? tr("exploration.compare.subtitle", "Several scans side by side, with what links them.")
        : tr("exploration.subtitle", "How each finding was found — from discovery to injection to proof.");

  return (
    <div className="space-y-4">
      <header className="space-y-3">
        <div>
          <h1 className="flex items-center gap-2 font-sans text-2xl font-semibold tracking-tight">
            <Network className="h-5 w-5 text-muted-foreground" />
            {tr("exploration.title", "Exploration Graph")}
          </h1>
          <p className="text-sm text-muted-foreground">{subtitle}</p>
        </div>
      </header>

      <Tabs value={view} onValueChange={switchView}>
        <TabsList
          aria-label={tr("exploration.views", "Exploration views")}
          className="w-full justify-start overflow-x-auto"
        >
          <TabsTrigger value="overview" className="gap-1.5">
            <LayoutDashboard className="h-3.5 w-3.5" aria-hidden />
            {tr("exploration.view.overview", "Overview")}
          </TabsTrigger>
          <TabsTrigger value="scan" className="gap-1.5">
            <Network className="h-3.5 w-3.5" aria-hidden />
            {tr("exploration.view.scan", "Scan graph")}
          </TabsTrigger>
          <TabsTrigger value="compare" className="gap-1.5">
            <GitCompare className="h-3.5 w-3.5" aria-hidden />
            {tr("exploration.view.compare", "Compare")}
            {compareIds.length > 0 && (
              <span className="rounded-full bg-muted px-1.5 text-[10px] tabular-nums text-muted-foreground">
                {compareIds.length}
              </span>
            )}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <OverviewView onOpenScan={openScan} onCompare={openCompare} />
        </TabsContent>

        <TabsContent value="scan">
          <ScanView scope={scope} onScopeChange={setScope} />
        </TabsContent>

        <TabsContent value="compare">
          {compareIds.length === 0 ? (
            <EmptyState
              icon={<GitCompare className="h-6 w-6" />}
              title={tr("exploration.compare.empty", "Nothing to compare yet")}
              description={tr(
                "exploration.compare.emptyHint",
                "Select two or more targets in the Overview (checkbox or Shift/Ctrl-click on the map), then choose “Compare selected”.",
              )}
              action={
                <Button size="sm" variant="outline" onClick={() => switchView("overview")}>
                  <LayoutDashboard className="h-3.5 w-3.5" />
                  {tr("exploration.compare.goOverview", "Go to Overview")}
                </Button>
              }
            />
          ) : (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <Button size="sm" variant="ghost" onClick={() => switchView("overview")}>
                  <ArrowLeft className="h-3.5 w-3.5" />
                  {tr("exploration.compare.back", "Back to Overview")}
                </Button>
                <span className="text-xs text-muted-foreground">
                  {tr("exploration.compare.comparing", "Comparing")} {compareIds.length}{" "}
                  {compareIds.length === 1
                    ? tr("exploration.compare.scan", "scan")
                    : tr("exploration.compare.scans", "scans")}
                </span>
              </div>
              <CombinedGraphView
                key={compareIds.join(",")}
                scanIds={compareIds}
                scope={scope}
                onScopeChange={setScope}
                onOpenScan={openScan}
              />
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}

/** Single-scan exploration graph with the scan picker (unchanged behaviour). */
function ScanView({
  scope,
  onScopeChange,
}: {
  scope: ExplorationScope;
  onScopeChange: (s: ExplorationScope) => void;
}) {
  const tr = useTr();
  const [params, setParams] = useSearchParams();
  const { data: scansRaw, isLoading, error, refetch } = useScansList();

  const scans = useMemo(() => [...(scansRaw ?? [])].sort(byNewest), [scansRaw]);
  const fallbackId = useMemo(
    () => (scans.find((s) => (s.vuln_count ?? 0) > 0) ?? scans[0])?.id ?? "",
    [scans],
  );
  const requested = params.get("scan") ?? "";
  const scanId = requested || fallbackId;
  const current = scans.find((s) => s.id === scanId);

  // Pin the default choice into the URL so the view is shareable/deep-linkable.
  useEffect(() => {
    if (!requested && fallbackId) {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          next.set("view", "scan");
          next.set("scan", fallbackId);
          return next;
        },
        { replace: true },
      );
    }
  }, [requested, fallbackId, setParams]);

  const selectScan = (v: string) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set("view", "scan");
      next.set("scan", v);
      return next;
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex w-full flex-wrap items-center justify-end gap-2">
        {scans.length > 0 && (
          <Select value={scanId} onValueChange={selectScan}>
            <SelectTrigger className="h-9 w-full sm:w-96" aria-label={tr("exploration.pickScan", "Select a scan")}>
              <SelectValue placeholder={tr("exploration.pickScan", "Select a scan")} />
            </SelectTrigger>
            <SelectContent className="max-w-[min(92vw,32rem)]">
              {scans.map((s) => (
                <SelectItem key={s.id} value={s.id} className="text-xs">
                  <span className="flex min-w-0 items-center gap-2">
                    <span className="truncate font-mono">{hostOf(s.target)}</span>
                    <span className="shrink-0 text-muted-foreground">{formatTime(s.started_at)}</span>
                    <span className="shrink-0 tabular-nums text-muted-foreground">
                      · {s.vuln_count ?? 0} {tr("exploration.findingsShort", "findings")}
                    </span>
                  </span>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        {current && <ScanStatusPill status={current.status} />}
        {scanId && (
          <Button asChild variant="outline" size="sm">
            <Link to={`/scans/${encodeURIComponent(scanId)}`}>
              <ExternalLink className="h-3.5 w-3.5" />
              {tr("exploration.openScan", "Open scan")}
            </Link>
          </Button>
        )}
      </div>

      {isLoading ? (
        <Skeleton className="h-[70vh] w-full" />
      ) : error ? (
        <ErrorState
          description={error instanceof Error ? error.message : undefined}
          action={
            <Button size="sm" variant="outline" onClick={() => refetch()}>
              {tr("common.retry", "Retry")}
            </Button>
          }
        />
      ) : !scanId ? (
        <EmptyState
          icon={<Network className="h-6 w-6" />}
          title={tr("exploration.noScans", "No scans yet")}
          description={tr(
            "exploration.noScansHint",
            "Run a scan and the exploration graph will show how each finding was reached.",
          )}
          action={
            <Button asChild size="sm">
              <Link to="/scans/new">{tr("exploration.newScan", "New scan")}</Link>
            </Button>
          }
        />
      ) : (
        <ExplorationGraphView
          key={scanId}
          scanId={scanId}
          scope={scope}
          onScopeChange={onScopeChange}
        />
      )}
    </div>
  );
}
