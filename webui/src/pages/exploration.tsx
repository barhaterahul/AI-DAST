import { useEffect, useMemo } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ExternalLink, Network } from "lucide-react";
import { useScansList } from "@/api/queries";
import type { ExplorationScope, ScanListItem } from "@/types/api";
import { ExplorationGraphView } from "@/components/exploration-graph";
import { EmptyState, ErrorState } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
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

export default function ExplorationPage() {
  const { t } = useI18n();
  const tr = (k: string, f: string) => (t(k) === k ? f : t(k));
  const [params, setParams] = useSearchParams();
  const { data: scansRaw, isLoading, error, refetch } = useScansList();

  const scans = useMemo(() => [...(scansRaw ?? [])].sort(byNewest), [scansRaw]);
  const fallbackId = useMemo(
    () => (scans.find((s) => (s.vuln_count ?? 0) > 0) ?? scans[0])?.id ?? "",
    [scans],
  );
  const requested = params.get("scan") ?? "";
  const scanId = requested || fallbackId;
  const scope: ExplorationScope = params.get("scope") === "all" ? "all" : "findings";
  const current = scans.find((s) => s.id === scanId);

  // Pin the default choice into the URL so the view is shareable/deep-linkable.
  useEffect(() => {
    if (!requested && fallbackId) {
      const next = new URLSearchParams(params);
      next.set("scan", fallbackId);
      setParams(next, { replace: true });
    }
  }, [requested, fallbackId, params, setParams]);

  const update = (key: string, value: string | null) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: key === "scope" });
  };

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 font-sans text-2xl font-semibold tracking-tight">
            <Network className="h-5 w-5 text-muted-foreground" />
            {tr("exploration.title", "Exploration Graph")}
          </h1>
          <p className="text-sm text-muted-foreground">
            {tr(
              "exploration.subtitle",
              "How each finding was found — from discovery to injection to proof.",
            )}
          </p>
        </div>
        <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">
          {scans.length > 0 && (
            <Select value={scanId} onValueChange={(v) => update("scan", v)}>
              <SelectTrigger className="h-9 w-full sm:w-96">
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
      </header>

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
          onScopeChange={(s) => update("scope", s === "all" ? "all" : null)}
        />
      )}
    </div>
  );
}
