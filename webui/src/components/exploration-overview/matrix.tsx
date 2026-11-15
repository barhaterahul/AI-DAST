import { useMemo, useState } from "react";
import { Grid3x3 } from "lucide-react";
import type { ExplorationOverview, OverviewTarget } from "@/types/api";
import { cn } from "@/lib/utils";
import { truncate } from "@/components/exploration-graph/meta";
import { EmptyState } from "@/components/states";
import { StatusDot } from "./primitives";
import { bySeverity, hostLabel, topSeverityColor, useTr } from "./shared";

// Target × vulnerability-class heatmap. Cell colour = top severity of that
// class on that target; opacity scales with the finding count.

type Cell = ExplorationOverview["matrix"]["cells"][number];

export function OverviewMatrix({
  targets,
  matrix,
  onOpenScan,
  className,
}: {
  targets: OverviewTarget[];
  matrix: ExplorationOverview["matrix"] | null | undefined;
  onOpenScan: (scanId: string) => void;
  className?: string;
}) {
  const tr = useTr();
  const [hover, setHover] = useState<{ row: string | null; col: string | null }>({ row: null, col: null });
  const classes = matrix?.classes ?? [];

  const { cells, max } = useMemo(() => {
    const m = new Map<string, Cell>();
    let mx = 0;
    for (const c of matrix?.cells ?? []) {
      if (!c || c.count <= 0) continue;
      m.set(`${c.target}\u0000${c.class}`, c);
      mx = Math.max(mx, c.count);
    }
    return { cells: m, max: mx };
  }, [matrix]);

  const rows = useMemo(() => [...targets].sort(bySeverity), [targets]);

  if (classes.length === 0) {
    return (
      <EmptyState
        className={className}
        icon={<Grid3x3 className="h-6 w-6" />}
        title={tr("exploration.overview.matrixEmpty", "No vulnerability classes yet")}
        description={tr(
          "exploration.overview.matrixEmptyHint",
          "The matrix fills in once scans report findings.",
        )}
      />
    );
  }

  return (
    <div
      className={cn("overflow-x-auto rounded-md border border-border bg-card", className)}
      onMouseLeave={() => setHover({ row: null, col: null })}
    >
      <table className="w-max min-w-full border-separate border-spacing-0 text-xs">
        <caption className="sr-only">
          {tr("exploration.overview.matrixCaption", "Findings per target and vulnerability class")}
        </caption>
        <thead>
          <tr>
            <th
              scope="col"
              className="sticky left-0 top-0 z-20 border-b border-r border-border bg-card px-3 py-2 text-left font-medium text-muted-foreground"
            >
              {tr("exploration.overview.target", "Target")}
            </th>
            {classes.map((c) => (
              <th
                key={c}
                scope="col"
                className={cn(
                  "border-b border-border px-1 py-2 text-center align-bottom font-mono text-[11px] font-medium transition-colors",
                  hover.col === c ? "bg-accent text-foreground" : "text-muted-foreground",
                )}
                title={c}
              >
                <span className="inline-block max-w-[7rem] truncate">{truncate(c, 18)}</span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((t) => {
            const host = hostLabel(t);
            const rowHot = hover.row === t.key;
            return (
              <tr key={t.key}>
                <th
                  scope="row"
                  className={cn(
                    "sticky left-0 z-10 max-w-[16rem] border-b border-r border-border px-3 py-1.5 text-left font-normal transition-colors",
                    rowHot ? "bg-accent" : "bg-card",
                  )}
                >
                  <span className="flex min-w-0 items-center gap-2">
                    <StatusDot status={t.latest_status} />
                    <span className="truncate font-mono" title={t.label || host}>
                      {host}
                    </span>
                    <span className="ml-auto shrink-0 pl-2 tabular-nums text-muted-foreground">{t.findings}</span>
                  </span>
                </th>
                {classes.map((c) => {
                  const cell = cells.get(`${t.key}\u0000${c}`);
                  const lit = rowHot || hover.col === c;
                  if (!cell) {
                    return (
                      <td
                        key={c}
                        className={cn("border-b border-border p-0.5 transition-colors", lit && "bg-accent/50")}
                        onMouseEnter={() => setHover({ row: t.key, col: c })}
                      >
                        <span className="block h-7 min-w-10" aria-hidden />
                      </td>
                    );
                  }
                  const color = topSeverityColor(cell.top_severity);
                  const alpha = max > 0 ? 0.25 + 0.65 * (cell.count / max) : 0.6;
                  const pct = Math.round(alpha * 100);
                  const label = `${host} · ${c}: ${cell.count} finding${cell.count === 1 ? "" : "s"}${cell.top_severity ? `, ${cell.top_severity}` : ""}`;
                  return (
                    <td
                      key={c}
                      className={cn("border-b border-border p-0.5 transition-colors", lit && "bg-accent/50")}
                      onMouseEnter={() => setHover({ row: t.key, col: c })}
                    >
                      <button
                        type="button"
                        onClick={() => t.latest_scan_id && onOpenScan(t.latest_scan_id)}
                        onFocus={() => setHover({ row: t.key, col: c })}
                        disabled={!t.latest_scan_id}
                        aria-label={`${label}. ${tr("exploration.overview.openGraph", "Open graph")}`}
                        title={label}
                        className={cn(
                          "flex h-7 w-full min-w-10 items-center justify-center rounded text-[11px] font-semibold tabular-nums transition-transform",
                          "hover:scale-105 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                          alpha > 0.55 ? "text-white" : "text-foreground",
                        )}
                        style={{
                          backgroundColor: `color-mix(in srgb, ${color} ${pct}%, transparent)`,
                          boxShadow: lit ? `inset 0 0 0 1px ${color}` : undefined,
                        }}
                      >
                        {cell.count}
                      </button>
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
