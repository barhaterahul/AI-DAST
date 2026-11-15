import { Check } from "lucide-react";
import type { OverviewTarget, SeverityCounts } from "@/types/api";
import { cn } from "@/lib/utils";
import { BACKEND_ICONS, SEVERITY_COLORS, truncate } from "@/components/exploration-graph/meta";
import { SEV_ORDER, severityTotal, statusDotClass, statusLabel } from "./shared";

// Small presentational building blocks shared by the map node, the cards and
// the details panel.

/** Stacked horizontal bar of severity counts. */
export function SeverityBar({
  counts,
  className,
  label,
}: {
  counts?: SeverityCounts | null;
  className?: string;
  label?: string;
}) {
  const total = severityTotal(counts);
  const summary = SEV_ORDER.filter((s) => (counts?.[s] ?? 0) > 0)
    .map((s) => `${counts?.[s] ?? 0} ${s}`)
    .join(", ");
  return (
    <div
      role="img"
      aria-label={label ?? (total ? summary : "No findings")}
      title={total ? summary : "No findings"}
      className={cn("flex h-1.5 w-full overflow-hidden rounded-full bg-muted", className)}
    >
      {total > 0 &&
        SEV_ORDER.map((s) => {
          const n = counts?.[s] ?? 0;
          if (!n) return null;
          return (
            <span
              key={s}
              className="h-full"
              style={{ width: `${(n / total) * 100}%`, backgroundColor: SEVERITY_COLORS[s] }}
            />
          );
        })}
    </div>
  );
}

export function StatusDot({ status, className }: { status?: string; className?: string }) {
  const label = statusLabel(status);
  return (
    <span
      role="img"
      aria-label={`Status: ${label}`}
      title={label}
      className={cn("inline-block h-2 w-2 shrink-0 rounded-full", statusDotClass(status), className)}
    />
  );
}

/** Small technology chips (database, server, …) for a target. */
export function TechChips({
  backend,
  max = 3,
  className,
}: {
  backend: OverviewTarget["backend"] | null | undefined;
  max?: number;
  className?: string;
}) {
  const list = backend ?? [];
  if (list.length === 0) return null;
  const shown = list.slice(0, max);
  const rest = list.length - shown.length;
  return (
    <div className={cn("flex min-w-0 flex-wrap items-center gap-1", className)}>
      {shown.map((b, i) => {
        const Icon = BACKEND_ICONS[b.category] ?? BACKEND_ICONS.other;
        return (
          <span
            key={`${b.name}-${i}`}
            title={`${b.name} (${b.category || "other"})`}
            className="inline-flex max-w-[9rem] items-center gap-1 rounded border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-px text-[10px] text-emerald-700 dark:text-emerald-300"
          >
            <Icon className="h-2.5 w-2.5 shrink-0" aria-hidden />
            <span className="truncate">{truncate(b.name, 24)}</span>
          </span>
        );
      })}
      {rest > 0 && <span className="text-[10px] text-muted-foreground">+{rest}</span>}
    </div>
  );
}

/** Accessible checkbox used to add a target to the compare selection. */
export function CompareCheckbox({
  checked,
  disabled,
  onToggle,
  label,
  className,
}: {
  checked: boolean;
  disabled?: boolean;
  onToggle: () => void;
  label: string;
  className?: string;
}) {
  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={checked}
      aria-label={label}
      title={label}
      disabled={disabled && !checked}
      onClick={(e) => {
        e.stopPropagation();
        onToggle();
      }}
      onPointerDown={(e) => e.stopPropagation()}
      className={cn(
        "nodrag nopan flex h-4 w-4 shrink-0 items-center justify-center rounded border transition-colors",
        "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-40",
        checked
          ? "border-sky-500 bg-sky-500 text-white"
          : "border-border bg-background/80 hover:border-foreground/50",
        className,
      )}
    >
      {checked && <Check className="h-3 w-3" strokeWidth={3} aria-hidden />}
    </button>
  );
}
