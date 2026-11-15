import { useMemo, useState } from "react";
import { ChevronDown, ChevronUp, Link2, X } from "lucide-react";
import type { OverviewLink } from "@/types/api";
import { cn } from "@/lib/utils";
import { truncate } from "@/components/exploration-graph/meta";
import { linkMeta, useTr } from "./shared";

// "What do my targets have in common?" — links aggregated by (kind, label)
// with the number of distinct targets involved. Clicking an item highlights
// those targets and links on the map.

export interface SharedItem {
  id: string;
  kind: string;
  label: string;
  targets: string[];
  linkIds: string[];
}

export function aggregateLinks(links: OverviewLink[]): SharedItem[] {
  const by = new Map<string, { kind: string; label: string; targets: Set<string>; linkIds: string[] }>();
  for (const l of links) {
    const label = l.label || linkMeta(l.kind).label;
    const id = `${l.kind}\u0000${label}`;
    let e = by.get(id);
    if (!e) {
      e = { kind: l.kind, label, targets: new Set(), linkIds: [] };
      by.set(id, e);
    }
    e.targets.add(l.source);
    e.targets.add(l.target);
    e.linkIds.push(l.id);
  }
  return [...by.entries()]
    .map(([id, e]) => ({ id, kind: e.kind, label: e.label, targets: [...e.targets].sort(), linkIds: e.linkIds }))
    .sort((a, b) => b.targets.length - a.targets.length || a.label.localeCompare(b.label));
}

const COLLAPSED_LIMIT = 10;

export function LinksPanel({
  items,
  activeId,
  onSelect,
  className,
}: {
  items: SharedItem[];
  activeId: string | null;
  onSelect: (item: SharedItem | null) => void;
  className?: string;
}) {
  const tr = useTr();
  const [open, setOpen] = useState(true);
  const [all, setAll] = useState(false);
  const shown = useMemo(() => (all ? items : items.slice(0, COLLAPSED_LIMIT)), [items, all]);

  return (
    <section
      className={cn("rounded-md border border-border bg-card text-card-foreground", className)}
      aria-label={tr("exploration.overview.shared", "Shared across targets")}
    >
      <div className="flex items-center gap-2 px-3 py-2">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
          className="flex flex-1 items-center gap-2 text-left text-xs font-medium focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
        >
          <Link2 className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
          {tr("exploration.overview.shared", "Shared across targets")}
          <span className="tabular-nums text-muted-foreground">({items.length})</span>
          <span className="ml-auto text-muted-foreground">
            {open ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
          </span>
        </button>
        {activeId && (
          <button
            type="button"
            onClick={() => onSelect(null)}
            className="rounded p-0.5 text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            aria-label={tr("exploration.overview.clearHighlight", "Clear highlight")}
            title={tr("exploration.overview.clearHighlight", "Clear highlight")}
          >
            <X className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
      {open && (
        <div className="border-t border-border p-1.5">
          {items.length === 0 ? (
            <p className="px-1.5 py-2 text-xs text-muted-foreground">
              {tr("exploration.overview.noShared", "No shared backends, classes or auth between these targets.")}
            </p>
          ) : (
            <ul className="space-y-0.5">
              {shown.map((it) => {
                const m = linkMeta(it.kind);
                const active = activeId === it.id;
                return (
                  <li key={it.id}>
                    <button
                      type="button"
                      aria-pressed={active}
                      onClick={() => onSelect(active ? null : it)}
                      className={cn(
                        "flex w-full items-center gap-2 rounded px-1.5 py-1 text-left text-xs transition-colors",
                        "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
                        active ? "bg-accent text-accent-foreground" : "hover:bg-accent/60",
                      )}
                      title={`${m.label}: ${it.label}`}
                    >
                      <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: m.color }} aria-hidden />
                      <span className="min-w-0 flex-1 truncate">{truncate(it.label, 40)}</span>
                      <span className="shrink-0 tabular-nums text-muted-foreground">
                        {it.targets.length} {tr("exploration.overview.targetsShort", "targets")}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
          {items.length > COLLAPSED_LIMIT && (
            <button
              type="button"
              onClick={() => setAll((a) => !a)}
              className="mt-1 w-full rounded px-1.5 py-1 text-left text-[11px] text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            >
              {all
                ? tr("exploration.overview.showLess", "Show less")
                : `${tr("exploration.overview.showAll", "Show all")} (${items.length})`}
            </button>
          )}
        </div>
      )}
    </section>
  );
}
