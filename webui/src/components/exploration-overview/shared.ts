import { useCallback } from "react";
import type { OverviewLinkKind, OverviewTarget, SeverityCounts } from "@/types/api";
import { normalizeSeverity, severityRank } from "@/lib/utils";
import { useI18n } from "@/i18n";
import { SEVERITY_COLORS } from "@/components/exploration-graph/meta";

// Shared vocabulary for the multi-target Exploration overview (map, cards,
// matrix). Every string that comes from a scan is untrusted and is rendered
// as plain React text only.

/** Maximum number of scans the combined (compare) view accepts. */
export const MAX_COMPARE = 8;

/** Above this many targets the map switches from rings to a grid. */
export const GRID_THRESHOLD = 120;

/** Size of a target card on the map. */
export const TARGET_NODE_W = 224;
export const TARGET_NODE_H = 108;

export type OverviewMode = "map" | "cards" | "matrix";
export const OVERVIEW_MODES: OverviewMode[] = ["map", "cards", "matrix"];

export function parseMode(v: string | null): OverviewMode {
  return v === "cards" || v === "matrix" ? v : "map";
}

export function useTr() {
  const { t } = useI18n();
  return useCallback((k: string, f: string) => (t(k) === k ? f : t(k)), [t]);
}

// ---- severity ----------------------------------------------------------------

export type SevKey = "critical" | "high" | "medium" | "low" | "info";
export const SEV_ORDER: SevKey[] = ["critical", "high", "medium", "low", "info"];

/** Neutral accent for targets without any finding. */
export const NONE_COLOR = "#64748b";

/** Accent for a top severity; "" (no findings) maps to a neutral slate. */
export function topSeverityColor(sev?: string): string {
  if (!sev) return NONE_COLOR;
  return SEVERITY_COLORS[normalizeSeverity(sev)];
}

/** Rank where "" (no findings) sorts below info. */
export function topRank(sev?: string): number {
  return sev ? severityRank(sev) + 1 : 0;
}

export function severityTotal(c?: SeverityCounts | null): number {
  if (!c) return 0;
  return (c.critical || 0) + (c.high || 0) + (c.medium || 0) + (c.low || 0) + (c.info || 0);
}

// ---- links -------------------------------------------------------------------

export interface LinkKindMeta {
  label: string;
  color: string;
  description: string;
}

export const LINK_KINDS: OverviewLinkKind[] = [
  "shared_backend",
  "shared_vuln_class",
  "shared_auth",
  "shared_infra",
];

export const LINK_META: Record<OverviewLinkKind, LinkKindMeta> = {
  shared_backend: {
    label: "Shared backend",
    color: "#10b981",
    description: "Same detected technology",
  },
  shared_vuln_class: {
    label: "Shared vuln class",
    color: "#f97316",
    description: "Same vulnerability class found on both",
  },
  shared_auth: {
    label: "Shared auth",
    color: "#8b5cf6",
    description: "Same token provider or default credential",
  },
  shared_infra: {
    label: "Shared infra",
    color: "#64748b",
    description: "Same host/port family or server banner",
  },
};

export function linkMeta(kind: string): LinkKindMeta {
  return LINK_META[kind as OverviewLinkKind] ?? LINK_META.shared_infra;
}

// ---- status ------------------------------------------------------------------

export function statusDotClass(status?: string): string {
  switch ((status || "").toLowerCase()) {
    case "running":
      return "bg-emerald-500 motion-safe:animate-pulse";
    case "pending":
    case "paused":
      return "bg-amber-500";
    case "failed":
    case "stopped":
      return "bg-red-500";
    case "saved":
      return "bg-blue-500";
    default:
      return "bg-zinc-400 dark:bg-zinc-500";
  }
}

export function statusLabel(status?: string): string {
  const s = (status || "").toLowerCase();
  if (!s) return "Unknown";
  if (s === "finished") return "Completed";
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// ---- misc --------------------------------------------------------------------

/** Display label for a target: its key (host) when present, else the label. */
export function hostLabel(t: Pick<OverviewTarget, "key" | "label">): string {
  return t.key || t.label || "—";
}

/** Sort comparator: most severe first, then most findings, then name. */
export function bySeverity(a: OverviewTarget, b: OverviewTarget): number {
  return (
    topRank(b.top_severity) - topRank(a.top_severity) ||
    (b.findings || 0) - (a.findings || 0) ||
    hostLabel(a).localeCompare(hostLabel(b))
  );
}

/** Top classes of a target, most frequent first. */
export function topClasses(t: OverviewTarget, n = 3): [string, number][] {
  return Object.entries(t.vuln_classes ?? {})
    .filter(([, c]) => c > 0)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, n);
}

export function timeMs(iso?: string): number {
  if (!iso) return 0;
  const t = new Date(iso).getTime();
  return Number.isNaN(t) ? 0 : t;
}
