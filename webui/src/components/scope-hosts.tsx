import { AlertTriangle, Info } from "lucide-react";
import type { ContextHost, ContextPreview } from "@/types/api";
import { cn } from "@/lib/utils";

/** Bare lowercased hostname of a target ("https://a.b:8443/x", "a.b") or "". */
export function hostOf(target: string): string {
  const t = target.trim();
  if (!t) return "";
  try {
    return new URL(t.includes("://") ? t : `http://${t}`).hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return "";
  }
}

/**
 * Hosts referenced by the uploads, merged by base URL. A host counts as
 * first-party when any upload classifies it so (one upload may see more of
 * the app than another).
 */
export function mergeUploadHosts(...previews: Array<ContextPreview | null | undefined>): ContextHost[] {
  const byBase = new Map<string, ContextHost>();
  for (const p of previews) {
    for (const h of p?.hosts ?? []) {
      const cur = byBase.get(h.base_url);
      if (!cur) {
        byBase.set(h.base_url, { ...h });
        continue;
      }
      cur.requests += h.requests;
      if (!h.third_party) {
        cur.third_party = false;
        cur.reason = undefined;
      }
    }
  }
  return [...byBase.values()].sort(
    (a, b) => Number(a.third_party) - Number(b.third_party) || b.requests - a.requests || a.base_url.localeCompare(b.base_url),
  );
}

/**
 * Scope derived from typed targets + upload hosts. Defaults: when the
 * operator typed targets, only upload hosts matching them are in scope (the
 * typed list states intent, e.g. "staging, not the prod URL in the
 * collection"); otherwise first-party hosts are. Explicit toggles win.
 */
export function computeScope(typed: string[], hosts: ContextHost[], overrides: Record<string, boolean>) {
  const typedHosts = new Set(typed.map(hostOf).filter(Boolean));
  const isDefault = (h: ContextHost) => (typedHosts.size ? typedHosts.has(h.host) : !h.third_party);
  const checked = (h: ContextHost) => overrides[h.base_url] ?? isDefault(h);
  const finalTargets = [...typed];
  const seen = new Set(typedHosts);
  for (const h of hosts) {
    if (checked(h) && !seen.has(h.host)) {
      seen.add(h.host);
      finalTargets.push(h.base_url);
    }
  }
  const uploadHostNames = new Set(hosts.map((h) => h.host));
  const skippedRequests = hosts.filter((h) => !seen.has(h.host)).reduce((n, h) => n + h.requests, 0);
  const unusedTyped = hosts.length ? typed.filter((t) => hostOf(t) && !uploadHostNames.has(hostOf(t))) : [];
  return { finalTargets, checked, skippedRequests, unusedTyped };
}

export function ScopeHostList({
  hosts,
  checked,
  onToggle,
  environment,
  unresolved,
  skippedRequests,
  unusedTyped,
}: {
  hosts: ContextHost[];
  checked: (h: ContextHost) => boolean;
  onToggle: (h: ContextHost, on: boolean) => void;
  environment?: string;
  unresolved: number;
  skippedRequests: number;
  unusedTyped: string[];
}) {
  if (!hosts.length && !unresolved) return null;
  return (
    <div className="space-y-2 rounded-md border border-border p-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <span className="text-xs font-medium">Hosts from your uploads</span>
        {environment && (
          <span className="text-[11px] text-muted-foreground">
            environment: <span className="mono text-foreground">{environment}</span>
          </span>
        )}
      </div>
      {hosts.length > 0 && (
        <ul className="divide-y divide-border rounded border border-border">
          {hosts.map((h) => {
            const on = checked(h);
            return (
              <li key={h.base_url}>
                <label className="flex cursor-pointer items-center gap-2 px-2.5 py-1.5 text-xs hover:bg-muted/40">
                  <input
                    type="checkbox"
                    className="h-3.5 w-3.5 accent-primary"
                    checked={on}
                    onChange={(e) => onToggle(h, e.target.checked)}
                  />
                  <span className={cn("mono min-w-0 flex-1 truncate", !on && "text-muted-foreground")}>{h.base_url}</span>
                  {h.third_party && (
                    <span
                      title={h.reason}
                      className="shrink-0 rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-[10px] text-amber-700 dark:text-amber-300"
                    >
                      third-party
                    </span>
                  )}
                  <span className="w-20 shrink-0 text-right text-[11px] text-muted-foreground">
                    {h.requests} request{h.requests === 1 ? "" : "s"}
                  </span>
                </label>
              </li>
            );
          })}
        </ul>
      )}
      <p className="text-[11px] text-muted-foreground text-pretty">
        Ticked hosts are scanned. Requests to unticked hosts are removed from the attack surface — third-party services
        (identity providers, payment gateways, other domains) stay unticked unless you own them and are authorized to test them.
      </p>
      {skippedRequests > 0 && (
        <p className="flex items-start gap-1.5 text-[11px] text-muted-foreground">
          <Info className="mt-px h-3 w-3 shrink-0" />
          {skippedRequests} request{skippedRequests === 1 ? "" : "s"} on unticked hosts will be skipped.
        </p>
      )}
      {unresolved > 0 && (
        <p className="flex items-start gap-1.5 text-[11px] text-amber-700 dark:text-amber-300">
          <AlertTriangle className="mt-px h-3 w-3 shrink-0" />
          {unresolved} request{unresolved === 1 ? "" : "s"} still use a host variable such as{" "}
          <code>{"{{baseUrl}}"}</code> — choose an environment or set the variable in the collection below, otherwise
          they are skipped.
        </p>
      )}
      {unusedTyped.length > 0 && (
        <p className="flex items-start gap-1.5 text-[11px] text-muted-foreground">
          <Info className="mt-px h-3 w-3 shrink-0" />
          <span>
            <span className="mono">{unusedTyped.join(", ")}</span> {unusedTyped.length === 1 ? "isn't" : "aren't"} used by
            any uploaded request. To test the collection against it, set the collection&apos;s host variable to it below.
          </span>
        </p>
      )}
    </div>
  );
}
