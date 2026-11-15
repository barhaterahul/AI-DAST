import * as Popover from "@radix-ui/react-popover";
import { AlertTriangle, KeyRound, RefreshCw } from "lucide-react";
import { useEffect, useState } from "react";
import { useTokenStatus } from "@/api/queries";
import type { TokenRoleStatus } from "@/types/api";
import { cn } from "@/lib/utils";

function useNow(ms: number) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), ms);
    return () => window.clearInterval(t);
  }, [ms]);
  return now;
}

function expiresIn(expiry: string | undefined, now: number): string {
  if (!expiry) return "";
  const s = Math.round((new Date(expiry).getTime() - now) / 1000);
  if (!Number.isFinite(s)) return "";
  if (s <= 0) return "expired";
  if (s < 90) return `${s}s`;
  if (s < 5400) return `${Math.round(s / 60)}m`;
  return `${Math.round(s / 3600)}h`;
}

/**
 * Token-provider status for a scan: which provider/profiles it uses and, while
 * it runs, whether each role's token is valid, when it expires, and how often
 * it was refreshed. Renders nothing for scans without a token provider.
 */
export function TokenStatusBadge({ instanceId, running }: { instanceId: string; running: boolean }) {
  const { data } = useTokenStatus(instanceId, running);
  const now = useNow(5000);
  if (!data?.configured) return null;
  const roles: TokenRoleStatus[] = data.roles ?? [];
  const failing = roles.some((r) => !r.valid || r.failures > 0);
  const roleA = roles.find((r) => r.role === "A");
  const tone = !data.active
    ? "border-border text-muted-foreground"
    : failing
      ? "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400"
      : "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400";
  const label = !data.active
    ? `Token: ${data.selection?.provider}`
    : failing
      ? "Token: refresh failing"
      : `Token valid · ${expiresIn(roleA?.expiry, now)}`;

  return (
    <Popover.Root>
      <Popover.Trigger asChild>
        <button
          type="button"
          className={cn("inline-flex h-7 items-center gap-1.5 rounded-md border px-2 text-xs font-medium", tone)}
          aria-label="Token provider status"
        >
          {failing ? <AlertTriangle className="h-3.5 w-3.5" /> : <KeyRound className="h-3.5 w-3.5" />}
          {label}
        </button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          align="end"
          sideOffset={6}
          className="z-50 w-80 rounded-md border border-border bg-card p-3 text-xs shadow-lg"
        >
          <p className="mb-2 font-medium">
            Token provider <span className="font-mono">{data.selection?.provider}</span>
          </p>
          {!data.active && (
            <div className="space-y-1 text-muted-foreground">
              <p>
                Role A: <span className="font-mono">{data.selection?.profile || "—"}</span>
                {data.selection?.profile_b && (
                  <>
                    {" "}· Role B: <span className="font-mono">{data.selection.profile_b}</span>
                  </>
                )}
              </p>
              <p>Tokens are fetched when the scan runs.</p>
            </div>
          )}
          <div className="space-y-2">
            {roles.map((r) => (
              <div key={r.role} className="rounded border border-border p-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium">
                    Role {r.role} · <span className="font-mono">{r.profile}</span>
                  </span>
                  <span className={r.valid ? "text-emerald-600 dark:text-emerald-400" : "text-red-600 dark:text-red-400"}>
                    {r.valid ? "valid" : "invalid"}
                  </span>
                </div>
                <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-muted-foreground">
                  {r.token_preview && <code>{r.token_preview}</code>}
                  <span>expires in {expiresIn(r.expiry, now) || "?"}</span>
                  <span className="inline-flex items-center gap-1">
                    <RefreshCw className="h-3 w-3" /> {r.refreshes}
                  </span>
                  {r.failures > 0 && <span className="text-amber-600">{r.failures} failed</span>}
                </div>
                {r.last_error && <p className="mt-1 break-words text-red-600 dark:text-red-400">{r.last_error}</p>}
              </div>
            ))}
          </div>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}
