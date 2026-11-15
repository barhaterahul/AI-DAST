import { useMemo, useState } from "react";
import { AlertTriangle, ChevronDown, ChevronRight, KeyRound, Loader2, Search } from "lucide-react";
import { api } from "@/api/client";
import type { ContextPreview, ContextPreviewRequest } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn } from "@/lib/utils";

const METHOD_STYLE: Record<string, string> = {
  GET: "text-sky-600 dark:text-sky-400",
  POST: "text-emerald-600 dark:text-emerald-400",
  PUT: "text-amber-600 dark:text-amber-400",
  PATCH: "text-violet-600 dark:text-violet-400",
  DELETE: "text-red-600 dark:text-red-400",
};

/**
 * Preview of an uploaded Postman/Bruno collection (or any context): pick an
 * environment, fill unresolved {{variables}}, and include/exclude requests.
 * Every change is saved server-side next to the upload, so the scan tests
 * exactly what is shown here.
 */
export function CollectionPreview({
  preview,
  onChange,
  onUseTargets,
}: {
  preview: ContextPreview;
  onChange: (p: ContextPreview) => void;
  onUseTargets?: (urls: string[]) => void;
}) {
  const [env, setEnv] = useState(preview.env || preview.environment || "");
  const [vars, setVars] = useState<Record<string, string>>({});
  const [excluded, setExcluded] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState("");
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  // Excluded requests disappear from the server preview, so keep the full
  // list from the first (unfiltered) response for re-including them.
  const [allRequests, setAllRequests] = useState<ContextPreviewRequest[]>(preview.requests ?? []);

  const apply = async (next: { env?: string; vars?: Record<string, string>; excluded?: Set<string> }) => {
    setBusy(true);
    setErr(null);
    try {
      const res = await api.resolveCollection({
        path: preview.path,
        env: next.env ?? env,
        vars: next.vars ?? vars,
        exclude: [...(next.excluded ?? excluded)],
      });
      // Requests IDs depend on the resolved URL, so an env change can
      // re-key them; refresh the full list when nothing is excluded.
      if ((next.excluded ?? excluded).size === 0) setAllRequests(res.requests ?? []);
      onChange({ ...preview, ...res });
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Could not apply selection");
    } finally {
      setBusy(false);
    }
  };

  const groups = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const map = new Map<string, ContextPreviewRequest[]>();
    for (const r of allRequests) {
      if (q && !`${r.method} ${r.url} ${r.name ?? ""} ${r.folder ?? ""}`.toLowerCase().includes(q)) continue;
      const k = r.folder || "(root)";
      (map.get(k) ?? map.set(k, []).get(k)!).push(r);
    }
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [allRequests, filter]);

  const toggle = (ids: string[], include: boolean) => {
    const next = new Set(excluded);
    for (const id of ids) {
      if (include) next.delete(id);
      else next.add(id);
    }
    setExcluded(next);
    void apply({ excluded: next });
  };

  const envs = preview.environments ?? [];
  const missing = preview.missing_vars ?? [];
  const baseUrls = preview.base_url_list ?? [];
  const tokenCandidates = allRequests.filter((r) => r.token_candidate);

  return (
    <div className="space-y-3 rounded-md border border-border p-3">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="font-medium">{preview.endpoints} requests</span>
        {preview.formats?.map((f) => (
          <span key={f} className="rounded border border-border px-1.5 py-0.5 text-[10px] uppercase">
            {f}
          </span>
        ))}
        {preview.auth_headers && preview.auth_headers.length > 0 && (
          <span className="text-muted-foreground">auth: {preview.auth_headers.join(", ")}</span>
        )}
        {!!preview.scripts_skipped && (
          <span className="text-amber-600 dark:text-amber-400">{preview.scripts_skipped} script(s) skipped</span>
        )}
        {busy && <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />}
      </div>

      {envs.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <Label className="text-xs">Environment</Label>
          <Select
            value={env || preview.environment || envs[0]}
            onValueChange={(e) => {
              setEnv(e);
              setExcluded(new Set());
              void apply({ env: e, excluded: new Set() });
            }}
          >
            <SelectTrigger className="h-8 w-56 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {envs.map((e) => (
                <SelectItem key={e} value={e}>
                  {e}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}

      {missing.length > 0 && (
        <div className="space-y-2 rounded-md border border-amber-500/30 bg-amber-500/5 p-2">
          <p className="flex items-center gap-1.5 text-xs font-medium text-amber-700 dark:text-amber-400">
            <AlertTriangle className="h-3.5 w-3.5" /> {missing.length} variable(s) have no value
          </p>
          <div className="grid gap-2 sm:grid-cols-2">
            {missing.map((m) => (
              <div key={m} className="flex items-center gap-2">
                <span className="w-32 shrink-0 truncate font-mono text-[11px]" title={m}>
                  {m}
                </span>
                <Input
                  value={vars[m] ?? ""}
                  onChange={(e) => setVars({ ...vars, [m]: e.target.value })}
                  className="h-7 text-xs"
                  type={/token|secret|pass|key/i.test(m) ? "password" : "text"}
                  autoComplete="off"
                />
              </div>
            ))}
          </div>
          <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void apply({})}>
            Apply values
          </Button>
        </div>
      )}

      {baseUrls.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-muted-foreground">Hosts:</span>
          {baseUrls.map((u) => (
            <code key={u} className="rounded bg-muted px-1.5 py-0.5 text-[11px]">
              {u}
            </code>
          ))}
          {onUseTargets && (
            <Button type="button" size="sm" variant="ghost" className="h-7 text-xs" onClick={() => onUseTargets(baseUrls)}>
              Use as targets
            </Button>
          )}
        </div>
      )}

      {tokenCandidates.length > 0 && (
        <p className="flex items-start gap-1.5 text-[11px] text-muted-foreground">
          <KeyRound className="mt-0.5 h-3 w-3 shrink-0" />
          <span>
            {tokenCandidates.map((r) => r.name || r.url).join(", ")} look like token requests. For a JWT that needs
            refreshing, set up a <a href="/token-providers" className="underline">token provider</a> and select it
            under Authentication instead of relying on a token pasted into the collection.
          </span>
        </p>
      )}

      {allRequests.length > 0 && (
        <div className="space-y-2">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter requests…"
              className="h-8 pl-7 text-xs"
            />
          </div>
          <div className="max-h-80 overflow-y-auto rounded-md border border-border">
            {groups.map(([folder, reqs]) => {
              const ids = reqs.map((r) => r.id);
              const allOn = ids.every((id) => !excluded.has(id));
              const isOpen = open[folder] ?? groups.length <= 3;
              return (
                <div key={folder} className="border-b border-border last:border-b-0">
                  <div className="flex items-center gap-2 bg-muted/40 px-2 py-1.5">
                    <input
                      type="checkbox"
                      checked={allOn}
                      onChange={(e) => toggle(ids, e.target.checked)}
                      aria-label={`Include folder ${folder}`}
                    />
                    <button
                      type="button"
                      className="flex flex-1 items-center gap-1 text-left text-xs font-medium"
                      onClick={() => setOpen({ ...open, [folder]: !isOpen })}
                    >
                      {isOpen ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                      {folder}
                      <span className="font-normal text-muted-foreground">({reqs.length})</span>
                    </button>
                  </div>
                  {isOpen &&
                    reqs.map((r) => (
                      <label
                        key={r.id}
                        className={cn(
                          "flex cursor-pointer items-start gap-2 px-2 py-1.5 text-xs hover:bg-accent/30",
                          excluded.has(r.id) && "opacity-50",
                        )}
                      >
                        <input
                          type="checkbox"
                          className="mt-0.5"
                          checked={!excluded.has(r.id)}
                          onChange={(e) => toggle([r.id], e.target.checked)}
                        />
                        <span className={cn("w-14 shrink-0 font-mono font-semibold", METHOD_STYLE[r.method])}>
                          {r.method}
                        </span>
                        <span className="min-w-0 flex-1">
                          <span className="block truncate font-mono" title={r.url}>
                            {r.url}
                          </span>
                          <span className="block truncate text-[10px] text-muted-foreground">
                            {r.name}
                            {r.params && r.params.length > 0 &&
                              ` · ${r.params.map((p) => (p.location ? `${p.name} (${p.location})` : p.name)).join(", ")}`}
                            {r.body_mode && ` · ${r.body_mode}`}
                          </span>
                        </span>
                        {r.token_candidate && <KeyRound className="h-3 w-3 shrink-0 text-amber-500" aria-label="token request" />}
                      </label>
                    ))}
                </div>
              );
            })}
          </div>
          {preview.truncated && <p className="text-[11px] text-muted-foreground">Showing the first 500 requests.</p>}
        </div>
      )}

      {preview.notes && preview.notes.length > 0 && (
        <ul className="list-disc space-y-0.5 pl-4 text-[11px] text-muted-foreground">
          {preview.notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      )}
      {err && <p className="text-xs text-red-600 dark:text-red-400">{err}</p>}
    </div>
  );
}
