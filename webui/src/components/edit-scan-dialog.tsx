import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Info, KeyRound, Loader2, Lock, Pencil } from "lucide-react";
import { useScanConfig, useTokenProviders, useUpdateScanConfig } from "@/api/queries";
import type { ScanConfig, ScanEdit, ScanEditField } from "@/types/api";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PHASES } from "@/components/phase-progress";
import { cn } from "@/lib/utils";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

const APPLIES: Record<string, string> = {
  start: "Changes apply when the scan is started.",
  resume: "Changes apply when the scan is resumed. Targets and scan mode can't change while paused.",
  next_run:
    "Changes apply the next time you press Start. The completed run and its findings are not changed. Targets and scan mode are fixed for a scan that has run — start a new scan for different targets.",
};

type Form = {
  name: string;
  targets: string;
  scan_mode: string;
  instruction: string;
  phases: number[];
  recon_mode: string;
  scan_intensity: string;
  severity_filter: string[];
  company_name: string;
  target_auth: string; // "" = keep (unless clear flag)
  target_auth_b: string;
  clear_target_auth: boolean;
  clear_target_auth_b: boolean;
  token_provider: string;
  token_profile: string;
  token_profile_b: string;
};

function formFrom(c: ScanConfig): Form {
  const cfg = c.config;
  return {
    name: cfg.name ?? "",
    targets: (cfg.targets ?? []).join("\n"),
    scan_mode: cfg.scan_mode || "single",
    instruction: cfg.instruction ?? "",
    phases: cfg.phases?.length ? cfg.phases : PHASES.map((p) => p.id),
    recon_mode: cfg.recon_mode || "active",
    scan_intensity: cfg.scan_intensity || "active",
    severity_filter: cfg.severity_filter ?? [],
    company_name: cfg.company_name ?? "",
    target_auth: "",
    target_auth_b: "",
    clear_target_auth: false,
    clear_target_auth_b: false,
    token_provider: cfg.token_auth?.provider ?? "",
    token_profile: cfg.token_auth?.profile ?? "",
    token_profile_b: cfg.token_auth?.profile_b ?? "",
  };
}

function sameSet<T>(a: T[], b: T[]) {
  return a.length === b.length && [...a].sort().join() === [...b].sort().join();
}

/** Builds a minimal edit: only fields that changed and are editable. */
function diff(c: ScanConfig, f: Form, can: (k: ScanEditField) => boolean): ScanEdit {
  const cfg = c.config;
  const e: ScanEdit = { status: c.status };
  const allPhases = PHASES.map((p) => p.id);
  if (can("name") && f.name.trim() !== (cfg.name ?? "")) e.name = f.name.trim();
  const targets = f.targets.split(/[\n,]/).map((t) => t.trim()).filter(Boolean);
  if (can("targets") && targets.join("\n") !== (cfg.targets ?? []).join("\n")) e.targets = targets;
  if (can("scan_mode") && f.scan_mode !== (cfg.scan_mode || "single")) e.scan_mode = f.scan_mode;
  if (can("instruction") && f.instruction.trim() !== (cfg.instruction ?? "")) e.instruction = f.instruction.trim();
  const curPhases = cfg.phases?.length ? cfg.phases : allPhases;
  if (can("phases") && !sameSet(f.phases, curPhases)) e.phases = sameSet(f.phases, allPhases) ? [] : f.phases;
  if (can("recon_mode") && f.recon_mode !== (cfg.recon_mode || "active")) e.recon_mode = f.recon_mode;
  if (can("scan_intensity") && f.scan_intensity !== (cfg.scan_intensity || "active")) e.scan_intensity = f.scan_intensity;
  if (can("severity_filter") && !sameSet(f.severity_filter, cfg.severity_filter ?? [])) e.severity_filter = f.severity_filter;
  if (can("company_name") && f.company_name.trim() !== (cfg.company_name ?? "")) e.company_name = f.company_name.trim();
  if (can("target_auth")) {
    if (f.target_auth.trim()) e.target_auth = f.target_auth.trim();
    else if (f.clear_target_auth) e.target_auth = "";
  }
  if (can("target_auth_b")) {
    if (f.target_auth_b.trim()) e.target_auth_b = f.target_auth_b.trim();
    else if (f.clear_target_auth_b) e.target_auth_b = "";
  }
  if (can("token_auth")) {
    const cur = cfg.token_auth;
    const changed =
      (cur?.provider ?? "") !== f.token_provider ||
      (cur?.profile ?? "") !== f.token_profile ||
      (cur?.profile_b ?? "") !== f.token_profile_b;
    if (changed)
      e.token_auth = f.token_provider
        ? { provider: f.token_provider, profile: f.token_profile || undefined, profile_b: f.token_profile_b || undefined }
        : { provider: "" };
  }
  return e;
}

function Field({
  label,
  locked,
  children,
  hint,
}: {
  label: string;
  locked: boolean;
  children: ReactNode;
  hint?: ReactNode;
}) {
  return (
    <div className={cn("space-y-1.5", locked && "opacity-60")}>
      <Label className="flex items-center gap-1.5 text-xs">
        {label}
        {locked && <Lock className="h-3 w-3 text-muted-foreground" aria-label="locked" />}
      </Label>
      {children}
      {hint && <p className="text-[11px] text-muted-foreground">{hint}</p>}
    </div>
  );
}

/**
 * Edit a scan's configuration. What can change depends on the scan's state
 * (the server's policy): everything while saved; most settings while paused
 * or after it ran (targets and mode stay fixed); nothing while it runs.
 */
export function EditScanDialog({
  scanId,
  open,
  onOpenChange,
}: {
  scanId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { data, isLoading, error, refetch } = useScanConfig(scanId, open);
  const update = useUpdateScanConfig(scanId);
  const providers = useTokenProviders();
  const [form, setForm] = useState<Form | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (open) {
      setSaved(false);
      update.reset();
      void refetch();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);
  useEffect(() => {
    if (data && open) setForm(formFrom(data));
  }, [data, open]);

  const can = useMemo(() => {
    const set = new Set(data?.policy.editable ?? []);
    return (k: ScanEditField) => set.has(k);
  }, [data]);
  const locked = !!data && data.policy.editable.length === 0;
  const edit = data && form ? diff(data, form, can) : null;
  const changes = edit ? Object.keys(edit).filter((k) => k !== "status") : [];
  const noPhases = !!form && can("phases") && form.phases.length === 0;
  const providerList = providers.data ?? [];
  const profiles = Object.keys(providerList.find((p) => p.id === form?.token_provider)?.profiles ?? {}).sort();
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => (f ? { ...f, [k]: v } : f));

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] max-w-2xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Pencil className="h-4 w-4" /> Edit scan
          </DialogTitle>
          <DialogDescription>
            {data ? (
              <>
                Status: <span className="font-medium text-foreground">{data.status}</span>
              </>
            ) : (
              "Loading…"
            )}
          </DialogDescription>
        </DialogHeader>

        {isLoading || (!form && !error) ? (
          <div className="flex justify-center py-10">
            <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
          </div>
        ) : error ? (
          <p className="text-sm text-red-600 dark:text-red-400">{(error as Error).message}</p>
        ) : data && form ? (
          <div className="space-y-4">
            <div
              className={cn(
                "flex items-start gap-2 rounded-md border p-2.5 text-xs",
                locked ? "border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-300" : "border-border bg-muted/40",
              )}
            >
              {locked ? <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0" /> : <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />}
              <span>{locked ? data.policy.locked_reason : APPLIES[data.policy.applies_on ?? ""]}</span>
            </div>

            <fieldset disabled={locked} className="space-y-4">
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Name" locked={!can("name")}>
                  <Input value={form.name} disabled={!can("name")} onChange={(e) => set("name", e.target.value)} maxLength={200} />
                </Field>
                <Field label="Scan mode" locked={!can("scan_mode")}>
                  <Select value={form.scan_mode} disabled={!can("scan_mode")} onValueChange={(v) => set("scan_mode", v)}>
                    <SelectTrigger className="h-9">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="single">Single target</SelectItem>
                      <SelectItem value="wildcard">Wildcard (subdomains)</SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
              </div>

              <Field label="Targets" locked={!can("targets")} hint="One per line.">
                <Textarea
                  value={form.targets}
                  disabled={!can("targets")}
                  onChange={(e) => set("targets", e.target.value)}
                  rows={3}
                  className="font-mono text-xs"
                />
              </Field>

              <Field label="Instructions" locked={!can("instruction")}>
                <Textarea
                  value={form.instruction}
                  disabled={!can("instruction")}
                  onChange={(e) => set("instruction", e.target.value)}
                  rows={3}
                  className="text-xs"
                  placeholder="e.g. focus on /api/orders and IDOR between accounts"
                />
              </Field>

              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Recon" locked={!can("recon_mode")}>
                  <Select
                    value={form.recon_mode}
                    disabled={!can("recon_mode") || form.scan_intensity === "passive"}
                    onValueChange={(v) => set("recon_mode", v)}
                  >
                    <SelectTrigger className="h-9">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="active">Active</SelectItem>
                      <SelectItem value="passive">Passive</SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
                <Field label="Testing" locked={!can("scan_intensity")}>
                  <Select
                    value={form.scan_intensity}
                    disabled={!can("scan_intensity")}
                    onValueChange={(v) =>
                      setForm((f) => (f ? { ...f, scan_intensity: v, recon_mode: v === "passive" ? "passive" : f.recon_mode } : f))
                    }
                  >
                    <SelectTrigger className="h-9">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="active">Active</SelectItem>
                      <SelectItem value="passive">Passive</SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
              </div>

              <Field
                label={`Phases (${form.phases.length}/${PHASES.length})`}
                locked={!can("phases")}
                hint={
                  <span className="flex gap-2">
                    <button type="button" className="underline" onClick={() => set("phases", PHASES.map((p) => p.id))}>
                      All
                    </button>
                    <button type="button" className="underline" onClick={() => set("phases", [])}>
                      None
                    </button>
                  </span>
                }
              >
                <div className="grid max-h-40 grid-cols-1 gap-1 overflow-y-auto rounded-md border border-border p-2 sm:grid-cols-2">
                  {PHASES.map((p) => (
                    <label key={p.id} className="flex items-center gap-2 text-[11px]">
                      <input
                        type="checkbox"
                        disabled={!can("phases")}
                        checked={form.phases.includes(p.id)}
                        onChange={(e) =>
                          set(
                            "phases",
                            e.target.checked ? [...form.phases, p.id].sort((a, b) => a - b) : form.phases.filter((x) => x !== p.id),
                          )
                        }
                      />
                      <span className="tabular-nums text-muted-foreground">{p.id}.</span> {p.name}
                    </label>
                  ))}
                </div>
              </Field>

              <Field label="Report only these severities" locked={!can("severity_filter")} hint="None selected = all severities.">
                <div className="flex flex-wrap gap-1.5">
                  {SEVERITIES.map((sv) => {
                    const on = form.severity_filter.includes(sv);
                    return (
                      <button
                        key={sv}
                        type="button"
                        disabled={!can("severity_filter")}
                        onClick={() =>
                          set("severity_filter", on ? form.severity_filter.filter((x) => x !== sv) : [...form.severity_filter, sv])
                        }
                        className={cn(
                          "rounded-md border px-2 py-1 text-[11px] capitalize",
                          on ? "border-primary/60 bg-primary/10" : "border-border text-muted-foreground",
                        )}
                      >
                        {sv}
                      </button>
                    );
                  })}
                </div>
              </Field>

              <div className="space-y-3 rounded-md border border-border p-3">
                <p className="flex items-center gap-1.5 text-xs font-semibold">
                  <KeyRound className="h-3.5 w-3.5" /> Authentication
                </p>
                <Field label="Token provider" locked={!can("token_auth")}>
                  <div className="grid gap-2 sm:grid-cols-3">
                    <Select
                      value={form.token_provider || "__none"}
                      disabled={!can("token_auth")}
                      onValueChange={(v) => {
                        const id = v === "__none" ? "" : v;
                        const profs = Object.keys(providerList.find((p) => p.id === id)?.profiles ?? {}).sort();
                        setForm((f) => (f ? { ...f, token_provider: id, token_profile: profs[0] ?? "", token_profile_b: "" } : f));
                      }}
                    >
                      <SelectTrigger className="h-9 text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="__none">None</SelectItem>
                        {providerList.map((p) => (
                          <SelectItem key={p.id} value={p.id}>
                            {p.name || p.id}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    {form.token_provider && (
                      <Select value={form.token_profile} disabled={!can("token_auth")} onValueChange={(v) => set("token_profile", v)}>
                        <SelectTrigger className="h-9 text-xs">
                          <SelectValue placeholder="Role A profile" />
                        </SelectTrigger>
                        <SelectContent>
                          {profiles.map((n) => (
                            <SelectItem key={n} value={n}>
                              Role A: {n}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    )}
                    {form.token_provider && (
                      <Select
                        value={form.token_profile_b || "__none"}
                        disabled={!can("token_auth")}
                        onValueChange={(v) => set("token_profile_b", v === "__none" ? "" : v)}
                      >
                        <SelectTrigger className="h-9 text-xs">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="__none">No role B</SelectItem>
                          {profiles
                            .filter((n) => n !== form.token_profile)
                            .map((n) => (
                              <SelectItem key={n} value={n}>
                                Role B: {n}
                              </SelectItem>
                            ))}
                        </SelectContent>
                      </Select>
                    )}
                  </div>
                </Field>
                {!form.token_provider &&
                  (
                    [
                      ["target_auth", "clear_target_auth", "Session headers", data.config.has_target_auth],
                      ["target_auth_b", "clear_target_auth_b", "Second account (role B)", data.config.has_target_auth_b],
                    ] as const
                  ).map(([key, clearKey, label, has]) => (
                    <Field
                      key={key}
                      label={label}
                      locked={!can(key)}
                      hint={
                        has ? (
                          <label className="flex items-center gap-1.5">
                            <input
                              type="checkbox"
                              checked={form[clearKey]}
                              disabled={!can(key) || !!form[key].trim()}
                              onChange={(e) => set(clearKey, e.target.checked)}
                            />
                            Set — leave blank to keep it, type to replace, or tick to remove it.
                          </label>
                        ) : (
                          "Not set."
                        )
                      }
                    >
                      <Textarea
                        value={form[key]}
                        disabled={!can(key)}
                        onChange={(e) => set(key, e.target.value)}
                        rows={2}
                        autoComplete="off"
                        className="font-mono text-xs"
                        placeholder={has ? "•••••••• (stored, not shown)" : "Authorization: Bearer … or Cookie: …"}
                      />
                    </Field>
                  ))}
              </div>

              <Field label="Report company name" locked={!can("company_name")}>
                <Input value={form.company_name} disabled={!can("company_name")} onChange={(e) => set("company_name", e.target.value)} />
              </Field>
            </fieldset>

            {noPhases && <p className="text-xs text-amber-600 dark:text-amber-400">Select at least one phase.</p>}
            {update.error && (
              <p className="text-xs text-red-600 dark:text-red-400">{(update.error as Error).message}</p>
            )}
            {saved && !update.error && <p className="text-xs text-emerald-600 dark:text-emerald-400">Saved.</p>}
          </div>
        ) : null}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Close
          </Button>
          <Button
            disabled={!edit || changes.length === 0 || locked || noPhases || update.isPending}
            onClick={() =>
              edit &&
              update.mutate(edit, {
                onSuccess: (res) => {
                  setForm(formFrom(res));
                  setSaved(true);
                },
              })
            }
          >
            {update.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
            Save {changes.length > 0 ? `(${changes.length})` : ""}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
