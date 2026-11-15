import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  BadgeCheck,
  KeyRound,
  Loader2,
  Play,
  Plus,
  Save,
  Trash2,
  X,
  XCircle,
} from "lucide-react";
import {
  useDeleteTokenProvider,
  useSaveTokenProvider,
  useTestTokenProvider,
  useTokenProviders,
} from "@/api/queries";
import type { TokenProvider, TokenRequestSpec, TokenTestResult, TokenTestStep } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { EmptyState, ErrorState } from "@/components/states";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

// Token Providers: configure a custom token API (request template + where the
// token lives in the response), named parameter profiles (one per identity),
// and test it — the result shows the decoded JWT claims and expiry.

const MASK = "********";

function blankProvider(): TokenProvider {
  return {
    id: "",
    name: "",
    request: {
      method: "POST",
      url: "https://auth.example.com/api/token",
      body_type: "json",
      body: { clientId: "{{clientId}}", secret: "{{secret:clientSecret}}", userId: "{{userId}}" },
    },
    extract: { token: "$.access_token", refresh_token: "$.refresh_token", expires_in: "$.expires_in" },
    apply: { header: "Authorization", format: "Bearer {{token}}" },
    refresh: {
      request: {
        method: "POST",
        url: "https://auth.example.com/api/token/refresh",
        body_type: "json",
        body: { refreshToken: "{{refresh_token}}" },
      },
      before_expiry_seconds: 60,
      max_ttl_seconds: 900,
      on_status: [401],
    },
    secrets: { clientSecret: "" },
    profiles: { user_a: { clientId: "", userId: "" } },
  };
}

const RESERVED = new Set(["token", "access_token", "refresh_token"]);

/** Mirrors the server's Placeholders(): {{name}} referenced by the templates. */
function placeholdersOf(p: TokenProvider): string[] {
  const seen = new Set<string>();
  const collect = (s: string) => {
    for (const m of s.matchAll(/\{\{\s*([a-zA-Z0-9_.:-]+)\s*\}\}/g)) {
      const n = m[1];
      if (!n.startsWith("secret:") && !RESERVED.has(n)) seen.add(n);
    }
  };
  const walk = (v: unknown) => {
    if (typeof v === "string") collect(v);
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object")
      for (const [k, val] of Object.entries(v)) {
        collect(k);
        walk(val);
      }
  };
  for (const r of [p.request, p.refresh?.request].filter(Boolean) as TokenRequestSpec[]) {
    collect(r.url);
    walk(r.headers ?? {});
    walk(r.body);
  }
  return [...seen].sort();
}

function secretNamesOf(p: TokenProvider): string[] {
  const out = new Set<string>(Object.keys(p.secrets ?? {}));
  const s = JSON.stringify([p.request, p.refresh?.request ?? null]);
  for (const m of s.matchAll(/\{\{\s*secret:([a-zA-Z0-9_.-]+)\s*\}\}/g)) out.add(m[1]);
  return [...out].sort();
}

export default function TokenProvidersPage() {
  const { data, isLoading, error, refetch } = useTokenProviders();
  const [selected, setSelected] = useState<string | "new" | null>(null);
  const providers = data ?? [];

  useEffect(() => {
    if (selected === null && providers.length > 0) setSelected(providers[0].id);
  }, [providers, selected]);

  const current =
    selected === "new" ? blankProvider() : providers.find((p) => p.id === selected) ?? null;

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <KeyRound className="h-5 w-5 text-muted-foreground" /> Token Providers
          </h1>
          <p className="text-sm text-muted-foreground">
            Get scan credentials (e.g. a JWT) from your token API. Tokens are fetched before a scan starts, sent
            on every request and refreshed automatically.
          </p>
        </div>
        <Button size="sm" onClick={() => setSelected("new")}>
          <Plus className="h-3.5 w-3.5" /> New provider
        </Button>
      </header>

      {isLoading ? (
        <Skeleton className="h-96 w-full" />
      ) : error ? (
        <ErrorState
          description={error instanceof Error ? error.message : undefined}
          action={
            <Button size="sm" variant="outline" onClick={() => refetch()}>
              Retry
            </Button>
          }
        />
      ) : providers.length === 0 && selected !== "new" ? (
        <EmptyState
          icon={<KeyRound className="h-6 w-6" />}
          title="No token providers yet"
          description="Add your token API once, define a profile per identity (user, tenant, role), then pick it when starting a scan."
          action={
            <Button size="sm" onClick={() => setSelected("new")}>
              <Plus className="h-3.5 w-3.5" /> New provider
            </Button>
          }
        />
      ) : (
        <div className="grid gap-4 lg:grid-cols-[240px_minmax(0,1fr)]">
          <nav className="space-y-1">
            {providers.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => setSelected(p.id)}
                className={cn(
                  "flex w-full flex-col rounded-md border px-3 py-2 text-left text-sm transition-colors",
                  selected === p.id ? "border-primary/50 bg-primary/5" : "border-border hover:bg-accent/40",
                )}
              >
                <span className="font-medium">{p.name || p.id}</span>
                <span className="truncate font-mono text-[11px] text-muted-foreground">{p.request.url}</span>
                <span className="text-[11px] text-muted-foreground">
                  {Object.keys(p.profiles ?? {}).length} profile(s)
                </span>
              </button>
            ))}
            {selected === "new" && (
              <div className="rounded-md border border-dashed border-primary/50 px-3 py-2 text-sm text-muted-foreground">
                New provider…
              </div>
            )}
          </nav>
          {current && (
            <ProviderEditor
              key={selected ?? "none"}
              initial={current}
              isNew={selected === "new"}
              onSaved={(id) => setSelected(id)}
              onDeleted={() => setSelected(null)}
            />
          )}
        </div>
      )}
    </div>
  );
}

function JsonField({
  label,
  value,
  onChange,
  hint,
}: {
  label: string;
  value: unknown;
  onChange: (v: unknown, valid: boolean) => void;
  hint?: string;
}) {
  const [text, setText] = useState(() =>
    typeof value === "string" ? value : JSON.stringify(value ?? {}, null, 2),
  );
  const [err, setErr] = useState<string | null>(null);
  return (
    <div className="space-y-1">
      <Label className="text-xs">{label}</Label>
      <Textarea
        value={text}
        spellCheck={false}
        rows={6}
        className="font-mono text-xs"
        onChange={(e) => {
          setText(e.target.value);
          try {
            const v = e.target.value.trim() ? JSON.parse(e.target.value) : null;
            setErr(null);
            onChange(v, true);
          } catch (ex) {
            setErr((ex as Error).message);
            onChange(null, false);
          }
        }}
      />
      {err ? (
        <p className="text-[11px] text-red-600 dark:text-red-400">Invalid JSON: {err}</p>
      ) : (
        hint && <p className="text-[11px] text-muted-foreground">{hint}</p>
      )}
    </div>
  );
}

function RequestFields({
  title,
  spec,
  onChange,
  onValidity,
}: {
  title: string;
  spec: TokenRequestSpec;
  onChange: (s: TokenRequestSpec) => void;
  onValidity: (ok: boolean) => void;
}) {
  return (
    <div className="space-y-3">
      <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">{title}</p>
      <div className="grid gap-2 sm:grid-cols-[110px_minmax(0,1fr)_120px]">
        <Select value={spec.method} onValueChange={(v) => onChange({ ...spec, method: v })}>
          <SelectTrigger className="h-9">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {["POST", "GET", "PUT", "PATCH"].map((m) => (
              <SelectItem key={m} value={m}>
                {m}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Input
          value={spec.url}
          onChange={(e) => onChange({ ...spec, url: e.target.value })}
          className="font-mono text-xs"
          placeholder="https://auth.example.com/api/token"
        />
        <Select
          value={spec.body_type ?? "json"}
          onValueChange={(v) => onChange({ ...spec, body_type: v as TokenRequestSpec["body_type"] })}
        >
          <SelectTrigger className="h-9">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="json">JSON body</SelectItem>
            <SelectItem value="form">Form body</SelectItem>
            <SelectItem value="raw">Raw body</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        <JsonField
          label="Body"
          value={spec.body}
          hint="Use {{param}} for profile values and {{secret:name}} for secrets."
          onChange={(v, ok) => {
            onValidity(ok);
            if (ok) onChange({ ...spec, body: v ?? undefined });
          }}
        />
        <JsonField
          label="Headers"
          value={spec.headers ?? {}}
          hint='Object of header → value, e.g. {"X-Client": "dast"}.'
          onChange={(v, ok) => {
            onValidity(ok);
            if (ok) onChange({ ...spec, headers: (v as Record<string, string>) ?? undefined });
          }}
        />
      </div>
    </div>
  );
}

function ProviderEditor({
  initial,
  isNew,
  onSaved,
  onDeleted,
}: {
  initial: TokenProvider;
  isNew: boolean;
  onSaved: (id: string) => void;
  onDeleted: () => void;
}) {
  const [p, setP] = useState<TokenProvider>(() => structuredClone(initial));
  const [jsonOk, setJsonOk] = useState<Record<string, boolean>>({});
  const [useRefresh, setUseRefresh] = useState(!!initial.refresh?.request);
  const [testProfile, setTestProfile] = useState<string>(Object.keys(initial.profiles ?? {})[0] ?? "");
  const [testRefresh, setTestRefresh] = useState(true);
  const [newProfile, setNewProfile] = useState("");
  const save = useSaveTokenProvider();
  const del = useDeleteTokenProvider();
  const test = useTestTokenProvider();

  const placeholders = useMemo(() => placeholdersOf(p), [p]);
  const secretNames = useMemo(() => secretNamesOf(p), [p]);
  const profiles = p.profiles ?? {};
  const allJsonOk = Object.values(jsonOk).every(Boolean);
  const idOk = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(p.id);

  const payload = (): TokenProvider => {
    const out = structuredClone(p);
    delete out.placeholders;
    if (!useRefresh && out.refresh) out.refresh = { ...out.refresh, request: null, extract: null };
    return out;
  };

  const setVal = (profile: string, key: string, val: string) =>
    setP((cur) => ({
      ...cur,
      profiles: { ...cur.profiles, [profile]: { ...(cur.profiles?.[profile] ?? {}), [key]: val } },
    }));

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">{isNew ? "New token provider" : p.name || p.id}</CardTitle>
          <CardDescription>How to call your token API and where the token is in its response.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1">
              <Label className="text-xs">ID</Label>
              <Input
                value={p.id}
                disabled={!isNew}
                onChange={(e) => setP({ ...p, id: e.target.value })}
                placeholder="corp-token-api"
                className="font-mono text-xs"
              />
              {!idOk && p.id && (
                <p className="text-[11px] text-red-600">Letters, digits, '-' or '_' (max 64).</p>
              )}
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Name</Label>
              <Input value={p.name} onChange={(e) => setP({ ...p, name: e.target.value })} placeholder="Corp token API" />
            </div>
          </div>

          <RequestFields
            title="Token request"
            spec={p.request}
            onChange={(request) => setP({ ...p, request })}
            onValidity={(ok) => setJsonOk((s) => ({ ...s, request: ok }))}
          />

          <div className="space-y-2">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Read from response</p>
            <div className="grid gap-2 sm:grid-cols-3">
              {(
                [
                  ["token", "Token (required)", "$.data.accessToken"],
                  ["refresh_token", "Refresh token", "$.data.refreshToken"],
                  ["expires_in", "Expires in (seconds)", "$.data.expiresIn"],
                ] as const
              ).map(([k, label, ph]) => (
                <div key={k} className="space-y-1">
                  <Label className="text-xs">{label}</Label>
                  <Input
                    value={p.extract[k] ?? ""}
                    onChange={(e) => setP({ ...p, extract: { ...p.extract, [k]: e.target.value } })}
                    placeholder={ph}
                    className="font-mono text-xs"
                  />
                </div>
              ))}
            </div>
            <p className="text-[11px] text-muted-foreground">
              JSON path (<code>$.a.b[0]</code>), <code>header:X-Token</code> or <code>regex:token=([^&]+)</code>.
              Without an expiry, the JWT <code>exp</code> claim is used.
            </p>
          </div>

          <div className="grid gap-2 sm:grid-cols-2">
            <div className="space-y-1">
              <Label className="text-xs">Send token in header</Label>
              <Input
                value={p.apply?.header ?? "Authorization"}
                onChange={(e) => setP({ ...p, apply: { ...p.apply, header: e.target.value } })}
                className="font-mono text-xs"
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Header value format</Label>
              <Input
                value={p.apply?.format ?? "Bearer {{token}}"}
                onChange={(e) => setP({ ...p, apply: { ...p.apply, format: e.target.value } })}
                className="font-mono text-xs"
              />
            </div>
          </div>

          <div className="space-y-3 rounded-md border border-border p-3">
            <div className="flex items-center justify-between gap-2">
              <div>
                <p className="text-sm font-medium">Separate refresh call</p>
                <p className="text-[11px] text-muted-foreground">
                  Uses <code>{"{{refresh_token}}"}</code>. Off = repeat the token request. Falls back to the token
                  request if refresh fails.
                </p>
              </div>
              <Switch checked={useRefresh} onCheckedChange={setUseRefresh} />
            </div>
            {useRefresh && p.refresh?.request && (
              <RequestFields
                title="Refresh request"
                spec={p.refresh.request}
                onChange={(request) => setP({ ...p, refresh: { ...p.refresh, request } })}
                onValidity={(ok) => setJsonOk((s) => ({ ...s, refresh: ok }))}
              />
            )}
            {useRefresh && !p.refresh?.request && (
              <Button
                size="sm"
                variant="outline"
                onClick={() =>
                  setP({ ...p, refresh: { ...p.refresh, request: blankProvider().refresh!.request! } })
                }
              >
                Add refresh request
              </Button>
            )}
            <div className="grid gap-2 sm:grid-cols-2">
              <div className="space-y-1">
                <Label className="text-xs">Refresh this many seconds before expiry</Label>
                <Input
                  type="number"
                  min={1}
                  value={p.refresh?.before_expiry_seconds ?? 60}
                  onChange={(e) => setP({ ...p, refresh: { ...p.refresh, before_expiry_seconds: Number(e.target.value) } })}
                />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Assumed lifetime if unknown (seconds)</Label>
                <Input
                  type="number"
                  min={1}
                  value={p.refresh?.max_ttl_seconds ?? 900}
                  onChange={(e) => setP({ ...p, refresh: { ...p.refresh, max_ttl_seconds: Number(e.target.value) } })}
                />
              </div>
            </div>
          </div>

          <div className="space-y-2">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Secrets</p>
            {secretNames.length === 0 && (
              <p className="text-[11px] text-muted-foreground">
                Reference a secret in a request as <code>{"{{secret:name}}"}</code>.
              </p>
            )}
            {secretNames.map((name) => (
              <div key={name} className="grid gap-2 sm:grid-cols-[180px_minmax(0,1fr)]">
                <span className="self-center font-mono text-xs">{name}</span>
                <Input
                  type="password"
                  autoComplete="off"
                  value={p.secrets?.[name] ?? ""}
                  placeholder={p.secrets?.[name] === MASK ? "stored" : "value"}
                  onChange={(e) => setP({ ...p, secrets: { ...p.secrets, [name]: e.target.value } })}
                />
              </div>
            ))}
            <p className="text-[11px] text-muted-foreground">Stored on the server and never shown again.</p>
          </div>

          <div className="flex items-center justify-between rounded-md border border-border px-3 py-2">
            <div>
              <p className="text-sm font-medium">Skip TLS verification</p>
              <p className="text-[11px] text-muted-foreground">Only for lab token APIs with self-signed certificates.</p>
            </div>
            <Switch checked={!!p.tls_skip_verify} onCheckedChange={(v) => setP({ ...p, tls_skip_verify: v })} />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Profiles</CardTitle>
          <CardDescription>
            One parameter set per identity. In a scan, one profile is the default session (role A) and an optional
            second profile is used to prove cross-account access (role B).
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {placeholders.length === 0 && (
            <p className="text-xs text-muted-foreground">The requests use no {"{{parameters}}"}.</p>
          )}
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-muted-foreground">
                  <th className="py-1 pr-2 font-medium">Profile</th>
                  {placeholders.map((ph) => (
                    <th key={ph} className="py-1 pr-2 font-mono font-medium">
                      {ph}
                    </th>
                  ))}
                  <th />
                </tr>
              </thead>
              <tbody>
                {Object.keys(profiles)
                  .sort()
                  .map((name) => (
                    <tr key={name} className="border-t border-border">
                      <td className="py-1.5 pr-2 font-mono">{name}</td>
                      {placeholders.map((ph) => (
                        <td key={ph} className="py-1.5 pr-2">
                          <Input
                            value={profiles[name]?.[ph] ?? ""}
                            onChange={(e) => setVal(name, ph, e.target.value)}
                            className={cn("h-8 min-w-28 text-xs", !profiles[name]?.[ph] && "border-amber-500/50")}
                          />
                        </td>
                      ))}
                      <td className="py-1.5 text-right">
                        <Button
                          size="sm"
                          variant="ghost"
                          aria-label={`Remove profile ${name}`}
                          onClick={() =>
                            setP((cur) => {
                              const next = { ...(cur.profiles ?? {}) };
                              delete next[name];
                              return { ...cur, profiles: next };
                            })
                          }
                        >
                          <X className="h-3.5 w-3.5" />
                        </Button>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
          <div className="flex gap-2">
            <Input
              value={newProfile}
              onChange={(e) => setNewProfile(e.target.value.replace(/[^a-zA-Z0-9_-]/g, ""))}
              placeholder="new profile name (e.g. admin, tenant_b)"
              className="h-8 max-w-xs text-xs"
            />
            <Button
              size="sm"
              variant="outline"
              disabled={!newProfile || !!profiles[newProfile]}
              onClick={() => {
                setP((cur) => ({ ...cur, profiles: { ...(cur.profiles ?? {}), [newProfile]: {} } }));
                if (!testProfile) setTestProfile(newProfile);
                setNewProfile("");
              }}
            >
              <Plus className="h-3.5 w-3.5" /> Add profile
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Test</CardTitle>
          <CardDescription>Calls the token API now with the settings above (saved or not).</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <Select value={testProfile} onValueChange={setTestProfile}>
              <SelectTrigger className="h-9 w-48">
                <SelectValue placeholder="Profile" />
              </SelectTrigger>
              <SelectContent>
                {Object.keys(profiles).map((n) => (
                  <SelectItem key={n} value={n}>
                    {n}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <label className="flex items-center gap-2 text-xs">
              <Switch checked={testRefresh} onCheckedChange={setTestRefresh} /> Also test refresh
            </label>
            <Button
              size="sm"
              disabled={!allJsonOk || test.isPending || !p.request.url}
              onClick={() =>
                test.mutate({ provider: { ...payload(), id: p.id || "draft" }, profile: testProfile, refresh: testRefresh })
              }
            >
              {test.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
              Get token
            </Button>
          </div>
          {test.error && (
            <p className="text-xs text-red-600 dark:text-red-400">{(test.error as Error).message}</p>
          )}
          {test.data && <TestResult result={test.data} />}
        </CardContent>
      </Card>

      <div className="flex flex-wrap items-center gap-2">
        <Button
          disabled={!idOk || !allJsonOk || save.isPending}
          onClick={() => save.mutate(payload(), { onSuccess: (saved) => onSaved(saved.id) })}
        >
          {save.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />} Save
        </Button>
        {!isNew && (
          <Button
            variant="outline"
            className="text-red-600"
            disabled={del.isPending}
            onClick={() => {
              if (window.confirm(`Delete token provider "${p.id}"? Scans using it will fail to start.`))
                del.mutate(p.id, { onSuccess: onDeleted });
            }}
          >
            <Trash2 className="h-4 w-4" /> Delete
          </Button>
        )}
        {save.error && <span className="text-xs text-red-600">{(save.error as Error).message}</span>}
        {save.isSuccess && <span className="text-xs text-emerald-600">Saved</span>}
      </div>
    </div>
  );
}

function fmtValue(v: unknown): string {
  if (typeof v === "string") return v;
  return JSON.stringify(v);
}

function claimHint(k: string, v: unknown): string | null {
  if ((k === "exp" || k === "iat" || k === "nbf") && typeof v === "number") return new Date(v * 1000).toLocaleString();
  return null;
}

function TestStep({ s }: { s: TokenTestStep }) {
  return (
    <div className={cn("rounded-md border p-3", s.ok ? "border-emerald-500/30" : "border-red-500/30")}>
      <div className="flex flex-wrap items-center gap-2 text-sm">
        {s.ok && !s.error ? (
          <BadgeCheck className="h-4 w-4 text-emerald-500" />
        ) : s.ok ? (
          <AlertTriangle className="h-4 w-4 text-amber-500" />
        ) : (
          <XCircle className="h-4 w-4 text-red-500" />
        )}
        <span className="font-medium capitalize">{s.step}</span>
        <span className="text-xs text-muted-foreground">{s.elapsed_ms} ms</span>
        {s.token_preview && <code className="rounded bg-muted px-1.5 py-0.5 text-[11px]">{s.token_preview}</code>}
        {s.has_refresh_token && <span className="text-[11px] text-muted-foreground">refresh token ✓</span>}
        {s.refresh_token_rotated && <span className="text-[11px] text-muted-foreground">rotated</span>}
        {typeof s.expires_in_seconds === "number" && s.ok && (
          <span className="text-[11px] text-muted-foreground">
            expires in {Math.max(0, Math.round(s.expires_in_seconds / 60))} min
          </span>
        )}
      </div>
      {s.error && <p className="mt-2 break-words font-mono text-[11px] text-red-600 dark:text-red-400">{s.error}</p>}
      {s.missing && s.missing.length > 0 && (
        <p className="mt-1 text-[11px]">
          Missing values for: <span className="font-mono">{s.missing.join(", ")}</span>
        </p>
      )}
      {s.jwt && (
        <div className="mt-3 grid gap-3 md:grid-cols-[180px_minmax(0,1fr)]">
          <div>
            <p className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">JWT header</p>
            {Object.entries(s.jwt.header).map(([k, v]) => (
              <div key={k} className="font-mono text-[11px]">
                <span className="text-muted-foreground">{k}:</span> {fmtValue(v)}
              </div>
            ))}
          </div>
          <div>
            <p className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Claims</p>
            <table className="w-full text-[11px]">
              <tbody>
                {Object.entries(s.jwt.claims).map(([k, v]) => (
                  <tr key={k} className="border-t border-border/60">
                    <td className="py-0.5 pr-3 align-top font-mono text-muted-foreground">{k}</td>
                    <td className="py-0.5 break-all font-mono">
                      {fmtValue(v)}
                      {claimHint(k, v) && <span className="ml-2 text-muted-foreground">({claimHint(k, v)})</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function TestResult({ result }: { result: TokenTestResult }) {
  return (
    <div className="space-y-2">
      {result.steps.map((s) => (
        <TestStep key={s.step} s={s} />
      ))}
    </div>
  );
}
