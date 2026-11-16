import { useNavigate } from "react-router-dom";
import { useMemo, useState, type FormEvent } from "react";
import { useI18n } from "@/i18n";
import {
  Boxes,
  ChevronLeft,
  FileSearch,
  ImageIcon,
  KeyRound,
  Loader2,
  Play,
  Radar,
  Save,
  ShieldCheck,
  Upload,
  X,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import { PHASES } from "@/components/phase-progress";
import { api } from "@/api/client";
import { useAuthProfiles, useLLMSettings, useProviders, useStartScan, useTokenProviders } from "@/api/queries";
import { CollectionPreview } from "@/components/collection-preview";
import { ContextDropzone, classifyFiles, useContextUpload, type ContextKind } from "@/components/context-upload";
import { ScopeHostList, computeScope, mergeUploadHosts } from "@/components/scope-hosts";
import { cn } from "@/lib/utils";

const SCAN_MODES = [
  {
    value: "single",
    label: "Single target",
    hint: "Test exactly what you provided. No subdomain enumeration.",
  },
  {
    value: "wildcard",
    label: "Wildcard / multi",
    hint: "Enumerate subdomains, then scan each one.",
  },
  {
    value: "dast",
    label: "DAST",
    hint: "Authenticated app testing with browser-driven probes.",
  },
];

const SEVERITIES = ["info", "low", "medium", "high", "critical"];
type ActivityMode = "active" | "passive";

const ACTIVITY_OPTIONS: Array<{
  value: ActivityMode;
  label: string;
  hint: string;
}> = [
  {
    value: "passive",
    label: "Passive only",
    hint: "Public sources and existing evidence. No direct target requests.",
  },
  {
    value: "active",
    label: "Active allowed",
    hint: "Direct in-scope probes and verification are allowed.",
  },
];

export default function NewScanPage() {
  const { t } = useI18n();
  const nav = useNavigate();
  const startScan = useStartScan();
  const llmQuery = useLLMSettings();

  const [targetsText, setTargetsText] = useState("");
  const [name, setName] = useState("");
  const [scanMode, setScanMode] = useState("single");
  const [reconMode, setReconMode] = useState<ActivityMode>("active");
  const [scanIntensity, setScanIntensity] = useState<ActivityMode>("active");
  const [instruction, setInstruction] = useState("");
  const [selectedPhases, setSelectedPhases] = useState<number[]>([]);
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [model, setModel] = useState("");
  // Optional "<provider>:<profileId>" key naming a stored AuthProfile
  // (provider-catalog-and-oauth, R11.1, R14.4). Empty string ("default"
  // option) means "let the server pick" — don't send provider_profile
  // and the legacy / catalog-default path resolves the credentials.
  const [providerProfile, setProviderProfile] = useState("");
  const [companyName, setCompanyName] = useState("");
  const [logoPath, setLogoPath] = useState("");
  const [logoFileName, setLogoFileName] = useState("");
  const [logoUploading, setLogoUploading] = useState(false);
  const security = useContextUpload();
  const collection = useContextUpload();
  // Shown when dropped files were routed to the other context section.
  const [routedNote, setRoutedNote] = useState<{ kind: ContextKind; text: string } | null>(null);
  const contextUploading = security.uploading || collection.uploading;
  const uploadHosts = useMemo(
    () => mergeUploadHosts(collection.preview, security.preview),
    [collection.preview, security.preview],
  );
  // Explicit host ticks, keyed by base URL; everything else uses the default.
  const [hostOverrides, setHostOverrides] = useState<Record<string, boolean>>({});
  const unresolvedHostRequests =
    (collection.preview?.unresolved_host_requests ?? 0) + (security.preview?.unresolved_host_requests ?? 0);
  const [tokenProvider, setTokenProvider] = useState("");
  const [tokenProfile, setTokenProfile] = useState("");
  const [tokenProfileB, setTokenProfileB] = useState("");
  const tokenProvidersQuery = useTokenProviders();
  const tokenProviders = tokenProvidersQuery.data ?? [];
  const selectedTokenProvider = tokenProviders.find((p) => p.id === tokenProvider);
  const tokenProfiles = Object.keys(selectedTokenProvider?.profiles ?? {}).sort();
  const [targetAuth, setTargetAuth] = useState("");
  const [targetAuthB, setTargetAuthB] = useState("");
  const [error, setError] = useState<string | null>(null);

  const targets = useMemo(
    () =>
      targetsText
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean),
    [targetsText],
  );
  const scope = useMemo(
    () => computeScope(targets, uploadHosts, hostOverrides),
    [targets, uploadHosts, hostOverrides],
  );

  // Profile picker source. Profiles drive the picker; the catalog
  // (separate query) supplies the human-readable displayName per
  // entry. Both queries fail open: when neither has loaded yet (or
  // the user has no profiles configured) the picker collapses to
  // the single "Server default" option.
  const profilesQuery = useAuthProfiles();
  const catalogQuery = useProviders();
  const profileOptions = useMemo(() => {
    const profiles = profilesQuery.data ?? [];
    const catalog = catalogQuery.data ?? [];
    const byID = new Map(catalog.map((e) => [e.id, e]));
    return profiles.map((p) => {
      const entry = byID.get(p.provider);
      const display = entry?.displayName ?? p.provider;
      return {
        value: `${p.provider}:${p.profileId}`,
        label: `${display} · ${p.profileId}`,
      };
    });
  }, [profilesQuery.data, catalogQuery.data]);

  function togglePhase(id: number) {
    setSelectedPhases((cur) =>
      cur.includes(id)
        ? cur.filter((p) => p !== id)
        : [...cur, id].sort((a, b) => a - b),
    );
  }
  function toggleSeverity(s: string) {
    setSeverityFilter((cur) =>
      cur.includes(s) ? cur.filter((p) => p !== s) : [...cur, s],
    );
  }
  function updateScanIntensity(value: ActivityMode) {
    setScanIntensity(value);
    if (value === "passive") setReconMode("passive");
  }

  async function uploadReportLogo(file?: File) {
    if (!file) return;
    setError(null);
    if (!/\.(png|jpe?g)$/i.test(file.name)) {
      setError("Report logos must be PNG or JPEG.");
      return;
    }
    setLogoUploading(true);
    try {
      const res = await api.uploadLogo(file);
      setLogoPath(res.path);
      setLogoFileName(res.filename || file.name);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to upload logo");
    } finally {
      setLogoUploading(false);
    }
  }

  // Files dropped in the wrong section (e.g. a Postman export under Security
  // context) are moved to the right one rather than rejected.
  async function addContextFiles(kind: ContextKind, files: File[]) {
    if (!files.length) return;
    const self = kind === "security" ? security : collection;
    const peer = kind === "security" ? collection : security;
    const { keep, other, rejected } = await classifyFiles(kind, files);
    setRoutedNote(null);
    self.setError(
      rejected.length
        ? `Unsupported: ${rejected.map((f) => f.name).join(", ")}. ${
            kind === "security"
              ? "Use an OpenAPI/Swagger spec (JSON/YAML), HAR, Burp XML, Android app, or .txt notes."
              : "Use a Postman collection/environment (.json) or a Bruno collection (folder, .bru files or .zip)."
          }`
        : null,
    );
    if (keep.length) self.add(keep);
    if (other.length) {
      peer.add(other);
      const peerKind: ContextKind = kind === "security" ? "collection" : "security";
      setRoutedNote({
        kind: peerKind,
        text: `${other.length === 1 ? other[0].name : `${other.length} files`} moved here from ${
          kind === "security" ? "Security context" : "API collection"
        }.`,
      });
    }
    if (!keep.length && !other.length && !rejected.length && files.length) {
      self.setError("That folder has no .bru or .json collection files.");
    }
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    await submitScan(false);
  }

  async function submitScan(saveOnly: boolean) {
    setError(null);
    if (contextUploading) {
      setError("Wait for the context upload to finish.");
      return;
    }
    if (!scope.finalTargets.length) {
      setError(
        uploadHosts.length
          ? "No host is in scope. Tick at least one host from your uploads or type a target."
          : "At least one target is required (or attach a collection whose requests use absolute URLs).",
      );
      return;
    }
    if (tokenProvider && !tokenProfile && tokenProfiles.length > 0) {
      setError("Choose the token provider profile to use as the default session.");
      return;
    }
    try {
      const res = await startScan.mutateAsync({
        targets: scope.finalTargets,
        name: name.trim() || undefined,
        scan_mode: scanMode,
        instruction: instruction.trim() || undefined,
        phases: selectedPhases.length ? selectedPhases : undefined,
        recon_mode: reconMode,
        scan_intensity: scanIntensity,
        severity_filter: severityFilter.length ? severityFilter : undefined,
        model: model.trim() || undefined,
        provider_profile: providerProfile || undefined,
        company_name: companyName.trim() || undefined,
        logo_path: logoPath || undefined,
        scan_context: security.path || undefined,
        api_collection: collection.path || undefined,
        target_auth: tokenProvider ? undefined : targetAuth.trim() || undefined,
        target_auth_b: tokenProvider ? undefined : targetAuthB.trim() || undefined,
        token_auth: tokenProvider
          ? { provider: tokenProvider, profile: tokenProfile || undefined, profile_b: tokenProfileB || undefined }
          : undefined,
        save_only: saveOnly || undefined,
      });
      const id =
        (res as { id?: string; instance_id?: string })?.instance_id ||
        (res as { id?: string })?.id;
      if (id) nav(`/scans/${id}`);
      else nav("/scans");
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : saveOnly
            ? "Failed to save scan"
            : "Failed to start scan",
      );
    }
  }

  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => nav(-1)}
          className="text-muted-foreground"
        >
          <ChevronLeft className="h-3.5 w-3.5" /> {t("newScan.back")}
        </Button>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight text-balance">
          {t("newScan.heading")}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground text-pretty">
          Configure target, scope, and methodology phases. AI-DAST-ING orchestrates
          recon and active probes, then synthesizes findings with the agent.
        </p>
      </div>

      <form onSubmit={onSubmit} className="space-y-5">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t("newScan.section.targets")}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="targets">
                {uploadHosts.length ? t("newScan.label.targetsOptional") : t("newScan.label.targets")}
              </Label>
              <Textarea
                id="targets"
                required={!uploadHosts.length}
                placeholder={"example.com\nhttps://app.example.com"}
                value={targetsText}
                onChange={(e) => setTargetsText(e.target.value)}
                rows={3}
                className="mono text-xs"
              />
              <p className="text-[11px] text-muted-foreground">
                {uploadHosts.length
                  ? "Optional — the hosts ticked below come from your uploads. Add any other host to scan here."
                  : "One per line, or comma-separated. Domains, hosts, or URLs. Uploading a collection or spec can fill this in."}
              </p>
              {targets.length > 1 && (
                <div className="flex flex-wrap gap-1">
                  {targets.map((t) => (
                    <Badge
                      key={t}
                      variant="outline"
                      className="mono text-[10px]"
                    >
                      {t}
                    </Badge>
                  ))}
                </div>
              )}
            </div>
            <ScopeHostList
              hosts={uploadHosts}
              checked={scope.checked}
              onToggle={(h, on) => setHostOverrides((cur) => ({ ...cur, [h.base_url]: on }))}
              environment={collection.preview?.environment || undefined}
              unresolved={unresolvedHostRequests}
              skippedRequests={scope.skippedRequests}
              unusedTyped={scope.unusedTyped}
            />
            <div className="space-y-2">
              <Label htmlFor="name">{t("newScan.label.displayName")}</Label>
              <Input
                id="name"
                placeholder="Auto-generated from target if blank"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="space-y-1.5">
            <CardTitle className="flex items-center gap-2 text-base">
              <FileSearch className="h-4 w-4 text-muted-foreground" />
              {t("newScan.section.securityContext")}
            </CardTitle>
            <CardDescription className="text-xs text-pretty">
              Specs, traffic and app builds that describe the real attack surface. AI-DAST-ING seeds
              the scan with their endpoints, parameters and any captured session instead of relying on
              crawling alone — the biggest single boost to black-box coverage.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {routedNote?.kind === "security" && <RoutedNote text={routedNote.text} onDismiss={() => setRoutedNote(null)} />}
            <ContextDropzone
              id="securityContext"
              upload={security}
              title="specs, captures or app builds"
              accept=".json,.yaml,.yml,.har,.xml,.apk,.apks,.xapk,.aab,.txt"
              formats={["OpenAPI / Swagger", "HAR", "Burp XML", "APK / AAB", "Notes .txt"]}
              onFiles={(f) => void addContextFiles("security", f)}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="space-y-1.5">
            <CardTitle className="flex items-center gap-2 text-base">
              <Boxes className="h-4 w-4 text-muted-foreground" />
              {t("newScan.section.apiCollection")}
            </CardTitle>
            <CardDescription className="text-xs text-pretty">
              A Postman or Bruno collection. Add the Postman environment alongside it (or pick a Bruno
              environment below) and AI-DAST-ING resolves{" "}
              <code className="text-foreground">{"{{variables}}"}</code> and auth, then lets you choose
              exactly which requests the scan tests.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {routedNote?.kind === "collection" && <RoutedNote text={routedNote.text} onDismiss={() => setRoutedNote(null)} />}
            <ContextDropzone
              id="apiCollection"
              upload={collection}
              allowFolder
              title="a Postman or Bruno collection"
              accept=".json,.bru,.zip"
              formats={["Postman v2.x", "Postman environment", "Bruno folder", "Bruno .zip / .bru"]}
              onFiles={(f) => void addContextFiles("collection", f)}
            />
            {collection.preview && !collection.uploading && (collection.preview.requests?.length ?? 0) > 0 && (
              <CollectionPreview
                key={collection.path}
                preview={collection.preview}
                onChange={(p) => collection.setPreview(p)}
              />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t("newScan.section.authAccess")}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2 rounded-md border border-border p-3">
              <Label className="flex items-center gap-2">
                <KeyRound className="h-3.5 w-3.5 text-muted-foreground" /> Token provider
              </Label>
              <div className="grid gap-2 sm:grid-cols-3">
                <Select
                  value={tokenProvider || "__none"}
                  onValueChange={(v) => {
                    const id = v === "__none" ? "" : v;
                    setTokenProvider(id);
                    const profs = Object.keys(tokenProviders.find((p) => p.id === id)?.profiles ?? {}).sort();
                    setTokenProfile(profs[0] ?? "");
                    setTokenProfileB("");
                  }}
                >
                  <SelectTrigger className="h-9 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__none">None (use headers below)</SelectItem>
                    {tokenProviders.map((p) => (
                      <SelectItem key={p.id} value={p.id}>
                        {p.name || p.id}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {tokenProvider && (
                  <Select value={tokenProfile} onValueChange={setTokenProfile}>
                    <SelectTrigger className="h-9 text-xs">
                      <SelectValue placeholder="Default session profile" />
                    </SelectTrigger>
                    <SelectContent>
                      {tokenProfiles.map((n) => (
                        <SelectItem key={n} value={n}>
                          Role A: {n}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
                {tokenProvider && (
                  <Select value={tokenProfileB || "__none"} onValueChange={(v) => setTokenProfileB(v === "__none" ? "" : v)}>
                    <SelectTrigger className="h-9 text-xs">
                      <SelectValue placeholder="Second identity (optional)" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="__none">No second identity</SelectItem>
                      {tokenProfiles
                        .filter((n) => n !== tokenProfile)
                        .map((n) => (
                          <SelectItem key={n} value={n}>
                            Role B: {n}
                          </SelectItem>
                        ))}
                    </SelectContent>
                  </Select>
                )}
              </div>
              <p className="text-[11px] text-muted-foreground text-pretty">
                {tokenProvider
                  ? "Tokens are fetched before the scan starts (it won't start if this fails), sent on every request and refreshed before they expire or after a 401. Role B proves cross-account access."
                  : tokenProviders.length
                    ? "Pick a token provider to get a fresh JWT from your token API for this scan."
                    : "To get a JWT from your token API automatically, add one under Token Providers."}{" "}
                <a href="/token-providers" className="underline">
                  Manage token providers
                </a>
              </p>
            </div>
            {!tokenProvider && (
            <>
            <div className="space-y-2">
              <Label htmlFor="targetAuth">{t("newScan.label.authSession")}</Label>
              <Textarea
                id="targetAuth"
                placeholder={"Cookie: session=abc123; Authorization: Bearer eyJ…"}
                value={targetAuth}
                onChange={(e) => setTargetAuth(e.target.value)}
                rows={2}
                className="mono text-xs"
              />
              <p className="text-[11px] text-muted-foreground text-pretty">
                Applied automatically to every request so the agent tests the post-login surface
                (IDOR/BOLA, privilege escalation, business logic). One{" "}
                <span className="mono">Header: value</span> per line, or semicolon-separated.
                Credentials are redacted from the event stream, logs, and reports.
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="targetAuthB">{t("newScan.label.secondAccount")}</Label>
              <Textarea
                id="targetAuthB"
                placeholder={"Cookie: session=DIFFERENT_USER…"}
                value={targetAuthB}
                onChange={(e) => setTargetAuthB(e.target.value)}
                rows={2}
                className="mono text-xs"
              />
              <p className="text-[11px] text-muted-foreground text-pretty">
                A DISTINCT second account. The agent uses it to prove horizontal access control —
                reaching account A&apos;s objects with account B&apos;s session confirms BOLA/IDOR
                with concrete evidence.
              </p>
            </div>
            </>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t("newScan.section.targetAccess")}</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label className="flex items-center gap-2">
                <Radar className="h-3.5 w-3.5 text-muted-foreground" />
                Recon phase
              </Label>
              <div className="grid gap-2">
                {ACTIVITY_OPTIONS.map((option) => {
                  const active = reconMode === option.value;
                  const disabled =
                    scanIntensity === "passive" && option.value === "active";
                  return (
                    <button
                      type="button"
                      key={option.value}
                      disabled={disabled}
                      onClick={() => setReconMode(option.value)}
                      className={cn(
                        "rounded-md border border-border bg-card p-3 text-left transition-colors",
                        "hover:border-foreground/30 disabled:cursor-not-allowed disabled:opacity-50",
                        active &&
                          "border-primary/70 bg-primary/5 ring-1 ring-primary/30",
                      )}
                    >
                      <div className="text-sm font-medium">{option.label}</div>
                      <p className="mt-1 text-[11px] text-muted-foreground text-pretty">
                        {option.hint}
                      </p>
                    </button>
                  );
                })}
              </div>
            </div>
            <div className="space-y-2">
              <Label className="flex items-center gap-2">
                <ShieldCheck className="h-3.5 w-3.5 text-muted-foreground" />
                Testing phases
              </Label>
              <div className="grid gap-2">
                {ACTIVITY_OPTIONS.map((option) => {
                  const active = scanIntensity === option.value;
                  return (
                    <button
                      type="button"
                      key={option.value}
                      onClick={() => updateScanIntensity(option.value)}
                      className={cn(
                        "rounded-md border border-border bg-card p-3 text-left transition-colors",
                        "hover:border-foreground/30",
                        active &&
                          "border-primary/70 bg-primary/5 ring-1 ring-primary/30",
                      )}
                    >
                      <div className="text-sm font-medium">{option.label}</div>
                      <p className="mt-1 text-[11px] text-muted-foreground text-pretty">
                        {option.hint}
                      </p>
                    </button>
                  );
                })}
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t("newScan.section.reportBranding")}</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-4 sm:grid-cols-[1fr_220px]">
            <div className="space-y-2">
              <Label htmlFor="companyName">{t("newScan.label.brandName")}</Label>
              <Input
                id="companyName"
                placeholder="Shown on the PDF cover"
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>{t("newScan.label.brandLogo")}</Label>
              <div className="flex items-center gap-3">
                <div className="flex h-14 w-14 shrink-0 items-center justify-center overflow-hidden rounded-md border border-border bg-muted">
                  {logoPath ? (
                    <img
                      src={logoPath}
                      alt=""
                      className="h-full w-full object-contain"
                    />
                  ) : (
                    <ImageIcon className="h-5 w-5 text-muted-foreground" />
                  )}
                </div>
                <div className="min-w-0 flex-1 space-y-2">
                  <div className="flex items-center gap-2">
                    <label
                      htmlFor="reportLogo"
                      className={cn(
                        "inline-flex h-8 cursor-pointer items-center justify-center gap-2 rounded-md border border-border bg-transparent px-3 text-xs font-medium transition-colors hover:bg-accent",
                        logoUploading && "pointer-events-none opacity-60",
                      )}
                    >
                      {logoUploading ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <Upload className="h-3.5 w-3.5" />
                      )}
                      Upload
                    </label>
                    <Input
                      id="reportLogo"
                      type="file"
                      accept="image/png,image/jpeg"
                      disabled={logoUploading}
                      className="hidden"
                      onChange={(e) => {
                        void uploadReportLogo(e.currentTarget.files?.[0]);
                        e.currentTarget.value = "";
                      }}
                    />
                    {logoPath && (
                      <Button
                        type="button"
                        size="icon"
                        variant="ghost"
                        onClick={() => {
                          setLogoPath("");
                          setLogoFileName("");
                        }}
                        aria-label="Remove report logo"
                      >
                        <X className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </div>
                  {logoFileName && (
                    <p className="truncate text-[11px] text-muted-foreground">
                      {logoFileName}
                    </p>
                  )}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t("newScan.section.scanMode")}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-3 sm:grid-cols-3">
              {SCAN_MODES.map((m) => (
                <button
                  type="button"
                  key={m.value}
                  onClick={() => setScanMode(m.value)}
                  className={cn(
                    "rounded-md border border-border bg-card p-3 text-left transition-colors",
                    "hover:border-foreground/30",
                    scanMode === m.value &&
                      "border-primary/70 bg-primary/5 ring-1 ring-primary/30",
                  )}
                >
                  <div className="text-sm font-medium">{m.label}</div>
                  <p className="mt-1 text-[11px] text-muted-foreground text-pretty">
                    {m.hint}
                  </p>
                </button>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Methodology phases
              <span className="ml-2 text-[11px] font-normal text-muted-foreground">
                {selectedPhases.length
                  ? `${selectedPhases.length} selected`
                  : "all phases (default)"}
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {PHASES.map((p) => {
                const active = selectedPhases.includes(p.id);
                return (
                  <button
                    type="button"
                    key={p.id}
                    onClick={() => togglePhase(p.id)}
                    className={cn(
                      "flex items-center gap-2 rounded-md border border-border bg-card px-2.5 py-1.5 text-left text-xs transition-colors",
                      "hover:border-foreground/30",
                      active &&
                        "border-primary/70 bg-primary/5 text-foreground",
                      !active && "text-muted-foreground",
                    )}
                  >
                    <span
                      className={cn(
                        "mono inline-flex h-5 w-7 shrink-0 items-center justify-center rounded text-[10px]",
                        active
                          ? "bg-primary/15 text-primary"
                          : "bg-muted text-muted-foreground",
                      )}
                    >
                      {String(p.id).padStart(2, "0")}
                    </span>
                    <span className="truncate">{p.name}</span>
                  </button>
                );
              })}
            </div>
            <div className="flex items-center gap-2">
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={() => setSelectedPhases([])}
              >
                All phases
              </Button>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={() => setSelectedPhases([1, 22])}
              >
                Recon + report only
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t("newScan.section.refinement")}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>{t("newScan.label.severityFilter")}</Label>
              <div className="flex flex-wrap gap-1.5">
                {SEVERITIES.map((s) => {
                  const active = severityFilter.includes(s);
                  return (
                    <button
                      type="button"
                      key={s}
                      onClick={() => toggleSeverity(s)}
                      className={cn(
                        "rounded-full border px-2.5 py-1 text-[11px] capitalize transition-colors",
                        active
                          ? "border-primary/60 bg-primary/10 text-foreground"
                          : "border-border bg-card text-muted-foreground hover:text-foreground",
                      )}
                    >
                      {s}
                    </button>
                  );
                })}
              </div>
              <p className="text-[11px] text-muted-foreground">
                Report only findings at or above selected severities. Leave
                blank for all.
              </p>
            </div>
            <Separator />
            <div className="space-y-2">
              <Label htmlFor="instr">{t("newScan.label.customInstruction")}</Label>
              <Textarea
                id="instr"
                placeholder="e.g. Focus on the payment flow at /checkout and skip /static/."
                value={instruction}
                onChange={(e) => setInstruction(e.target.value)}
                rows={3}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="model">{t("newScan.label.modelOverride")}</Label>
              <Input
                id="model"
                placeholder={llmQuery.data?.model || "model-name"}
                value={model}
                onChange={(e) => setModel(e.target.value)}
              />
              <p className="text-[11px] text-muted-foreground">
                Override the model for this scan. Leave blank to use the
                server default{llmQuery.data?.model ? ` (${llmQuery.data.model})` : ""}.
              </p>
            </div>
            <div className="space-y-2">
              <Label>{t("newScan.label.providerProfile")}</Label>
              <Select
                value={providerProfile || "default"}
                onValueChange={(v) =>
                  setProviderProfile(v === "default" ? "" : v)
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="default">Server default</SelectItem>
                  {profileOptions.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-[11px] text-muted-foreground">
                Pick a stored credential profile to route this scan
                through. Manage profiles under Settings → Providers.
              </p>
            </div>
          </CardContent>
        </Card>

        {error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </div>
        )}

        <div className="flex flex-col-reverse gap-2 border-t border-border pt-3 sm:flex-row sm:items-center sm:justify-end">
          <Button type="button" variant="outline" onClick={() => nav(-1)}>
            {t("common.cancel")}
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={!scope.finalTargets.length || contextUploading || startScan.isPending}
            onClick={() => void submitScan(true)}
          >
            {startScan.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Save className="h-3.5 w-3.5" />
            )}
            {t("newScan.btn.saveForLater")}
          </Button>
          <Button
            type="submit"
            disabled={!scope.finalTargets.length || contextUploading || startScan.isPending}
          >
            {startScan.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Play className="h-3.5 w-3.5" />
            )}
            {t("newScan.btn.startScan")}
          </Button>
        </div>
      </form>
    </div>
  );
}

function RoutedNote({ text, onDismiss }: { text: string; onDismiss: () => void }) {
  return (
    <div className="flex items-center gap-2 rounded-md border border-sky-500/30 bg-sky-500/5 px-3 py-1.5 text-[11px] text-sky-700 dark:text-sky-300">
      <span className="flex-1">{text}</span>
      <button type="button" onClick={onDismiss} aria-label="Dismiss" className="opacity-70 hover:opacity-100">
        <X className="h-3 w-3" />
      </button>
    </div>
  );
}
