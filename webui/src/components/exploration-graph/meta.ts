import {
  Bot,
  Box,
  Code2,
  Cpu,
  Crosshair,
  Database,
  FileCode,
  FlaskConical,
  Layers,
  Radar,
  Route,
  Server,
  Shield,
  ShieldAlert,
  Syringe,
  Variable,
  type LucideIcon,
} from "lucide-react";
import type { ExplorationEdgeKind, ExplorationNodeType } from "@/types/api";
import { normalizeSeverity, type Severity } from "@/lib/utils";

// Visual vocabulary for the Exploration Graph. Colors are plain hex so they
// work for SVG strokes, the minimap and inline accents in both themes.

export interface NodeTypeMeta {
  label: string;
  icon: LucideIcon;
  color: string;
  width: number;
  height: number;
  description: string;
}

export const NODE_TYPES: ExplorationNodeType[] = [
  "target",
  "agent",
  "discovery",
  "endpoint",
  "parameter",
  "attempt",
  "evidence",
  "finding",
  "backend",
];

export const NODE_META: Record<ExplorationNodeType, NodeTypeMeta> = {
  target: {
    label: "Target",
    icon: Crosshair,
    color: "#94a3b8",
    width: 240,
    height: 64,
    description: "The scanned application",
  },
  agent: {
    label: "Agent",
    icon: Bot,
    color: "#8b5cf6",
    width: 240,
    height: 72,
    description: "Sub-agent lane that worked the path",
  },
  discovery: {
    label: "Discovery",
    icon: Radar,
    color: "#0ea5e9",
    width: 240,
    height: 72,
    description: "First tool call that surfaced the endpoint",
  },
  endpoint: {
    label: "Endpoint",
    icon: Route,
    color: "#3b82f6",
    width: 260,
    height: 68,
    description: "HTTP method + normalized path",
  },
  parameter: {
    label: "Parameter",
    icon: Variable,
    color: "#14b8a6",
    width: 220,
    height: 64,
    description: "Input that was tested",
  },
  attempt: {
    label: "Attempt",
    icon: FlaskConical,
    color: "#f59e0b",
    width: 250,
    height: 76,
    description: "Hypothesis the agent tested",
  },
  evidence: {
    label: "Evidence",
    icon: Syringe,
    color: "#f97316",
    width: 270,
    height: 84,
    description: "Injected request / probe and its proof",
  },
  finding: {
    label: "Finding",
    icon: ShieldAlert,
    color: "#ef4444",
    width: 270,
    height: 84,
    description: "Reported vulnerability",
  },
  backend: {
    label: "Backend",
    icon: Server,
    color: "#10b981",
    width: 230,
    height: 68,
    description: "Technology revealed by the exploit",
  },
};

export function nodeMeta(type: string): NodeTypeMeta {
  return NODE_META[type as ExplorationNodeType] ?? NODE_META.target;
}

export const BACKEND_ICONS: Record<string, LucideIcon> = {
  database: Database,
  server: Server,
  framework: Layers,
  language: Code2,
  parser: FileCode,
  os: Cpu,
  waf: Shield,
  other: Box,
};

export interface EdgeKindMeta {
  label: string;
  color: string;
  description: string;
}

export const EDGE_KINDS: ExplorationEdgeKind[] = [
  "assigned",
  "discovered",
  "exposes",
  "tested",
  "injected",
  "proves",
  "reveals",
];

export const EDGE_META: Record<ExplorationEdgeKind | "bridged", EdgeKindMeta> = {
  assigned: { label: "assigned", color: "#a78bfa", description: "Target handed to an agent" },
  discovered: { label: "discovered", color: "#38bdf8", description: "Tool call found the endpoint" },
  exposes: { label: "exposes", color: "#94a3b8", description: "Endpoint takes this parameter" },
  tested: { label: "tested", color: "#f59e0b", description: "Hypothesis tested on the input" },
  injected: { label: "injected", color: "#fb923c", description: "Payload sent / evidence captured" },
  proves: { label: "proves", color: "#ef4444", description: "Evidence confirms the finding" },
  reveals: { label: "reveals", color: "#10b981", description: "Finding exposes backend tech" },
  bridged: { label: "via hidden", color: "#71717a", description: "Path through hidden node types" },
};

export function edgeMeta(kind: string): EdgeKindMeta {
  return EDGE_META[kind as keyof typeof EDGE_META] ?? EDGE_META.bridged;
}

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#3b82f6",
  info: "#a1a1aa",
};

export function severityColor(sev?: string): string {
  return SEVERITY_COLORS[normalizeSeverity(sev)];
}

/** Accent color for a concrete node (findings follow their severity). */
export function accentFor(type: string, severity?: string): string {
  if (type === "finding") return severityColor(severity);
  return nodeMeta(type).color;
}

export const STATUS_STYLES: Record<string, string> = {
  proven: "border-emerald-500/40 bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  rejected: "border-border bg-muted text-muted-foreground",
  blocked: "border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-400",
  exhausted: "border-zinc-500/40 bg-zinc-500/10 text-zinc-600 dark:text-zinc-400",
  active: "border-sky-500/40 bg-sky-500/15 text-sky-700 dark:text-sky-400",
};

export const METHOD_STYLES: Record<string, string> = {
  GET: "bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/30",
  POST: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30",
  PUT: "bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30",
  PATCH: "bg-violet-500/15 text-violet-700 dark:text-violet-300 border-violet-500/30",
  DELETE: "bg-red-500/15 text-red-700 dark:text-red-300 border-red-500/30",
};

// ---- untrusted-value helpers ----------------------------------------------

/** Coerce an unknown API value to a display string (never HTML). */
export function str(v: unknown): string {
  if (v == null) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

export function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

/** First non-empty line, whitespace-collapsed, truncated. */
export function oneLine(v: unknown, n = 64): string {
  const s = str(v)
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find((l) => l.length > 0);
  return truncate((s ?? "").replace(/\s+/g, " "), n);
}

/** Returns the URL only if it is an absolute http(s) URL; otherwise null. */
export function safeHttpUrl(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (!/^https?:\/\//i.test(s)) return null;
  try {
    const u = new URL(s);
    return u.protocol === "http:" || u.protocol === "https:" ? u.href : null;
  } catch {
    return null;
  }
}
