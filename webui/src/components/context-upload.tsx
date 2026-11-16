import { useCallback, useRef, useState, type DragEvent, type ReactNode } from "react";
import { CheckCircle2, FileText, FolderOpen, KeyRound, Loader2, Upload, X } from "lucide-react";
import { api } from "@/api/client";
import type { ContextPreview } from "@/types/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/** Which new-scan section an upload belongs to. */
export type ContextKind = "security" | "collection";

const SECURITY_EXT = /\.(json|ya?ml|har|xml|apk|apks|xapk|aab|txt)$/i;
const COLLECTION_EXT = /\.(json|bru|zip)$/i;
const IGNORED_PATH = /(^|\/)(node_modules|\.git)\//;

/** File path as the server should see it (keeps a Bruno folder layout). */
const pathOf = (f: File) => f.webkitRelativePath || f.name;

/**
 * Best-effort sniff of a .json file so a Postman export dropped in the wrong
 * section can be routed to the right one. Only the head is read.
 */
async function sniffJSON(f: File): Promise<"postman" | "spec" | "other"> {
  if (!/\.json$/i.test(f.name)) return "other";
  try {
    const head = await f.slice(0, 64 << 10).text();
    if (/getpostman\.com|"_postman_(id|variable_scope|exported_using)"/.test(head)) return "postman";
    if (/"(openapi|swagger)"\s*:/.test(head) || /"log"\s*:\s*\{[\s\S]*"entries"/.test(head)) return "spec";
  } catch {
    /* unreadable: let the server decide */
  }
  return "other";
}

/** Splits dropped files into the ones this section accepts and the ones that belong to the other. */
export async function classifyFiles(kind: ContextKind, files: File[]) {
  const keep: File[] = [];
  const other: File[] = [];
  const rejected: File[] = [];
  for (const f of files) {
    if (IGNORED_PATH.test(pathOf(f))) continue;
    const isCollectionOnly = /\.(bru|zip)$/i.test(f.name) || !!f.webkitRelativePath;
    const sniff = await sniffJSON(f);
    if (kind === "security") {
      if (isCollectionOnly || sniff === "postman") other.push(f);
      else if (SECURITY_EXT.test(f.name)) keep.push(f);
      else rejected.push(f);
    } else {
      if (f.webkitRelativePath && !/\.(bru|json)$/i.test(f.name)) continue; // folder noise (.env, README…)
      if (sniff === "spec" || (SECURITY_EXT.test(f.name) && !COLLECTION_EXT.test(f.name))) other.push(f);
      else if (COLLECTION_EXT.test(f.name)) keep.push(f);
      else rejected.push(f);
    }
  }
  return { keep, other, rejected };
}

/**
 * State for one context section. Files are kept client-side so the operator
 * can add or remove individual files; every change re-uploads the set as one
 * server directory (the server parses a directory as a unit, e.g. a Postman
 * collection together with its environment).
 */
export function useContextUpload() {
  const [files, setFiles] = useState<File[]>([]);
  const [preview, setPreview] = useState<ContextPreview | null>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const seq = useRef(0);

  const upload = useCallback(async (next: File[]) => {
    const id = ++seq.current;
    setFiles(next);
    setError(null);
    if (!next.length) {
      setPreview(null);
      setUploading(false);
      return;
    }
    setUploading(true);
    try {
      const res = await api.uploadContext(next);
      if (id === seq.current) setPreview(res);
    } catch (err) {
      if (id === seq.current) {
        setPreview(null);
        setError(err instanceof Error ? err.message : "Upload failed");
      }
    } finally {
      if (id === seq.current) setUploading(false);
    }
  }, []);

  /** Adds files; a file with the same path replaces the earlier one. */
  const add = useCallback(
    (incoming: File[]) => {
      if (!incoming.length) return;
      const byPath = new Map(files.map((f) => [pathOf(f), f]));
      for (const f of incoming) byPath.set(pathOf(f), f);
      void upload([...byPath.values()]);
    },
    [files, upload],
  );
  const removeWhere = useCallback((drop: (f: File) => boolean) => void upload(files.filter((f) => !drop(f))), [files, upload]);
  const remove = useCallback((path: string) => removeWhere((f) => pathOf(f) === path), [removeWhere]);
  const clear = useCallback(() => void upload([]), [upload]);

  return { files, preview, setPreview, uploading, error, setError, add, remove, removeWhere, clear, path: preview?.path ?? "" };
}

export type ContextUpload = ReturnType<typeof useContextUpload>;

/** Reads a dropped folder tree into Files carrying their relative paths. */
async function filesFromDrop(e: DragEvent): Promise<File[]> {
  const items = Array.from(e.dataTransfer.items ?? []);
  const entries = items
    .map((i) => (i.kind === "file" ? i.webkitGetAsEntry?.() : null))
    .filter((x): x is FileSystemEntry => !!x);
  if (!entries.some((en) => en.isDirectory)) return Array.from(e.dataTransfer.files ?? []);

  const out: File[] = [];
  const walk = async (entry: FileSystemEntry, prefix: string): Promise<void> => {
    if (out.length > 1000) return;
    if (entry.isFile) {
      const file = await new Promise<File>((res, rej) => (entry as FileSystemFileEntry).file(res, rej));
      const rel = prefix + entry.name;
      if (prefix) Object.defineProperty(file, "webkitRelativePath", { value: rel });
      out.push(file);
      return;
    }
    if (entry.name === "node_modules" || entry.name === ".git") return;
    const reader = (entry as FileSystemDirectoryEntry).createReader();
    // readEntries returns batches; call until empty.
    for (;;) {
      const batch = await new Promise<FileSystemEntry[]>((res, rej) => reader.readEntries(res, rej));
      if (!batch.length) break;
      for (const child of batch) await walk(child, `${prefix}${entry.name}/`);
    }
  };
  for (const en of entries) await walk(en, "");
  return out;
}

const fmtBytes = (n: number) =>
  n < 1024 ? `${n} B` : n < 1 << 20 ? `${(n / 1024).toFixed(0)} KB` : `${(n / (1 << 20)).toFixed(1)} MB`;

/**
 * Drop zone + attached-file list for one context section.
 */
export function ContextDropzone({
  id,
  upload,
  accept,
  allowFolder,
  title,
  formats,
  onFiles,
}: {
  id: string;
  upload: ContextUpload;
  accept: string;
  allowFolder?: boolean;
  title: string;
  /** Short format chips shown in the empty state. */
  formats: string[];
  onFiles: (files: File[]) => void;
}) {
  const [over, setOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const folderRef = useRef<HTMLInputElement>(null);
  const { files, preview, uploading } = upload;

  // A folder upload lists every .bru file; summarize it as one entry.
  const folderRoots = new Map<string, { count: number; size: number }>();
  const loose: File[] = [];
  for (const f of files) {
    const root = f.webkitRelativePath.split("/")[0];
    if (f.webkitRelativePath && root) {
      const cur = folderRoots.get(root) ?? { count: 0, size: 0 };
      folderRoots.set(root, { count: cur.count + 1, size: cur.size + f.size });
    } else loose.push(f);
  }

  const onDrop = async (e: DragEvent) => {
    e.preventDefault();
    setOver(false);
    if (uploading) return;
    onFiles(await filesFromDrop(e));
  };

  return (
    <div className="space-y-3">
      <div
        onDragOver={(e) => {
          e.preventDefault();
          if (!uploading) setOver(true);
        }}
        onDragLeave={(e) => {
          if (!e.currentTarget.contains(e.relatedTarget as Node)) setOver(false);
        }}
        onDrop={(e) => void onDrop(e)}
        className={cn(
          "relative flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-border bg-muted/30 px-4 py-6 text-center transition-colors",
          over && "border-primary/70 bg-primary/5",
          uploading && "opacity-70",
        )}
      >
        <div className="flex h-9 w-9 items-center justify-center rounded-full bg-background ring-1 ring-border">
          {uploading ? (
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          ) : (
            <Upload className="h-4 w-4 text-muted-foreground" />
          )}
        </div>
        <div className="space-y-1">
          <p className="text-sm font-medium">{uploading ? "Parsing…" : files.length ? `Drop to add more ${title}` : `Drop ${title} here`}</p>
          <div className="flex flex-wrap justify-center gap-1">
            {formats.map((f) => (
              <span key={f} className="rounded border border-border bg-background px-1.5 py-0.5 text-[10px] text-muted-foreground">
                {f}
              </span>
            ))}
          </div>
        </div>
        <div className="flex flex-wrap justify-center gap-2">
          <Button type="button" size="sm" variant="outline" disabled={uploading} onClick={() => fileRef.current?.click()}>
            <FileText className="h-3.5 w-3.5" /> Choose files
          </Button>
          {allowFolder && (
            <Button type="button" size="sm" variant="outline" disabled={uploading} onClick={() => folderRef.current?.click()}>
              <FolderOpen className="h-3.5 w-3.5" /> Choose folder
            </Button>
          )}
        </div>
        <input
          ref={fileRef}
          id={id}
          type="file"
          multiple
          accept={accept}
          className="hidden"
          onChange={(e) => {
            onFiles(Array.from(e.currentTarget.files ?? []));
            e.currentTarget.value = "";
          }}
        />
        {allowFolder && (
          <input
            ref={folderRef}
            type="file"
            multiple
            className="hidden"
            {...({ webkitdirectory: "", directory: "" } as Record<string, string>)}
            onChange={(e) => {
              onFiles(Array.from(e.currentTarget.files ?? []));
              e.currentTarget.value = "";
            }}
          />
        )}
      </div>

      {upload.error && (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">{upload.error}</p>
      )}

      {files.length > 0 && (
        <ul className="divide-y divide-border rounded-md border border-border">
          {[...folderRoots].map(([root, info]) => (
            <FileRow
              key={`dir:${root}`}
              icon={<FolderOpen className="h-3.5 w-3.5" />}
              name={`${root}/`}
              meta={`${info.count} file${info.count === 1 ? "" : "s"} · ${fmtBytes(info.size)}`}
              disabled={uploading}
              onRemove={() => upload.removeWhere((f) => !!f.webkitRelativePath && f.webkitRelativePath.split("/")[0] === root)}
            />
          ))}
          {loose.map((f) => (
            <FileRow
              key={f.name}
              icon={<FileText className="h-3.5 w-3.5" />}
              name={f.name}
              meta={fmtBytes(f.size)}
              disabled={uploading}
              onRemove={() => upload.remove(f.name)}
            />
          ))}
        </ul>
      )}

      {preview && !uploading && <PreviewSummary preview={preview} />}
    </div>
  );
}

function FileRow({
  icon,
  name,
  meta,
  disabled,
  onRemove,
}: {
  icon: ReactNode;
  name: string;
  meta: string;
  disabled?: boolean;
  onRemove: () => void;
}) {
  return (
    <li className="flex items-center gap-2 px-3 py-1.5 text-xs">
      <span className="text-muted-foreground">{icon}</span>
      <span className="mono min-w-0 flex-1 truncate">{name}</span>
      <span className="shrink-0 text-[11px] text-muted-foreground">{meta}</span>
      <Button
        type="button"
        size="icon"
        variant="ghost"
        className="h-6 w-6"
        disabled={disabled}
        onClick={onRemove}
        aria-label={`Remove ${name}`}
      >
        <X className="h-3 w-3" />
      </Button>
    </li>
  );
}

/** One-line parse result: endpoints, formats, captured auth, base hosts. */
export function PreviewSummary({ preview }: { preview: ContextPreview }) {
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-md bg-emerald-500/5 px-3 py-2 text-[11px] ring-1 ring-emerald-500/20">
      <span className="inline-flex items-center gap-1.5 font-medium text-emerald-700 dark:text-emerald-400">
        <CheckCircle2 className="h-3.5 w-3.5" />
        {preview.endpoints} endpoint{preview.endpoints === 1 ? "" : "s"} seeded
      </span>
      {(preview.formats ?? []).map((f) => (
        <Badge key={f} variant="outline" className="text-[10px] capitalize">
          {f}
        </Badge>
      ))}
      {preview.has_auth && (
        <span className="inline-flex items-center gap-1 text-muted-foreground">
          <KeyRound className="h-3 w-3" /> auth captured
          {preview.auth_headers?.length ? <span className="mono">({preview.auth_headers.join(", ")})</span> : null}
        </span>
      )}
      {(preview.base_url_list?.length ?? 0) > 0 && (
        <span className="min-w-0 truncate text-muted-foreground">
          hosts: <span className="mono">{preview.base_url_list!.join(", ")}</span>
        </span>
      )}
    </div>
  );
}
