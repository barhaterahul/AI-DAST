import { useState } from "react";
import { ChevronDown, ChevronUp } from "lucide-react";
import { cn } from "@/lib/utils";
import { useI18n } from "@/i18n";
import { EDGE_KINDS, EDGE_META, NODE_META, NODE_TYPES } from "./meta";

export function GraphLegend({ className }: { className?: string }) {
  const { t } = useI18n();
  const tr = (k: string, f: string) => (t(k) === k ? f : t(k));
  const [open, setOpen] = useState(false);
  return (
    <div
      className={cn(
        "w-56 rounded-md border border-border bg-card/95 text-card-foreground shadow-sm backdrop-blur",
        className,
      )}
    >
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between px-3 py-2 text-xs font-medium"
        aria-expanded={open}
      >
        {tr("exploration.legend", "Legend")}
        {open ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
      </button>
      {open && (
        <div className="max-h-[60vh] space-y-3 overflow-y-auto border-t border-border px-3 py-2">
          <div className="space-y-1.5">
            <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
              {tr("exploration.legend.nodes", "Nodes")}
            </p>
            {NODE_TYPES.map((type) => {
              const m = NODE_META[type];
              const Icon = m.icon;
              return (
                <div key={type} className="flex items-start gap-2">
                  <span
                    className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded"
                    style={{ backgroundColor: `${m.color}22`, color: m.color }}
                  >
                    <Icon className="h-2.5 w-2.5" />
                  </span>
                  <div className="min-w-0">
                    <p className="text-[11px] font-medium leading-tight">{m.label}</p>
                    <p className="text-[10px] leading-tight text-muted-foreground">{m.description}</p>
                  </div>
                </div>
              );
            })}
          </div>
          <div className="space-y-1.5">
            <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
              {tr("exploration.legend.edges", "Edges")}
            </p>
            {[...EDGE_KINDS, "bridged" as const].map((kind) => {
              const m = EDGE_META[kind];
              return (
                <div key={kind} className="flex items-center gap-2">
                  <svg width="22" height="6" className="shrink-0" aria-hidden>
                    <line
                      x1="0"
                      y1="3"
                      x2="22"
                      y2="3"
                      stroke={m.color}
                      strokeWidth="2"
                      strokeDasharray={kind === "bridged" ? "3 3" : kind === "proves" ? "5 3" : undefined}
                    />
                  </svg>
                  <span className="font-mono text-[10px]">{m.label}</span>
                  <span className="truncate text-[10px] text-muted-foreground" title={m.description}>
                    {m.description}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
