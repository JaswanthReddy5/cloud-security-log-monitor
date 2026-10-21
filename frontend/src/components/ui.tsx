import { AlertOctagon, AlertTriangle, ChevronLeft, ChevronRight, Info, Loader2, ShieldAlert, ShieldCheck, X } from "lucide-react";
import { useEffect, type ReactNode } from "react";
import type { PageMeta, Severity } from "../types";

const SEV_STYLE: Record<Severity, { cls: string; Icon: typeof Info }> = {
  INFO: { cls: "text-muted border-muted/40 bg-muted/10", Icon: Info },
  LOW: { cls: "text-accent border-accent/40 bg-accent/10", Icon: Info },
  MEDIUM: { cls: "text-warn border-warn/40 bg-warn/10", Icon: AlertTriangle },
  HIGH: { cls: "text-serious border-serious/40 bg-serious/10", Icon: ShieldAlert },
  CRITICAL: { cls: "text-crit border-crit/50 bg-crit/15", Icon: AlertOctagon },
};

/** Severity is always shown as icon + text label, never color alone. */
export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = SEV_STYLE[severity] ?? SEV_STYLE.INFO;
  return (
    <span className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-semibold tracking-wide ${s.cls}`}>
      <s.Icon size={12} aria-hidden />
      {severity}
    </span>
  );
}

export function StatusPill({ status }: { status: string }) {
  const map: Record<string, string> = {
    success: "text-good bg-good/10 border-good/30",
    failure: "text-serious bg-serious/10 border-serious/30",
    invalid: "text-warn bg-warn/10 border-warn/30",
  };
  return <span className={`rounded-md border px-1.5 py-0.5 text-[11px] font-medium ${map[status] ?? "text-muted border-line"}`}>{status}</span>;
}

export function Panel({ title, subtitle, actions, children, className = "" }: {
  title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header className="flex flex-wrap items-start justify-between gap-2 border-b border-line px-4 py-3">
          <div>
            {title && <h2 className="text-sm font-semibold text-ink">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-xs text-muted">{subtitle}</p>}
          </div>
          {actions}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Kpi({ label, value, hint, tone = "default", icon }: {
  label: string; value: ReactNode; hint?: ReactNode; tone?: "default" | "warn" | "serious" | "crit" | "good"; icon?: ReactNode;
}) {
  const toneCls = { default: "text-ink", warn: "text-warn", serious: "text-serious", crit: "text-crit", good: "text-good" }[tone];
  return (
    <div className="card flex flex-col gap-1 p-4">
      <div className="flex items-center justify-between text-xs font-medium uppercase tracking-wide text-muted">
        <span>{label}</span>
        <span className={toneCls}>{icon}</span>
      </div>
      <div className={`text-2xl font-semibold ${toneCls}`}>{value}</div>
      {hint && <div className="text-xs text-muted">{hint}</div>}
    </div>
  );
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-10 text-sm text-muted" role="status">
      <Loader2 className="animate-spin" size={16} /> {label}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-10 text-center">
      <ShieldCheck className="text-muted" size={28} />
      <p className="text-sm font-medium text-ink2">{title}</p>
      {children && <div className="text-xs text-muted">{children}</div>}
    </div>
  );
}

export function ErrorBox({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-crit/40 bg-crit/10 px-3 py-2 text-sm text-crit" role="alert">
      <span className="flex items-center gap-2"><AlertOctagon size={16} /> {message}</span>
      {onRetry && <button className="btn-ghost !py-1 text-xs" onClick={onRetry}>Retry</button>}
    </div>
  );
}

export function Pagination({ meta, onPage }: { meta: PageMeta; onPage: (p: number) => void }) {
  if (meta.total === 0) return null;
  const from = (meta.page - 1) * meta.page_size + 1;
  const to = Math.min(meta.page * meta.page_size, meta.total);
  return (
    <div className="flex items-center justify-between gap-2 pt-3 text-xs text-muted">
      <span className="tabular">{from}–{to} of {meta.total.toLocaleString()}</span>
      <div className="flex items-center gap-1">
        <button className="btn-ghost !px-2 !py-1" disabled={meta.page <= 1} onClick={() => onPage(meta.page - 1)} aria-label="Previous page">
          <ChevronLeft size={14} />
        </button>
        <span className="tabular px-2">Page {meta.page} / {Math.max(meta.pages, 1)}</span>
        <button className="btn-ghost !px-2 !py-1" disabled={meta.page >= meta.pages} onClick={() => onPage(meta.page + 1)} aria-label="Next page">
          <ChevronRight size={14} />
        </button>
      </div>
    </div>
  );
}

export function Modal({ open, title, children, onClose }: { open: boolean; title: string; children: ReactNode; onClose: () => void }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div role="dialog" aria-modal="true" aria-label={title} className="card w-full max-w-md p-5 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-base font-semibold">{title}</h3>
          <button className="text-muted hover:text-ink" onClick={onClose} aria-label="Close"><X size={18} /></button>
        </div>
        {children}
      </div>
    </div>
  );
}

export type ToastMsg = { id: number; kind: "success" | "error" | "info"; text: string };

export function Toasts({ items, onDismiss }: { items: ToastMsg[]; onDismiss: (id: number) => void }) {
  return (
    <div className="fixed bottom-4 right-4 z-50 flex w-[min(380px,calc(100vw-32px))] flex-col gap-2" aria-live="polite">
      {items.map((t) => (
        <div key={t.id} className={`card flex items-start justify-between gap-3 px-3 py-2.5 text-sm shadow-lg ${
          t.kind === "error" ? "border-crit/50" : t.kind === "success" ? "border-good/50" : ""}`}>
          <span className={t.kind === "error" ? "text-crit" : "text-ink2"}>{t.text}</span>
          <button className="text-muted hover:text-ink" onClick={() => onDismiss(t.id)} aria-label="Dismiss"><X size={14} /></button>
        </div>
      ))}
    </div>
  );
}
