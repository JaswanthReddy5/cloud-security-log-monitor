import { CheckCircle2, Clock, Globe, RotateCcw, User } from "lucide-react";
import { useState } from "react";
import { api } from "../api";
import { EmptyState, ErrorBox, Pagination, Panel, SeverityBadge, Spinner } from "../components/ui";
import { fmtRelative, fmtTime } from "../lib/format";
import { useAsync, useDebounced } from "../lib/hooks";
import { SEVERITIES, type Alert } from "../types";

export default function Alerts({ refreshKey, onChanged, toast }: {
  refreshKey: number; onChanged: () => void; toast: (kind: "success" | "error", text: string) => void;
}) {
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("open");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [busy, setBusy] = useState<number | null>(null);
  const q = useDebounced(search);
  const { data, error, reload } = useAsync(
    () => api.alerts({ severity, status, search: q, page, page_size: 20, sort: "severity", order: "desc" }),
    [severity, status, q, page, refreshKey],
  );

  const toggle = async (a: Alert) => {
    setBusy(a.id);
    try {
      await api.ackAlert(a.id, !a.acknowledged);
      toast("success", a.acknowledged ? `Alert #${a.id} reopened` : `Alert #${a.id} acknowledged`);
      await reload();
      onChanged();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Failed to update alert");
    } finally {
      setBusy(null);
    }
  };

  return (
    <Panel title="Alerts" subtitle="Rule-based detections for review. An alert is a signal, not proof of compromise.">
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="inline-flex rounded-lg border border-line bg-raised p-0.5" role="tablist" aria-label="Alert status">
          {["open", "acknowledged", "all"].map((s) => (
            <button key={s} role="tab" aria-selected={status === s}
              className={`rounded-md px-3 py-1.5 text-xs font-medium capitalize ${status === s ? "bg-panel text-ink shadow" : "text-muted hover:text-ink"}`}
              onClick={() => { setStatus(s); setPage(1); }}>{s}</button>
          ))}
        </div>
        <select className="input !w-44" value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }} aria-label="Filter by severity">
          <option value="">All severities</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <input className="input !w-64" placeholder="Search title, IP, user…" value={search} maxLength={100}
          onChange={(e) => { setSearch(e.target.value); setPage(1); }} aria-label="Search alerts" />
      </div>

      {error ? <ErrorBox message={error} onRetry={reload} /> : !data ? <Spinner /> : data.data.length === 0 ? (
        <EmptyState title={status === "open" ? "No open alerts" : "No alerts match these filters"}>
          Generate demo logs from the header to create sample alerts.
        </EmptyState>
      ) : (
        <>
          <ul className="flex flex-col gap-2">
            {data.data.map((a) => (
              <li key={a.id} className={`rounded-lg border p-3 transition-colors ${a.acknowledged ? "border-line bg-raised/30 opacity-75" : "border-line bg-raised/60"}`}>
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={a.severity} />
                      <span className="rounded border border-line px-1.5 py-0.5 font-mono text-[10px] text-muted">{a.rule_id}</span>
                      {a.acknowledged && <span className="inline-flex items-center gap-1 text-xs text-good"><CheckCircle2 size={12} /> Acknowledged {fmtRelative(a.acknowledged_at)}</span>}
                    </div>
                    <h3 className="mt-1.5 text-sm font-semibold text-ink">{a.title}</h3>
                    <p className="mt-1 text-sm text-ink2">{a.description}</p>
                    <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted">
                      <span className="inline-flex items-center gap-1"><Clock size={12} /> Detected {fmtTime(a.detected_at)}</span>
                      {a.source_ip && <span className="inline-flex items-center gap-1 font-mono"><Globe size={12} /> {a.source_ip}</span>}
                      {a.username && <span className="inline-flex items-center gap-1"><User size={12} /> {a.username}</span>}
                      {a.failed_attempts != null && <span className="tabular">Count {a.failed_attempts}{a.threshold != null ? ` / threshold ${a.rule_id === "HIGH_FAILURE_RATE" ? `${Math.round(a.threshold * 100)}%` : a.threshold}` : ""}</span>}
                      {a.window_start && <span>Window {fmtTime(a.window_start)} → {fmtTime(a.window_end, false)}</span>}
                    </div>
                  </div>
                  <button className={a.acknowledged ? "btn-ghost" : "btn-primary"} disabled={busy === a.id} onClick={() => toggle(a)}>
                    {a.acknowledged ? <><RotateCcw size={14} /> Unacknowledge</> : <><CheckCircle2 size={14} /> Acknowledge</>}
                  </button>
                </div>
              </li>
            ))}
          </ul>
          {data.meta && <Pagination meta={data.meta} onPage={setPage} />}
        </>
      )}
    </Panel>
  );
}
