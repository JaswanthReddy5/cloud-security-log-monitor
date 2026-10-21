import { Download, FileUp, Sparkles, Trash2, UploadCloud } from "lucide-react";
import { useRef, useState } from "react";
import { api, ApiError, getAdminKey } from "../api";
import { ErrorBox, Modal, Panel, SeverityBadge } from "../components/ui";
import { fmtRelative } from "../lib/format";
import { useAsync } from "../lib/hooks";
import type { IngestSummary, Severity } from "../types";

function SummaryCard({ s }: { s: IngestSummary }) {
  const b = s.batch;
  return (
    <div className="rounded-lg border border-good/40 bg-good/5 p-3 text-sm">
      <p className="font-medium text-ink">Ingestion #{b.id} complete ({b.source}{b.filename ? ` · ${b.filename}` : ""})</p>
      <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-5">
        {([["Received", b.received], ["Imported", b.imported], ["Rejected", b.rejected], ["Analyzed", b.analyzed], ["Alerts", b.alerts_created]] as const).map(([k, v]) => (
          <div key={k} className="rounded-md bg-raised px-2 py-1.5"><div className="text-[11px] uppercase text-muted">{k}</div><div className="tabular text-base font-semibold">{v}</div></div>
        ))}
      </div>
      <div className="mt-2 flex flex-wrap gap-2">
        {(Object.entries(s.alerts_by_severity) as [Severity, number][]).filter(([, n]) => n > 0).map(([sev, n]) => (
          <span key={sev} className="inline-flex items-center gap-1 text-xs text-ink2"><SeverityBadge severity={sev} /> × {n}</span>
        ))}
      </div>
      {s.rejected_samples.length > 0 && (
        <details className="mt-2 text-xs text-muted">
          <summary className="cursor-pointer">Show rejected rows ({b.rejected})</summary>
          <ul className="mt-1 list-disc pl-5">{s.rejected_samples.map((r) => <li key={r.row}>Row {r.row}: {r.reason}</li>)}</ul>
        </details>
      )}
    </div>
  );
}

export default function Ingest({ refreshKey, onIngested, toast, adminEnabled }: {
  refreshKey: number; onIngested: () => void; toast: (k: "success" | "error", t: string) => void; adminEnabled: boolean;
}) {
  const [count, setCount] = useState(250);
  const [busy, setBusy] = useState<"gen" | "up" | "reset" | null>(null);
  const [summary, setSummary] = useState<IngestSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [drag, setDrag] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirmText, setConfirmText] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);
  const batches = useAsync(() => api.batches(), [refreshKey]);

  const run = async (kind: "gen" | "up", fn: () => Promise<{ data: IngestSummary }>) => {
    setBusy(kind); setError(null);
    try {
      const r = await fn();
      setSummary(r.data);
      toast("success", `Imported ${r.data.batch.imported} events, ${r.data.batch.alerts_created} alerts raised`);
      onIngested();
    } catch (e) {
      const msg = e instanceof ApiError && e.details && typeof e.details === "object" && "rejected_samples" in e.details
        ? `${e.message} First issue: ${(e.details as { rejected_samples: { reason: string }[] }).rejected_samples[0]?.reason ?? ""}`
        : e instanceof Error ? e.message : String(e);
      setError(msg);
      toast("error", msg);
    } finally { setBusy(null); }
  };

  const onFile = (f: File | undefined) => {
    if (!f) return;
    if (!/\.(csv|json|jsonl|ndjson)$/i.test(f.name)) { setError("Only .csv, .json, .jsonl or .ndjson files are accepted."); return; }
    if (f.size > 2 * 1024 * 1024) { setError("File too large (max 2 MB)."); return; }
    run("up", () => api.upload(f));
    if (fileRef.current) fileRef.current.value = "";
  };

  const doReset = async () => {
    setBusy("reset");
    try {
      const r = await api.reset();
      toast("success", `Deleted ${r.data.deleted.events} events and ${r.data.deleted.alerts} alerts`);
      setSummary(null); setConfirmOpen(false); setConfirmText("");
      onIngested();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Reset failed");
    } finally { setBusy(null); }
  };

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <Panel title="Generate synthetic logs" subtitle="Normal traffic plus brute force, password spraying, distributed attack, success-after-failures, off-hours admin login, failure burst and malformed rows.">
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label className="label" htmlFor="count">Baseline events</label>
            <input id="count" type="number" className="input !w-32" min={0} max={2000} value={count}
              onChange={(e) => setCount(Math.max(0, Math.min(2000, Number(e.target.value) || 0)))} />
          </div>
          <button className="btn-primary" disabled={busy !== null} onClick={() => run("gen", () => api.generate(count))}>
            <Sparkles size={16} />{busy === "gen" ? "Generating…" : "Generate & analyze"}
          </button>
        </div>
        <p className="mt-3 text-xs text-muted">All generated IPs are from reserved documentation (RFC 5737) or private ranges. Usernames are fictional.</p>
      </Panel>

      <Panel title="Upload log file" subtitle="CSV or JSON, max 2 MB / 5,000 records. Files are parsed as data only — never executed.">
        <div
          className={`flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed p-6 text-center transition-colors ${drag ? "border-accent bg-accent/5" : "border-line hover:border-muted/60"}`}
          onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
          onDrop={(e) => { e.preventDefault(); setDrag(false); onFile(e.dataTransfer.files[0]); }}
          onClick={() => fileRef.current?.click()} role="button" tabIndex={0}
          onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && fileRef.current?.click()}>
          <UploadCloud className="text-muted" size={28} />
          <p className="text-sm text-ink2">{busy === "up" ? "Uploading & analyzing…" : <>Drop a file here or <span className="text-accent">browse</span></>}</p>
          <p className="text-xs text-muted">Columns: timestamp, source_ip, username, event_type and/or status</p>
          <input ref={fileRef} type="file" accept=".csv,.json,.jsonl,.ndjson,text/csv,application/json" className="hidden"
            onChange={(e) => onFile(e.target.files?.[0])} aria-label="Upload log file" />
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <a className="btn-ghost" href={api.sampleUrl("csv")} download><Download size={14} /> Sample CSV</a>
          <a className="btn-ghost" href={api.sampleUrl("json")} download><Download size={14} /> Sample JSON</a>
        </div>
      </Panel>

      <div className="flex flex-col gap-3 lg:col-span-2">
        {error && <ErrorBox message={error} />}
        {summary && <SummaryCard s={summary} />}
      </div>

      <Panel title="Recent ingestions" className="lg:col-span-2">
        {batches.error ? <ErrorBox message={batches.error} onRetry={batches.reload} /> : (
          <div className="-mx-4 overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-line"><tr>
                <th className="th">#</th><th className="th">When</th><th className="th">Source</th><th className="th">Imported</th>
                <th className="th">Rejected</th><th className="th">Analyzed</th><th className="th">Alerts</th><th className="th">Data</th>
              </tr></thead>
              <tbody className="divide-y divide-line">
                {(batches.data?.data ?? []).map((b) => (
                  <tr key={b.id}>
                    <td className="td tabular">{b.id}</td><td className="td">{fmtRelative(b.created_at)}</td>
                    <td className="td"><span className="inline-flex items-center gap-1"><FileUp size={12} /> {b.source}{b.filename ? ` · ${b.filename}` : ""}</span></td>
                    <td className="td tabular">{b.imported}</td><td className="td tabular">{b.rejected}</td>
                    <td className="td tabular">{b.analyzed}</td><td className="td tabular">{b.alerts_created}</td>
                    <td className="td text-xs">{b.is_synthetic ? "synthetic" : "uploaded"}</td>
                  </tr>
                ))}
                {batches.data?.data.length === 0 && <tr><td className="td text-muted" colSpan={8}>No ingestions yet.</td></tr>}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title="Reset demo data" subtitle="Deletes all events, alerts and ingestion history. Admin key required." className="lg:col-span-2">
        <div className="flex flex-wrap items-center gap-3">
          <button className="btn-danger" disabled={!adminEnabled || busy !== null} onClick={() => setConfirmOpen(true)}><Trash2 size={14} /> Reset all data…</button>
          <span className="text-xs text-muted">
            {!adminEnabled ? "Disabled: the server has no ADMIN_API_KEY configured."
              : getAdminKey() ? "Admin key loaded for this browser session." : "Enter the admin key on the Settings tab first."}
          </span>
        </div>
      </Panel>

      <Modal open={confirmOpen} title="Reset all data?" onClose={() => setConfirmOpen(false)}>
        <p className="text-sm text-ink2">This permanently deletes every stored event, alert and ingestion record. Type <b className="font-mono">RESET</b> to confirm.</p>
        <input className="input mt-3 font-mono" value={confirmText} onChange={(e) => setConfirmText(e.target.value)} placeholder="RESET" aria-label="Type RESET to confirm" autoFocus />
        <div className="mt-4 flex justify-end gap-2">
          <button className="btn-ghost" onClick={() => setConfirmOpen(false)}>Cancel</button>
          <button className="btn-danger" disabled={confirmText !== "RESET" || busy === "reset"} onClick={doReset}>{busy === "reset" ? "Deleting…" : "Delete everything"}</button>
        </div>
      </Modal>
    </div>
  );
}
