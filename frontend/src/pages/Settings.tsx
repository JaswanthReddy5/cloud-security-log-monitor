import { KeyRound, Lock, Save, Unlock } from "lucide-react";
import { useEffect, useState } from "react";
import { api, getAdminKey, setAdminKey } from "../api";
import { ErrorBox, Panel, Spinner } from "../components/ui";
import { humanize } from "../lib/format";
import { useAsync } from "../lib/hooks";

const LABELS: Record<string, string> = {
  ip_failure_threshold: "Failures per IP",
  ip_failure_window_minutes: "IP window (min)",
  user_failure_threshold: "Failures per username",
  user_failure_window_minutes: "Username window (min)",
  distributed_ip_threshold: "Distinct IPs = distributed",
  failure_rate_threshold: "Failure rate (0–1)",
  failure_rate_window_minutes: "Rate window (min)",
  failure_rate_min_events: "Rate min. events",
  success_after_failures_threshold: "Failures before success",
  success_after_failures_window_minutes: "Success window (min)",
  spray_username_threshold: "Usernames per IP (spray)",
  spray_window_minutes: "Spray window (min)",
  off_hours_start_utc: "Off-hours start (UTC h)",
  off_hours_end_utc: "Off-hours end (UTC h)",
  malformed_alert_threshold: "Malformed rows per ingest",
};

export default function Settings({ adminEnabled, toast, onChanged }: {
  adminEnabled: boolean; toast: (k: "success" | "error", t: string) => void; onChanged: () => void;
}) {
  const rules = useAsync(() => api.rules(), []);
  const [values, setValues] = useState<Record<string, string>>({});
  const [key, setKey] = useState("");
  const [unlocked, setUnlocked] = useState(Boolean(getAdminKey()));
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!rules.data) return;
    const v: Record<string, string> = {};
    rules.data.data.forEach((r) => Object.entries(r.current).forEach(([k, n]) => (v[k] = String(n))));
    setValues(v);
  }, [rules.data]);

  const unlock = async () => {
    setAdminKey(key.trim());
    try {
      await api.verifyAdmin();
      setUnlocked(true); setKey("");
      toast("success", "Admin key verified for this browser session");
    } catch (e) {
      setAdminKey(""); setUnlocked(false);
      toast("error", e instanceof Error ? e.message : "Invalid key");
    }
  };

  const save = async () => {
    setSaving(true);
    try {
      const payload = Object.fromEntries(Object.entries(values).map(([k, v]) => [k, Number(v)]));
      await api.saveSettings(payload);
      toast("success", "Thresholds saved. New ingestions use the updated values.");
      rules.reload(); onChanged();
    } catch (e) {
      const details = (e as { details?: Record<string, string> }).details;
      toast("error", `${e instanceof Error ? e.message : "Save failed"}${details ? " " + Object.entries(details).map(([k, v]) => `${LABELS[k] ?? k}: ${v}`).join("; ") : ""}`);
    } finally { setSaving(false); }
  };

  return (
    <div className="flex flex-col gap-4">
      <Panel title="Administrator access" subtitle="Changing thresholds and resetting data require the server's admin key. The key is kept only in this tab's session storage.">
        {!adminEnabled ? (
          <p className="text-sm text-muted">Admin actions are disabled because ADMIN_API_KEY is not set on the server. The public demo is read/generate/upload/acknowledge only.</p>
        ) : unlocked ? (
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <span className="inline-flex items-center gap-2 text-good"><Unlock size={16} /> Admin mode active</span>
            <button className="btn-ghost" onClick={() => { setAdminKey(""); setUnlocked(false); }}><Lock size={14} /> Lock</button>
          </div>
        ) : (
          <form className="flex flex-wrap items-center gap-2" onSubmit={(e) => { e.preventDefault(); unlock(); }}>
            <KeyRound size={16} className="text-muted" />
            <input type="password" className="input !w-72" placeholder="Admin API key" value={key} onChange={(e) => setKey(e.target.value)} autoComplete="off" aria-label="Admin API key" />
            <button className="btn-primary" disabled={!key.trim()}>Unlock</button>
          </form>
        )}
      </Panel>

      <Panel title="Detection rules & thresholds" subtitle="Rule-based detections for demonstration and education. They highlight patterns worth reviewing; they do not prove compromise."
        actions={unlocked && adminEnabled ? <button className="btn-primary" onClick={save} disabled={saving}><Save size={14} />{saving ? "Saving…" : "Save thresholds"}</button> : undefined}>
        {rules.error ? <ErrorBox message={rules.error} onRetry={rules.reload} /> : !rules.data ? <Spinner /> : (
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            {rules.data.data.map((r) => (
              <div key={r.id} className="rounded-lg border border-line bg-raised/50 p-3">
                <div className="flex items-center justify-between gap-2">
                  <h3 className="text-sm font-semibold text-ink">{r.name}</h3>
                  <span className="font-mono text-[10px] text-muted">{r.id}</span>
                </div>
                <p className="mt-1 text-xs text-ink2">{r.description}</p>
                <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3">
                  {r.settings.map((s) => (
                    <label key={s} className="block">
                      <span className="label !normal-case !tracking-normal">{LABELS[s] ?? humanize(s)}</span>
                      <input className="input tabular" type="number" step={s === "failure_rate_threshold" ? 0.05 : 1}
                        value={values[s] ?? ""} disabled={!unlocked || !adminEnabled}
                        onChange={(e) => setValues((v) => ({ ...v, [s]: e.target.value }))} />
                    </label>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
