import { Bell, Database, FlaskConical, LayoutDashboard, List, Moon, RefreshCw, Settings as SettingsIcon, Shield, Sparkles, Sun, Upload } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import { Toasts, type ToastMsg } from "./components/ui";
import { useAsync, useChartColors, useTheme } from "./lib/hooks";
import Alerts from "./pages/Alerts";
import Dashboard from "./pages/Dashboard";
import Events from "./pages/Events";
import Ingest from "./pages/Ingest";
import Settings from "./pages/Settings";

const TABS = [
  { id: "dashboard", label: "Dashboard", Icon: LayoutDashboard },
  { id: "events", label: "Events", Icon: List },
  { id: "alerts", label: "Alerts", Icon: Bell },
  { id: "ingest", label: "Ingest", Icon: Upload },
  { id: "settings", label: "Settings", Icon: SettingsIcon },
] as const;
type TabId = (typeof TABS)[number]["id"];

const tabFromHash = (): TabId => {
  const h = window.location.hash.replace("#", "");
  return (TABS.find((t) => t.id === h)?.id ?? "dashboard") as TabId;
};

export default function App() {
  const [theme, toggleTheme] = useTheme();
  const colors = useChartColors(theme);
  const [tab, setTab] = useState<TabId>(tabFromHash);
  const [refreshKey, setRefreshKey] = useState(0);
  const [toasts, setToasts] = useState<ToastMsg[]>([]);
  const [generating, setGenerating] = useState(false);

  const health = useAsync(() => api.health().then((r) => r.data).catch(() => null), []);
  const stats = useAsync(() => api.stats().then((r) => r.data), [refreshKey]);

  useEffect(() => {
    const onHash = () => setTab(tabFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const go = (t: string) => { window.location.hash = t; };
  const refresh = useCallback(() => setRefreshKey((k) => k + 1), []);
  const toast = useCallback((kind: ToastMsg["kind"], text: string) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t.slice(-3), { id, kind, text }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 5000);
  }, []);

  const generate = async () => {
    setGenerating(true);
    try {
      const r = await api.generate(250);
      toast("success", `Generated ${r.data.batch.imported} synthetic events → ${r.data.batch.alerts_created} alerts`);
      refresh();
    } catch (e) {
      toast("error", e instanceof Error ? e.message : "Generation failed");
    } finally { setGenerating(false); }
  };

  const h = health.data;
  const dbOk = h?.database.reachable;
  const s = stats.data;
  const openAlerts = s?.alerts.open ?? 0;

  return (
    <div className="min-h-screen">
      {/* Demo-data banner: always visible so synthetic data can't be mistaken for real monitoring */}
      <div className="border-b border-warn/30 bg-warn/10 px-4 py-1.5 text-center text-xs text-warn">
        <FlaskConical size={12} className="mr-1 inline" aria-hidden />
        <b>Educational demo.</b>{" "}
        {s && s.data_mode.synthetic_events > 0
          ? `${s.data_mode.synthetic_events.toLocaleString()} of ${s.total_events.toLocaleString()} events are SYNTHETIC. `
          : s && s.total_events > 0 ? "Showing user-uploaded sample logs. " : ""}
        This dashboard does not monitor real infrastructure. Detections are rule-based signals, not proof of compromise.
      </div>

      <header className="sticky top-0 z-40 border-b border-line bg-page/90 backdrop-blur">
        <div className="mx-auto flex max-w-[1400px] flex-wrap items-center gap-3 px-4 py-3">
          <div className="flex items-center gap-2">
            <div className="rounded-lg bg-accent/15 p-1.5 text-accent"><Shield size={20} /></div>
            <div>
              <h1 className="text-sm font-semibold leading-tight">SecLog Monitor</h1>
              <p className="text-[11px] leading-tight text-muted">Cloud security log monitoring</p>
            </div>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <span className={`hidden items-center gap-1.5 rounded-md border px-2 py-1 text-xs sm:inline-flex ${
              h == null ? "border-line text-muted" : dbOk ? "border-good/40 text-good" : "border-crit/40 text-crit"}`}
              title={h ? `${h.database.dialect ?? "no"} database · ${h.environment} · v${h.version}` : "API unreachable"}>
              <Database size={12} />
              {h == null ? "API offline" : dbOk ? `DB online · ${h.database.dialect}` : "DB unavailable"}
            </span>
            <button className="btn-ghost !px-2.5" onClick={refresh} aria-label="Refresh data" title="Refresh"><RefreshCw size={15} className={stats.loading ? "animate-spin" : ""} /></button>
            <button className="btn-ghost !px-2.5" onClick={toggleTheme} aria-label="Toggle theme" title="Toggle light/dark">{theme === "dark" ? <Sun size={15} /> : <Moon size={15} />}</button>
            <button className="btn-primary" onClick={generate} disabled={generating}><Sparkles size={15} /><span className="hidden sm:inline">{generating ? "Generating…" : "Generate demo logs"}</span></button>
          </div>
        </div>
        <nav className="mx-auto flex max-w-[1400px] gap-1 overflow-x-auto px-4" aria-label="Sections">
          {TABS.map(({ id, label, Icon }) => (
            <button key={id} onClick={() => go(id)} aria-current={tab === id ? "page" : undefined}
              className={`inline-flex items-center gap-1.5 whitespace-nowrap border-b-2 px-3 py-2 text-sm font-medium transition-colors ${
                tab === id ? "border-accent text-ink" : "border-transparent text-muted hover:text-ink"}`}>
              <Icon size={15} /> {label}
              {id === "alerts" && openAlerts > 0 && <span className="tabular rounded-full bg-crit/20 px-1.5 text-[11px] text-crit">{openAlerts}</span>}
            </button>
          ))}
        </nav>
      </header>

      <main className="mx-auto max-w-[1400px] px-4 py-5">
        {h && !dbOk && (
          <div className="mb-4 rounded-lg border border-crit/40 bg-crit/10 px-3 py-2 text-sm text-crit" role="alert">
            The database is {h.database.configured ? "unreachable" : "not configured (set DATABASE_URL)"}. Data cannot be loaded or stored.
          </div>
        )}
        {tab === "dashboard" && <Dashboard stats={s} statsError={stats.error} colors={colors} refreshKey={refreshKey} onGenerate={generate} generating={generating} go={go} />}
        {tab === "events" && <Events refreshKey={refreshKey} />}
        {tab === "alerts" && <Alerts refreshKey={refreshKey} onChanged={refresh} toast={toast} />}
        {tab === "ingest" && <Ingest refreshKey={refreshKey} onIngested={refresh} toast={toast} adminEnabled={Boolean(h?.admin_enabled)} />}
        {tab === "settings" && <Settings adminEnabled={Boolean(h?.admin_enabled)} toast={toast} onChanged={refresh} />}
      </main>

      <footer className="mx-auto max-w-[1400px] px-4 pb-8 pt-2 text-xs text-muted">
        Cloud-Based Security Log Monitoring · College portfolio project · Synthetic data uses RFC 5737 documentation IP ranges.
      </footer>
      <Toasts items={toasts} onDismiss={(id) => setToasts((t) => t.filter((x) => x.id !== id))} />
    </div>
  );
}
