import { Activity, AlertOctagon, Bell, Globe, KeyRound, ShieldAlert, Sparkles } from "lucide-react";
import { api } from "../api";
import { HBarChart, SeverityChart, SplitBar, TimelineChart } from "../components/charts";
import { EmptyState, ErrorBox, Kpi, Panel, SeverityBadge, Spinner, StatusPill } from "../components/ui";
import { fmtNumber, fmtRelative, fmtTime, humanize } from "../lib/format";
import { useAsync, type useChartColors } from "../lib/hooks";
import type { Stats } from "../types";

type Props = {
  stats: Stats | null;
  statsError: string | null;
  colors: ReturnType<typeof useChartColors>;
  refreshKey: number;
  onGenerate: () => void;
  generating: boolean;
  go: (tab: string) => void;
};

const eventTypeRows = (stats: Stats) =>
  Object.entries(stats.events_by_type).map(([k, v]) => ({ label: humanize(k), value: v }));

export default function Dashboard({ stats, statsError, colors, refreshKey, onGenerate, generating, go }: Props) {
  const recent = useAsync(() => api.events({ page_size: 10, sort: "timestamp", order: "desc" }), [refreshKey]);

  if (statsError && !stats) return <ErrorBox message={statsError} />;
  if (!stats) return <Spinner />;

  if (stats.total_events === 0) {
    return (
      <Panel>
        <EmptyState title="No log events yet">
          <p className="mb-4 max-w-md">Generate a synthetic dataset with realistic attack scenarios, or upload your own CSV/JSON logs from the Ingest tab.</p>
          <div className="flex justify-center gap-2">
            <button className="btn-primary" onClick={onGenerate} disabled={generating}><Sparkles size={16} />{generating ? "Generating…" : "Generate demo logs"}</button>
            <button className="btn-ghost" onClick={() => go("ingest")}>Upload logs</button>
          </div>
        </EmptyState>
      </Panel>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Kpi label="Events analyzed" value={fmtNumber(stats.total_events)} icon={<Activity size={16} />}
          hint={stats.malformed_events ? `${fmtNumber(stats.malformed_events)} malformed` : "all entries valid"} />
        <Kpi label="Failed logins" value={fmtNumber(stats.failed_logins)} icon={<KeyRound size={16} />} tone="serious"
          hint={`${fmtNumber(stats.successful_logins)} successful`} />
        <Kpi label="Suspicious IPs" value={fmtNumber(stats.suspicious_ips)} icon={<Globe size={16} />} tone="warn" hint="named in alerts" />
        <Kpi label="High events" value={fmtNumber(stats.high_events)} icon={<ShieldAlert size={16} />} tone="serious" hint="severity HIGH" />
        <Kpi label="Critical events" value={fmtNumber(stats.critical_events)} icon={<AlertOctagon size={16} />} tone="crit" hint="severity CRITICAL" />
        <Kpi label="Open alerts" value={fmtNumber(stats.alerts.open)} icon={<Bell size={16} />} tone={stats.alerts.open ? "crit" : "good"}
          hint={`${fmtNumber(stats.alerts.acknowledged)} acknowledged`} />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel title="Security event timeline" subtitle={`Login outcomes per ${stats.timeline.bucket_minutes}-minute bucket (UTC data, local display)`} className="xl:col-span-2">
          <TimelineChart stats={stats} colors={colors} />
        </Panel>
        <div className="flex flex-col gap-4">
          <Panel title="Successful vs failed logins">
            <SplitBar success={stats.successful_logins} failure={stats.failed_logins} colors={colors} />
          </Panel>
          <Panel title="Alerts by severity" actions={<button className="text-xs text-accent hover:underline" onClick={() => go("alerts")}>View alerts →</button>}>
            <div className="flex flex-col gap-1.5">
              {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) => (
                <div key={s} className="flex items-center justify-between text-sm">
                  <SeverityBadge severity={s} />
                  <span className="tabular font-medium text-ink">{stats.alerts.by_severity[s] ?? 0}</span>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Panel title="Events by severity" subtitle="After rule-based escalation">
          <SeverityChart data={stats.events_by_severity} colors={colors} label="Events" />
        </Panel>
        <Panel title="Events by type">
          <HBarChart rows={eventTypeRows(stats)} colors={colors} name="Events" />
        </Panel>
        <Panel title="Top failing source IPs">
          {stats.top_failing_ips.length ? (
            <HBarChart rows={stats.top_failing_ips.map((r) => ({ label: r.source_ip, value: r.failures }))} colors={colors} name="Failures" />
          ) : <EmptyState title="No failed logins" />}
        </Panel>
      </div>

      <Panel title="Recent security events" subtitle={stats.last_ingest ? `Last ingestion ${fmtRelative(stats.last_ingest.created_at)} (${stats.last_ingest.source})` : undefined}
        actions={<button className="text-xs text-accent hover:underline" onClick={() => go("events")}>All events →</button>}>
        {recent.error ? <ErrorBox message={recent.error} onRetry={recent.reload} /> : !recent.data ? <Spinner /> : (
          <div className="-mx-4 overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-line"><tr>
                <th className="th">Time</th><th className="th">Severity</th><th className="th">Event</th><th className="th">Status</th>
                <th className="th">Source IP</th><th className="th">User</th><th className="th">Rule</th>
              </tr></thead>
              <tbody className="divide-y divide-line">
                {recent.data.data.map((e) => (
                  <tr key={e.id} className="hover:bg-raised/60">
                    <td className="td tabular">{fmtTime(e.timestamp)}</td>
                    <td className="td"><SeverityBadge severity={e.severity} /></td>
                    <td className="td">{humanize(e.event_type)}</td>
                    <td className="td"><StatusPill status={e.status} /></td>
                    <td className="td font-mono text-xs">{e.source_ip ?? "—"}</td>
                    <td className="td">{e.username ?? "—"}</td>
                    <td className="td text-xs">{e.detection_rule ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
