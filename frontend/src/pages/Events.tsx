import { ArrowDown, ArrowUp, ArrowUpDown, Search } from "lucide-react";
import { Fragment, useState } from "react";
import { api } from "../api";
import { EmptyState, ErrorBox, Pagination, Panel, SeverityBadge, Spinner, StatusPill } from "../components/ui";
import { fmtTime, humanize } from "../lib/format";
import { useAsync, useDebounced } from "../lib/hooks";
import { SEVERITIES } from "../types";

const EVENT_TYPES = ["LOGIN_SUCCESS", "LOGIN_FAILURE", "LOGOUT", "PASSWORD_RESET", "ACCOUNT_LOCKED", "MFA_FAILURE", "MALFORMED"];
type SortKey = "timestamp" | "severity" | "source_ip" | "username" | "event_type";

export default function Events({ refreshKey }: { refreshKey: number }) {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [eventType, setEventType] = useState("");
  const [flagged, setFlagged] = useState(false);
  const [sort, setSort] = useState<SortKey>("timestamp");
  const [order, setOrder] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState(1);
  const [expanded, setExpanded] = useState<number | null>(null);
  const q = useDebounced(search);

  const { data, error, loading, reload } = useAsync(
    () => api.events({ search: q, severity, status, event_type: eventType, flagged: flagged || undefined, sort, order, page, page_size: 25 }),
    [q, severity, status, eventType, flagged, sort, order, page, refreshKey],
  );

  const reset = (fn: () => void) => { fn(); setPage(1); };
  const toggleSort = (k: SortKey) => {
    if (sort === k) setOrder((o) => (o === "asc" ? "desc" : "asc"));
    else { setSort(k); setOrder(k === "timestamp" || k === "severity" ? "desc" : "asc"); }
    setPage(1);
  };
  const SortTh = ({ k, children }: { k: SortKey; children: string }) => (
    <th className="th">
      <button className="inline-flex items-center gap-1 hover:text-ink" onClick={() => toggleSort(k)} aria-label={`Sort by ${children}`}>
        {children}
        {sort === k ? (order === "asc" ? <ArrowUp size={12} /> : <ArrowDown size={12} />) : <ArrowUpDown size={12} className="opacity-40" />}
      </button>
    </th>
  );

  return (
    <Panel title="Security events" subtitle="Normalized log events. Click a row for details.">
      <div className="mb-4 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-[1fr_repeat(3,170px)_auto]">
        <label className="relative">
          <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input className="input pl-8" placeholder="Search IP, username, description…" value={search} maxLength={100}
            onChange={(e) => reset(() => setSearch(e.target.value))} aria-label="Search events" />
        </label>
        <select className="input" value={severity} onChange={(e) => reset(() => setSeverity(e.target.value))} aria-label="Filter by severity">
          <option value="">All severities</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="input" value={status} onChange={(e) => reset(() => setStatus(e.target.value))} aria-label="Filter by status">
          <option value="">All statuses</option>
          <option value="success">success</option><option value="failure">failure</option><option value="invalid">invalid</option>
        </select>
        <select className="input" value={eventType} onChange={(e) => reset(() => setEventType(e.target.value))} aria-label="Filter by event type">
          <option value="">All event types</option>
          {EVENT_TYPES.map((t) => <option key={t} value={t}>{humanize(t)}</option>)}
        </select>
        <label className="flex items-center gap-2 whitespace-nowrap text-sm text-ink2">
          <input type="checkbox" checked={flagged} onChange={(e) => reset(() => setFlagged(e.target.checked))} className="accent-[rgb(var(--accent))]" />
          Flagged only
        </label>
      </div>

      {error ? <ErrorBox message={error} onRetry={reload} /> : !data ? <Spinner /> : data.data.length === 0 ? (
        <EmptyState title="No events match these filters" />
      ) : (
        <div className={loading ? "opacity-60 transition-opacity" : ""}>
          <div className="-mx-4 overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-line"><tr>
                <SortTh k="timestamp">Time</SortTh><SortTh k="severity">Severity</SortTh><SortTh k="event_type">Event</SortTh>
                <th className="th">Status</th><SortTh k="source_ip">Source IP</SortTh><SortTh k="username">User</SortTh>
                <th className="th">Rule</th><th className="th">Count / Thr.</th>
              </tr></thead>
              <tbody className="divide-y divide-line">
                {data.data.map((e) => (
                  <Fragment key={e.id}>
                    <tr className="cursor-pointer hover:bg-raised/60" onClick={() => setExpanded(expanded === e.id ? null : e.id)}>
                      <td className="td tabular">{fmtTime(e.timestamp)}</td>
                      <td className="td"><SeverityBadge severity={e.severity} /></td>
                      <td className="td">{humanize(e.event_type)}</td>
                      <td className="td"><StatusPill status={e.status} /></td>
                      <td className="td font-mono text-xs">{e.source_ip ?? "—"}</td>
                      <td className="td">{e.username ?? "—"}</td>
                      <td className="td text-xs">{e.detection_rule ?? "—"}</td>
                      <td className="td tabular text-xs">{e.count != null ? `${e.count} / ${e.threshold ?? "—"}` : "—"}</td>
                    </tr>
                    {expanded === e.id && (
                      <tr className="bg-raised/40">
                        <td colSpan={8} className="px-4 py-3 text-sm text-ink2">
                          <p>{e.description}</p>
                          {e.raw && <pre className="mt-2 overflow-x-auto rounded bg-page p-2 font-mono text-xs text-muted">{e.raw}</pre>}
                          <p className="mt-2 text-xs text-muted">Event #{e.id} · batch #{e.batch_id} · {e.is_synthetic ? "synthetic demo data" : "uploaded data"}</p>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
          {data.meta && <Pagination meta={data.meta} onPage={setPage} />}
        </div>
      )}
    </Panel>
  );
}
