import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import type { TooltipProps } from "recharts";
import { fmtTime } from "../lib/format";
import type { useChartColors } from "../lib/hooks";
import { SEVERITIES, type Stats } from "../types";

type Colors = ReturnType<typeof useChartColors>;

function ChartTooltip({ active, payload, label, labelFmt }: TooltipProps<number, string> & { labelFmt?: (l: string) => string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-line bg-raised px-3 py-2 text-xs shadow-xl">
      <div className="mb-1 font-medium text-ink">{labelFmt ? labelFmt(String(label)) : label}</div>
      {payload.map((p) => (
        <div key={String(p.dataKey)} className="flex items-center gap-2 text-ink2">
          <span className="inline-block h-2 w-2 rounded-full" style={{ background: p.color }} />
          <span>{p.name}</span>
          <span className="tabular ml-auto pl-3 font-medium text-ink">{p.value}</span>
        </div>
      ))}
    </div>
  );
}

const axisProps = (c: Colors) => ({
  stroke: c.axis,
  tick: { fill: c.axis, fontSize: 11 },
  tickLine: false,
  axisLine: { stroke: c.grid },
});

export function TimelineChart({ stats, colors }: { stats: Stats; colors: Colors }) {
  const pts = stats.timeline.points;
  const showDate = pts.length > 1 && new Date(pts[0].time).toDateString() !== new Date(pts[pts.length - 1].time).toDateString();
  const tick = (t: string) => {
    const d = new Date(t);
    return showDate
      ? d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
      : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  };
  return (
    <ResponsiveContainer width="100%" height={260}>
      <AreaChart data={pts} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
        <CartesianGrid stroke={colors.grid} vertical={false} />
        <XAxis dataKey="time" tickFormatter={tick} minTickGap={40} {...axisProps(colors)} />
        <YAxis allowDecimals={false} {...axisProps(colors)} />
        <Tooltip content={<ChartTooltip labelFmt={(l) => fmtTime(l)} />} cursor={{ stroke: colors.axis, strokeDasharray: "3 3" }} />
        <Legend wrapperStyle={{ fontSize: 12, color: colors.axis }} iconType="circle" iconSize={8} />
        <Area isAnimationActive={false} type="monotone" dataKey="success" name="Successful" stroke={colors.success} fill={colors.success} fillOpacity={0.12} strokeWidth={2} dot={false} />
        <Area isAnimationActive={false} type="monotone" dataKey="failure" name="Failed" stroke={colors.failure} fill={colors.failure} fillOpacity={0.12} strokeWidth={2} dot={false} />
        <Area isAnimationActive={false} type="monotone" dataKey="flagged" name="Flagged (≥ MEDIUM)" stroke={colors.flagged} fill="none" strokeWidth={2} strokeDasharray="5 3" dot={false} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function SeverityChart({ data, colors, label }: { data: Record<string, number>; colors: Colors; label: string }) {
  const rows = SEVERITIES.map((s) => ({ severity: s, count: data[s] ?? 0 }));
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={rows} margin={{ top: 16, right: 8, left: -16, bottom: 0 }} barCategoryGap="22%">
        <CartesianGrid stroke={colors.grid} vertical={false} />
        <XAxis dataKey="severity" {...axisProps(colors)} />
        <YAxis allowDecimals={false} {...axisProps(colors)} />
        <Tooltip content={<ChartTooltip />} cursor={{ fill: colors.grid, opacity: 0.4 }} />
        <Bar isAnimationActive={false} dataKey="count" name={label} radius={[4, 4, 0, 0]} label={{ position: "top", fill: colors.axis, fontSize: 11 }}>
          {rows.map((r) => <Cell key={r.severity} fill={colors.sev[r.severity]} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function HBarChart({ rows, colors, name, height }: { rows: { label: string; value: number }[]; colors: Colors; name: string; height?: number }) {
  return (
    <ResponsiveContainer width="100%" height={height ?? Math.max(160, rows.length * 34)}>
      <BarChart data={rows} layout="vertical" margin={{ top: 0, right: 36, left: 8, bottom: 0 }} barCategoryGap="25%">
        <CartesianGrid stroke={colors.grid} horizontal={false} />
        <XAxis type="number" allowDecimals={false} {...axisProps(colors)} />
        <YAxis type="category" dataKey="label" width={120} {...axisProps(colors)} tick={{ fill: colors.axis, fontSize: 11 }} />
        <Tooltip content={<ChartTooltip />} cursor={{ fill: colors.grid, opacity: 0.4 }} />
        <Bar isAnimationActive={false} dataKey="value" name={name} fill={colors.bar} radius={[0, 4, 4, 0]} label={{ position: "right", fill: colors.axis, fontSize: 11 }} />
      </BarChart>
    </ResponsiveContainer>
  );
}

/** Success vs failure as one split bar with direct labels (no pie). */
export function SplitBar({ success, failure, colors }: { success: number; failure: number; colors: Colors }) {
  const total = success + failure;
  const sp = total ? (success / total) * 100 : 50;
  return (
    <div>
      <div className="mb-2 flex justify-between text-sm">
        <span className="flex items-center gap-2 text-ink2"><span className="h-2.5 w-2.5 rounded-full" style={{ background: colors.success }} />Successful <b className="tabular text-ink">{success.toLocaleString()}</b></span>
        <span className="flex items-center gap-2 text-ink2">Failed <b className="tabular text-ink">{failure.toLocaleString()}</b><span className="h-2.5 w-2.5 rounded-full" style={{ background: colors.failure }} /></span>
      </div>
      <div className="flex h-3 w-full gap-[2px] overflow-hidden rounded-full" role="img" aria-label={`${success} successful and ${failure} failed logins`}>
        {total > 0 ? (
          <>
            <div style={{ width: `${sp}%`, background: colors.success }} className="rounded-l-full" />
            <div style={{ width: `${100 - sp}%`, background: colors.failure }} className="rounded-r-full" />
          </>
        ) : (
          <div className="w-full bg-line" />
        )}
      </div>
      <div className="mt-2 flex justify-between text-xs text-muted tabular">
        <span>{total ? `${Math.round(sp)}%` : "—"}</span>
        <span>{total ? `${Math.round(100 - sp)}% failure rate` : "no login events"}</span>
      </div>
    </div>
  );
}
