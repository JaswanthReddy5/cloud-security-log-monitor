export function fmtNumber(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  return new Intl.NumberFormat("en-US").format(n);
}

export function fmtTime(iso: string | null | undefined, withDate = true): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    month: withDate ? "short" : undefined,
    day: withDate ? "numeric" : undefined,
    hour: "2-digit",
    minute: "2-digit",
    second: withDate ? "2-digit" : undefined,
  });
}

export function fmtRelative(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return "—";
  const diff = Math.round((now - new Date(iso).getTime()) / 1000);
  if (Number.isNaN(diff)) return "—";
  if (diff < 60) return `${Math.max(diff, 0)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export function pct(part: number, whole: number): string {
  if (!whole) return "0%";
  return `${Math.round((part / whole) * 100)}%`;
}

export function humanize(s: string): string {
  return s
    .toLowerCase()
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}
