import { useCallback, useEffect, useRef, useState } from "react";

export type Theme = "dark" | "light";

export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const t = localStorage.getItem("theme");
      if (t === "light" || t === "dark") return t;
    } catch {
      /* ignore */
    }
    return "dark";
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("theme", theme);
    } catch {
      /* ignore */
    }
  }, [theme]);
  return [theme, () => setTheme((t) => (t === "dark" ? "light" : "dark"))];
}

/** Read chart colors from CSS custom properties so charts follow the theme. */
export function useChartColors(theme: Theme) {
  const read = useCallback(() => {
    const cs = getComputedStyle(document.documentElement);
    const v = (n: string) => cs.getPropertyValue(n).trim();
    return {
      success: v("--chart-success"),
      failure: v("--chart-failure"),
      flagged: v("--chart-flagged"),
      grid: v("--chart-grid"),
      axis: v("--chart-axis"),
      bar: v("--chart-bar"),
      surface: `rgb(${v("--panel")})`,
      sev: {
        INFO: v("--sev-info"),
        LOW: v("--sev-low"),
        MEDIUM: v("--sev-medium"),
        HIGH: v("--sev-high"),
        CRITICAL: v("--sev-critical"),
      } as Record<string, string>,
    };
  }, []);
  const [colors, setColors] = useState(read);
  useEffect(() => {
    // theme attribute is applied in an effect; read on next frame
    const id = requestAnimationFrame(() => setColors(read()));
    return () => cancelAnimationFrame(id);
  }, [theme, read]);
  return colors;
}

/** Generic async loader with refresh + error state. */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const seq = useRef(0);
  const run = useCallback(async () => {
    const id = ++seq.current;
    setLoading(true);
    try {
      const d = await fn();
      if (id === seq.current) {
        setData(d);
        setError(null);
      }
    } catch (e) {
      if (id === seq.current) setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (id === seq.current) setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => {
    run();
  }, [run]);
  return { data, error, loading, reload: run };
}

export function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}
