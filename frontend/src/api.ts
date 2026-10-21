import type { Alert, Batch, Health, IngestSummary, LogEvent, PageMeta, Rule, SettingsData, Stats } from "./types";

// Same-origin by default (Vercel serves the API at /api). Override for split hosting.
const BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, "") ?? "";

export class ApiError extends Error {
  status: number;
  code: string;
  details?: unknown;
  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

const ADMIN_KEY_STORAGE = "seclog.adminKey";

export function getAdminKey(): string {
  try {
    return sessionStorage.getItem(ADMIN_KEY_STORAGE) ?? "";
  } catch {
    return "";
  }
}

export function setAdminKey(key: string) {
  try {
    if (key) sessionStorage.setItem(ADMIN_KEY_STORAGE, key);
    else sessionStorage.removeItem(ADMIN_KEY_STORAGE);
  } catch {
    /* storage unavailable: key lives only for this call */
  }
}

async function request<T>(path: string, init: RequestInit & { admin?: boolean } = {}): Promise<{ data: T; meta?: PageMeta }> {
  const headers = new Headers(init.headers);
  if (init.body && !(init.body instanceof FormData)) headers.set("Content-Type", "application/json");
  if (init.admin) headers.set("X-Admin-Key", getAdminKey());
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, "network_error", "Cannot reach the API. Check your connection or the backend.");
  }
  let body: { ok: boolean; data?: T; meta?: PageMeta; error?: { code: string; message: string; details?: unknown } } | null = null;
  try {
    body = await res.json();
  } catch {
    /* non-JSON */
  }
  if (!res.ok || !body?.ok) {
    const err = body?.error;
    throw new ApiError(res.status, err?.code ?? "http_error", err?.message ?? `Request failed (${res.status})`, err?.details);
  }
  return { data: body.data as T, meta: body.meta };
}

function qs(params: Record<string, string | number | boolean | undefined | null>) {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") u.set(k, String(v));
  const s = u.toString();
  return s ? `?${s}` : "";
}

export const api = {
  health: () => request<Health>("/api/health"),
  stats: () => request<Stats>("/api/stats"),
  events: (p: Record<string, string | number | boolean | undefined>) => request<LogEvent[]>(`/api/events${qs(p)}`),
  alerts: (p: Record<string, string | number | boolean | undefined>) => request<Alert[]>(`/api/alerts${qs(p)}`),
  ackAlert: (id: number, acknowledged: boolean) =>
    request<Alert>(`/api/alerts/${id}`, { method: "PATCH", body: JSON.stringify({ acknowledged }) }),
  generate: (count: number) => request<IngestSummary>("/api/logs/generate", { method: "POST", body: JSON.stringify({ count }) }),
  upload: (file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    return request<IngestSummary>("/api/logs/upload", { method: "POST", body: fd });
  },
  batches: () => request<Batch[]>("/api/batches"),
  rules: () => request<Rule[]>("/api/rules"),
  settings: () => request<SettingsData>("/api/settings"),
  saveSettings: (thresholds: Record<string, number>) =>
    request<{ thresholds: Record<string, number> }>("/api/settings", { method: "PUT", body: JSON.stringify({ thresholds }), admin: true }),
  verifyAdmin: () => request<{ admin: boolean }>("/api/admin/verify", { method: "POST", admin: true }),
  reset: () => request<{ deleted: Record<string, number> }>("/api/admin/reset", { method: "POST", body: JSON.stringify({ confirm: "RESET" }), admin: true }),
  sampleUrl: (format: "csv" | "json") => `${BASE}/api/logs/sample?format=${format}`,
};
