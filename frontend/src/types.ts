export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export const SEVERITIES: Severity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

export interface LogEvent {
  id: number;
  batch_id: number | null;
  timestamp: string | null;
  source_ip: string | null;
  username: string | null;
  event_type: string;
  status: string;
  severity: Severity;
  description: string;
  detection_rule: string | null;
  count: number | null;
  threshold: number | null;
  is_synthetic: boolean;
  raw: string | null;
}

export interface Alert {
  id: number;
  batch_id: number | null;
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  source_ip: string | null;
  username: string | null;
  failed_attempts: number | null;
  threshold: number | null;
  window_start: string | null;
  window_end: string | null;
  detected_at: string;
  acknowledged: boolean;
  acknowledged_at: string | null;
  is_synthetic: boolean;
  details: Record<string, unknown>;
}

export interface Batch {
  id: number;
  source: string;
  filename: string | null;
  is_synthetic: boolean;
  received: number;
  imported: number;
  rejected: number;
  analyzed: number;
  alerts_created: number;
  created_at: string;
}

export interface IngestSummary {
  batch: Batch;
  alerts_by_severity: Record<Severity, number>;
  rejected_samples: { row: number; reason: string }[];
}

export interface TimelinePoint {
  time: string;
  success: number;
  failure: number;
  flagged: number;
  total: number;
}

export interface Stats {
  total_events: number;
  failed_logins: number;
  successful_logins: number;
  failure_events: number;
  malformed_events: number;
  suspicious_ips: number;
  high_events: number;
  critical_events: number;
  events_by_severity: Record<Severity, number>;
  events_by_type: Record<string, number>;
  alerts: {
    total: number;
    open: number;
    acknowledged: number;
    by_severity: Record<Severity, number>;
    by_rule: Record<string, number>;
  };
  top_failing_ips: { source_ip: string; failures: number }[];
  timeline: { bucket_minutes: number; points: TimelinePoint[] };
  data_mode: { synthetic_events: number; uploaded_events: number; is_demo: boolean };
  last_ingest: Batch | null;
}

export interface PageMeta {
  page: number;
  page_size: number;
  total: number;
  pages: number;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  settings: string[];
  current: Record<string, number>;
}

export interface SettingsData {
  thresholds: Record<string, number>;
  limits: Record<string, number>;
  admin_enabled: boolean;
}

export interface Health {
  status: "ok" | "degraded";
  version: string;
  environment: string;
  database: { configured: boolean; reachable: boolean; dialect: string | null };
  admin_enabled: boolean;
}
