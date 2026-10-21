"""Business logic: settings, ingestion pipeline, alert management, statistics."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import case, delete, func, or_, select
from sqlalchemy.orm import Session

from .config import DEFAULT_THRESHOLDS, THRESHOLD_BOUNDS
from .detection import Detection, malformed_detection, run_detection
from .errors import ApiError, ValidationFailed
from .models import SEVERITIES, SEVERITY_RANK, Alert, AppSetting, IngestBatch, LogEvent, as_utc
from .parsing import ParseResult

# ---------------------------------------------------------------- settings


def get_thresholds(sess: Session) -> dict:
    values = dict(DEFAULT_THRESHOLDS)
    for row in sess.scalars(select(AppSetting)):
        if row.key in values:
            values[row.key] = row.value
    # Keep integer-valued settings as ints for clean JSON.
    return {k: (int(v) if float(v).is_integer() and k != "failure_rate_threshold" else v) for k, v in values.items()}


def update_thresholds(sess: Session, updates: dict) -> dict:
    if not isinstance(updates, dict) or not updates:
        raise ValidationFailed("Provide a JSON object of threshold values to update.")
    errors = {}
    clean: dict[str, float] = {}
    for key, value in updates.items():
        if key not in THRESHOLD_BOUNDS:
            errors[key] = "unknown setting"
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            errors[key] = "must be a number"
            continue
        lo, hi = THRESHOLD_BOUNDS[key]
        if not lo <= value <= hi:
            errors[key] = f"must be between {lo} and {hi}"
            continue
        clean[key] = float(value)
    if errors:
        raise ValidationFailed("Invalid settings.", details=errors)
    for key, value in clean.items():
        row = sess.get(AppSetting, key)
        if row is None:
            sess.add(AppSetting(key=key, value=value))
        else:
            row.value = value
    sess.flush()
    return get_thresholds(sess)


# ---------------------------------------------------------------- ingestion


def _escalate(event: LogEvent, det: Detection) -> None:
    if SEVERITY_RANK[det.severity] > SEVERITY_RANK[event.severity]:
        event.severity = det.severity
        event.detection_rule = det.rule_id
        event.rule_count = det.count
        event.rule_threshold = det.threshold
        event.description = f"{event.description} Flagged by {det.rule_id}: {det.title}."


def _base_description(rec) -> str:
    verb = {
        "LOGIN_SUCCESS": "Successful login",
        "LOGIN_FAILURE": "Failed login",
        "LOGOUT": "Logout",
        "PASSWORD_RESET": "Password reset",
        "ACCOUNT_LOCKED": "Account locked",
        "MFA_FAILURE": "MFA challenge failed",
    }[rec.event_type]
    return f"{verb} for '{rec.username}' from {rec.source_ip}."


def ingest(sess: Session, result: ParseResult, *, source: str, filename: str | None, is_synthetic: bool,
           client_hash: str | None, max_stored_events: int) -> dict:
    """Store parsed records, run detection on them and persist alerts."""
    cfg = get_thresholds(sess)
    batch = IngestBatch(source=source, filename=filename, is_synthetic=is_synthetic,
                        received=result.received, imported=len(result.records), rejected=len(result.rejected),
                        client_hash=client_hash)
    sess.add(batch)
    sess.flush()

    events: list[LogEvent] = []
    for rec in result.records:
        events.append(LogEvent(batch_id=batch.id, timestamp=rec.timestamp, source_ip=rec.source_ip,
                               username=rec.username, event_type=rec.event_type, status=rec.status,
                               severity=rec.severity, description=_base_description(rec),
                               is_synthetic=is_synthetic))
    for rej in result.rejected[:500]:
        events.append(LogEvent(batch_id=batch.id, timestamp=None, source_ip=None, username=None,
                               event_type="MALFORMED", status="invalid", severity="LOW",
                               description=f"Rejected row {rej.row}: {rej.reason}.",
                               detection_rule="MALFORMED_ENTRIES", is_synthetic=is_synthetic, raw=rej.raw))

    valid_events = events[: len(result.records)]
    detections = run_detection(valid_events, cfg)
    mal = malformed_detection(len(result.rejected), result.received, cfg)
    if mal:
        detections.append(mal)

    alerts = []
    for det in detections:
        for idx in det.event_indices:
            _escalate(valid_events[idx], det)
        alerts.append(Alert(batch_id=batch.id, rule_id=det.rule_id, title=det.title, description=det.description,
                            severity=det.severity, source_ip=det.source_ip, username=det.username,
                            failed_attempts=det.count, threshold=det.threshold, window_start=det.window_start,
                            window_end=det.window_end, is_synthetic=is_synthetic, details=det.details))
    sess.add_all(events)
    sess.add_all(alerts)
    batch.analyzed = len(valid_events)
    batch.alerts_created = len(alerts)
    sess.flush()
    _prune(sess, max_stored_events)

    sev_counts = Counter(a.severity for a in alerts)
    return {
        "batch": batch.to_dict(),
        "alerts_by_severity": {s: sev_counts.get(s, 0) for s in SEVERITIES},
        "rejected_samples": [{"row": r.row, "reason": r.reason} for r in result.rejected[:20]],
    }


def _prune(sess: Session, max_events: int) -> None:
    """Keep storage bounded for the public demo by dropping the oldest events."""
    total = sess.scalar(select(func.count(LogEvent.id))) or 0
    if total <= max_events:
        return
    cutoff_id = sess.scalar(select(LogEvent.id).order_by(LogEvent.id.desc()).offset(max_events).limit(1))
    if cutoff_id is not None:
        sess.execute(delete(LogEvent).where(LogEvent.id <= cutoff_id))
    alert_total = sess.scalar(select(func.count(Alert.id))) or 0
    max_alerts = max(500, max_events // 10)
    if alert_total > max_alerts:
        cut = sess.scalar(select(Alert.id).order_by(Alert.id.desc()).offset(max_alerts).limit(1))
        if cut is not None:
            sess.execute(delete(Alert).where(Alert.id <= cut))


def recent_ingests_by_client(sess: Session, client_hash: str, minutes: int = 10) -> int:
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    return sess.scalar(select(func.count(IngestBatch.id)).where(
        IngestBatch.client_hash == client_hash, IngestBatch.created_at >= since)) or 0


def reset_all(sess: Session) -> dict:
    counts = {
        "events": sess.scalar(select(func.count(LogEvent.id))) or 0,
        "alerts": sess.scalar(select(func.count(Alert.id))) or 0,
        "batches": sess.scalar(select(func.count(IngestBatch.id))) or 0,
    }
    sess.execute(delete(Alert))
    sess.execute(delete(LogEvent))
    sess.execute(delete(IngestBatch))
    return counts


# ---------------------------------------------------------------- queries

EVENT_SORT_FIELDS = {
    "timestamp": LogEvent.timestamp,
    "severity": case({s: i for i, s in enumerate(SEVERITIES)}, value=LogEvent.severity),
    "source_ip": LogEvent.source_ip,
    "username": LogEvent.username,
    "event_type": LogEvent.event_type,
    "id": LogEvent.id,
}
ALERT_SORT_FIELDS = {
    "detected_at": Alert.detected_at,
    "severity": case({s: i for i, s in enumerate(SEVERITIES)}, value=Alert.severity),
    "failed_attempts": Alert.failed_attempts,
    "id": Alert.id,
}


def _csv_param(value: str | None, allowed: set[str] | None = None, upper: bool = True) -> list[str]:
    if not value:
        return []
    items = [v.strip().upper() if upper else v.strip() for v in value.split(",") if v.strip()]
    if allowed is not None:
        bad = [v for v in items if v not in allowed]
        if bad:
            raise ValidationFailed(f"Invalid filter value(s): {', '.join(bad)}", details={"allowed": sorted(allowed)})
    return items


def paginate(args) -> tuple[int, int]:
    try:
        page = int(args.get("page", 1))
        size = int(args.get("page_size", 25))
    except ValueError as exc:
        raise ValidationFailed("page and page_size must be integers.") from exc
    if page < 1 or not 1 <= size <= 200:
        raise ValidationFailed("page must be >= 1 and page_size between 1 and 200.")
    return page, size


def _order(args, fields: dict, default: str):
    sort = args.get("sort", default)
    order = args.get("order", "desc").lower()
    if sort not in fields:
        raise ValidationFailed(f"Invalid sort field '{sort}'.", details={"allowed": sorted(fields)})
    if order not in ("asc", "desc"):
        raise ValidationFailed("order must be 'asc' or 'desc'.")
    col = fields[sort]
    if order == "asc":
        return [col.asc(), LogEvent.id.asc()] if fields is EVENT_SORT_FIELDS else [col.asc(), Alert.id.asc()]
    return [col.desc(), LogEvent.id.desc()] if fields is EVENT_SORT_FIELDS else [col.desc(), Alert.id.desc()]


def list_events(sess: Session, args) -> tuple[list[dict], dict]:
    page, size = paginate(args)
    q = select(LogEvent)
    sev = _csv_param(args.get("severity"), set(SEVERITIES))
    if sev:
        q = q.where(LogEvent.severity.in_(sev))
    etypes = _csv_param(args.get("event_type"))
    if etypes:
        q = q.where(LogEvent.event_type.in_(etypes))
    statuses = _csv_param(args.get("status"), {"success", "failure", "invalid"}, upper=False)
    if statuses:
        q = q.where(LogEvent.status.in_(statuses))
    if args.get("rule"):
        q = q.where(LogEvent.detection_rule == args["rule"].upper())
    if args.get("flagged") == "true":
        q = q.where(LogEvent.detection_rule.is_not(None))
    if args.get("ip"):
        q = q.where(LogEvent.source_ip == args["ip"].strip())
    if args.get("username"):
        q = q.where(LogEvent.username == args["username"].strip().lower())
    search = (args.get("search") or "").strip()
    if search:
        if len(search) > 100:
            raise ValidationFailed("search must be at most 100 characters.")
        like = f"%{search.lower()}%"
        q = q.where(or_(func.lower(LogEvent.source_ip).like(like), func.lower(LogEvent.username).like(like),
                        func.lower(LogEvent.description).like(like), func.lower(LogEvent.event_type).like(like)))
    total = sess.scalar(select(func.count()).select_from(q.subquery())) or 0
    rows = sess.scalars(q.order_by(*_order(args, EVENT_SORT_FIELDS, "timestamp")).offset((page - 1) * size).limit(size))
    return [r.to_dict() for r in rows], {"page": page, "page_size": size, "total": total,
                                          "pages": (total + size - 1) // size}


def list_alerts(sess: Session, args) -> tuple[list[dict], dict]:
    page, size = paginate(args)
    q = select(Alert)
    sev = _csv_param(args.get("severity"), set(SEVERITIES))
    if sev:
        q = q.where(Alert.severity.in_(sev))
    status = (args.get("status") or "all").lower()
    if status not in ("all", "open", "acknowledged"):
        raise ValidationFailed("status must be one of: all, open, acknowledged.")
    if status == "open":
        q = q.where(Alert.acknowledged.is_(False))
    elif status == "acknowledged":
        q = q.where(Alert.acknowledged.is_(True))
    if args.get("rule"):
        q = q.where(Alert.rule_id == args["rule"].upper())
    search = (args.get("search") or "").strip()
    if search:
        like = f"%{search.lower()[:100]}%"
        q = q.where(or_(func.lower(Alert.title).like(like), func.lower(Alert.source_ip).like(like),
                        func.lower(Alert.username).like(like)))
    total = sess.scalar(select(func.count()).select_from(q.subquery())) or 0
    rows = sess.scalars(q.order_by(*_order(args, ALERT_SORT_FIELDS, "detected_at")).offset((page - 1) * size).limit(size))
    return [r.to_dict() for r in rows], {"page": page, "page_size": size, "total": total,
                                          "pages": (total + size - 1) // size}


def set_alert_ack(sess: Session, alert_id: int, acknowledged: bool) -> dict:
    alert = sess.get(Alert, alert_id)
    if alert is None:
        raise ApiError(f"Alert {alert_id} not found.", status_code=404, code="not_found")
    alert.acknowledged = acknowledged
    alert.acknowledged_at = datetime.now(timezone.utc) if acknowledged else None
    sess.flush()
    return alert.to_dict()


def _timeline(rows: list[tuple]) -> dict:
    stamps = [as_utc(r[0]) for r in rows if r[0] is not None]
    if not stamps:
        return {"bucket_minutes": 5, "points": []}
    lo, hi = min(stamps), max(stamps)
    span = (hi - lo).total_seconds() / 60
    bucket = next((b for b in (1, 5, 10, 15, 30, 60, 120, 240, 720, 1440) if span / b <= 60), 1440)
    def key(dt: datetime) -> datetime:
        minutes = (dt.hour * 60 + dt.minute) // bucket * bucket
        return dt.replace(hour=minutes // 60 % 24, minute=minutes % 60, second=0, microsecond=0) if bucket < 1440 \
            else dt.replace(hour=0, minute=0, second=0, microsecond=0)
    points: dict[datetime, dict] = {}
    for ts, status, severity in rows:
        if ts is None:
            continue
        k = key(as_utc(ts))
        p = points.setdefault(k, {"success": 0, "failure": 0, "flagged": 0, "total": 0})
        p["total"] += 1
        if status in ("success", "failure"):
            p[status] += 1
        if SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK["MEDIUM"]:
            p["flagged"] += 1
    # Fill gaps so the chart has a continuous axis.
    out = []
    cur, end = key(lo), key(hi)
    step = timedelta(minutes=bucket)
    while cur <= end and len(out) < 500:
        p = points.get(cur, {"success": 0, "failure": 0, "flagged": 0, "total": 0})
        out.append({"time": cur.isoformat().replace("+00:00", "Z"), **p})
        cur += step
    return {"bucket_minutes": bucket, "points": out}


def dashboard_stats(sess: Session) -> dict:
    total = sess.scalar(select(func.count(LogEvent.id))) or 0
    by_sev = dict(sess.execute(select(LogEvent.severity, func.count()).group_by(LogEvent.severity)).all())
    by_type = dict(sess.execute(select(LogEvent.event_type, func.count()).group_by(LogEvent.event_type)).all())
    by_status = dict(sess.execute(select(LogEvent.status, func.count()).group_by(LogEvent.status)).all())
    alerts_by_sev = dict(sess.execute(select(Alert.severity, func.count()).group_by(Alert.severity)).all())
    open_alerts = sess.scalar(select(func.count(Alert.id)).where(Alert.acknowledged.is_(False))) or 0
    total_alerts = sess.scalar(select(func.count(Alert.id))) or 0
    suspicious_ips = sess.scalar(select(func.count(func.distinct(Alert.source_ip))).where(Alert.source_ip.is_not(None))) or 0
    synthetic = sess.scalar(select(func.count(LogEvent.id)).where(LogEvent.is_synthetic.is_(True))) or 0
    rule_counts = dict(sess.execute(select(Alert.rule_id, func.count()).group_by(Alert.rule_id)).all())
    top_ips = sess.execute(
        select(LogEvent.source_ip, func.count().label("n")).where(LogEvent.status == "failure")
        .group_by(LogEvent.source_ip).order_by(func.count().desc()).limit(8)).all()
    timeline_rows = sess.execute(select(LogEvent.timestamp, LogEvent.status, LogEvent.severity)
                                 .where(LogEvent.timestamp.is_not(None))).all()
    last_batch = sess.scalars(select(IngestBatch).order_by(IngestBatch.id.desc()).limit(1)).first()
    return {
        "total_events": total,
        "failed_logins": by_type.get("LOGIN_FAILURE", 0),
        "successful_logins": by_type.get("LOGIN_SUCCESS", 0),
        "failure_events": by_status.get("failure", 0),
        "malformed_events": by_type.get("MALFORMED", 0),
        "suspicious_ips": suspicious_ips,
        "high_events": by_sev.get("HIGH", 0),
        "critical_events": by_sev.get("CRITICAL", 0),
        "events_by_severity": {s: by_sev.get(s, 0) for s in SEVERITIES},
        "events_by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        "alerts": {"total": total_alerts, "open": open_alerts, "acknowledged": total_alerts - open_alerts,
                   "by_severity": {s: alerts_by_sev.get(s, 0) for s in SEVERITIES}, "by_rule": rule_counts},
        "top_failing_ips": [{"source_ip": ip, "failures": n} for ip, n in top_ips],
        "timeline": _timeline(timeline_rows),
        "data_mode": {
            "synthetic_events": synthetic,
            "uploaded_events": total - synthetic,
            "is_demo": total == 0 or synthetic > 0,
        },
        "last_ingest": last_batch.to_dict() if last_batch else None,
    }


def list_batches(sess: Session, limit: int = 10) -> list[dict]:
    return [b.to_dict() for b in sess.scalars(select(IngestBatch).order_by(IngestBatch.id.desc()).limit(limit))]
