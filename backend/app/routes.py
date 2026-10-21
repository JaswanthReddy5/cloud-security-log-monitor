"""REST API routes. All responses use a consistent JSON envelope:

    success: {"ok": true, "data": ..., "meta": {...}}
    error:   {"ok": false, "error": {"code": "...", "message": "...", "details": ...}}
"""
from __future__ import annotations

import csv
import io
import json
import logging
import time

from flask import Blueprint, Response, current_app, jsonify, request

from . import services
from .detection import RULES
from .errors import ApiError, ValidationFailed
from .parsing import InvalidFile, parse_file, parse_records
from .security import client_hash, rate_limit, require_admin
from .synthetic import SCENARIOS, generate, sample_records

api = Blueprint("api", __name__, url_prefix="/api")
log = logging.getLogger("seclog")

VERSION = "1.0.0"


def ok(data=None, meta=None, status=200):
    body = {"ok": True, "data": data}
    if meta is not None:
        body["meta"] = meta
    return jsonify(body), status


def db():
    return current_app.config["DB"]


def settings():
    return current_app.config["SETTINGS"]


def audit(action: str, **fields):
    """Structured log line - visible in Vercel runtime logs (observability)."""
    log.info(json.dumps({"event": action, "ts": time.time(), **fields}, default=str))


def _check_ingest_quota(sess, chash: str):
    if current_app.config.get("TESTING_DISABLE_RATE_LIMIT"):
        return
    limit = settings().rate_limit_ingest_per_10min
    if services.recent_ingests_by_client(sess, chash) >= limit:
        raise ApiError(f"Ingestion limit reached ({limit} per 10 minutes). Try again later.",
                       status_code=429, code="rate_limited")


# ------------------------------------------------------------------ health


@api.get("/health")
def health():
    database = db()
    reachable = database.ping() if database.configured else False
    data = {
        "status": "ok" if reachable else "degraded",
        "version": VERSION,
        "environment": settings().environment,
        "database": {"configured": database.configured, "reachable": reachable, "dialect": database.dialect},
        "admin_enabled": bool(settings().admin_api_key),
    }
    return ok(data, status=200 if reachable else 503)


@api.get("/rules")
def rules():
    with db().session() as sess:
        cfg = services.get_thresholds(sess)
    return ok([{**r, "current": {k: cfg[k] for k in r["settings"]}} for r in RULES])


# ------------------------------------------------------------------ ingestion


@api.post("/logs/generate")
@rate_limit("generate", limit=10, window_s=60)
def generate_logs():
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        raise ValidationFailed("Request body must be a JSON object.")
    count = body.get("count", 250)
    if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= settings().max_generate_count:
        raise ValidationFailed(f"count must be an integer between 0 and {settings().max_generate_count}.")
    scenarios = body.get("scenarios")
    if scenarios is not None:
        if not isinstance(scenarios, list) or any(s not in SCENARIOS for s in scenarios):
            raise ValidationFailed("Invalid scenarios.", details={"allowed": SCENARIOS})
    records = generate(count=count, scenarios=scenarios)
    result = parse_records(records, max_records=settings().max_generate_count + 500)
    chash = client_hash()
    with db().session() as sess:
        _check_ingest_quota(sess, chash)
        summary = services.ingest(sess, result, source="synthetic", filename=None, is_synthetic=True,
                                  client_hash=chash, max_stored_events=settings().max_stored_events)
    audit("ingest", source="synthetic", **{k: summary["batch"][k] for k in ("imported", "rejected", "alerts_created")})
    return ok(summary, status=201)


@api.post("/logs/upload")
@rate_limit("upload", limit=10, window_s=60)
def upload_logs():
    file = request.files.get("file")
    if file is None:
        raise InvalidFile("No file uploaded. Send multipart/form-data with a 'file' field.", code="missing_file")
    data = file.read(settings().max_upload_bytes + 1)
    if len(data) > settings().max_upload_bytes:
        raise ApiError(f"File too large (max {settings().max_upload_bytes // 1024} KB).", status_code=413,
                       code="file_too_large")
    filename = (file.filename or "upload")[:255]
    fmt, result = parse_file(data, filename, settings().max_records_per_ingest)
    if not result.records and result.rejected:
        raise InvalidFile(f"No valid records found ({len(result.rejected)} rejected).", code="no_valid_records",
                          details={"rejected_samples": [{"row": r.row, "reason": r.reason} for r in result.rejected[:20]]})
    chash = client_hash()
    with db().session() as sess:
        _check_ingest_quota(sess, chash)
        summary = services.ingest(sess, result, source=fmt, filename=filename, is_synthetic=False,
                                  client_hash=chash, max_stored_events=settings().max_stored_events)
    audit("ingest", source=fmt, **{k: summary["batch"][k] for k in ("imported", "rejected", "alerts_created")})
    return ok(summary, status=201)


@api.post("/logs/ingest")
@rate_limit("ingest", limit=30, window_s=60)
def ingest_json():
    """Centralized ingestion endpoint for log shippers: {"events": [...]}."""
    if request.content_length and request.content_length > settings().max_upload_bytes:
        raise ApiError("Payload too large.", status_code=413, code="payload_too_large")
    body = request.get_json(silent=True)
    if body is None:
        raise InvalidFile("Body must be valid JSON with Content-Type: application/json.", code="invalid_json")
    items = body.get("events") if isinstance(body, dict) else body
    if not isinstance(items, list):
        raise InvalidFile("Expected {\"events\": [...]} or a JSON array.", code="invalid_json")
    result = parse_records(items, settings().max_records_per_ingest)
    if not result.records:
        raise InvalidFile(f"No valid records found ({len(result.rejected)} rejected).", code="no_valid_records",
                          details={"rejected_samples": [{"row": r.row, "reason": r.reason} for r in result.rejected[:20]]})
    chash = client_hash()
    with db().session() as sess:
        _check_ingest_quota(sess, chash)
        summary = services.ingest(sess, result, source="api", filename=None, is_synthetic=False,
                                  client_hash=chash, max_stored_events=settings().max_stored_events)
    audit("ingest", source="api", **{k: summary["batch"][k] for k in ("imported", "rejected", "alerts_created")})
    return ok(summary, status=201)


@api.get("/logs/sample")
def sample():
    fmt = request.args.get("format", "csv").lower()
    recs = sample_records()
    if fmt == "json":
        payload = json.dumps({"events": recs}, indent=2)
        return Response(payload, mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=sample_security_logs.json"})
    if fmt != "csv":
        raise ValidationFailed("format must be 'csv' or 'json'.")
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["timestamp", "source_ip", "username", "event_type", "status"])
    writer.writeheader()
    writer.writerows(recs)
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=sample_security_logs.csv"})


@api.get("/batches")
def batches():
    with db().session() as sess:
        return ok(services.list_batches(sess))


# ------------------------------------------------------------------ read APIs


@api.get("/stats")
def stats():
    with db().session() as sess:
        return ok(services.dashboard_stats(sess))


@api.get("/events")
def events():
    with db().session() as sess:
        rows, meta = services.list_events(sess, request.args)
    return ok(rows, meta)


@api.get("/alerts")
def alerts():
    with db().session() as sess:
        rows, meta = services.list_alerts(sess, request.args)
    return ok(rows, meta)


@api.patch("/alerts/<int:alert_id>")
@rate_limit("ack", limit=60, window_s=60)
def update_alert(alert_id: int):
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("acknowledged"), bool):
        raise ValidationFailed("Body must be {\"acknowledged\": true|false}.")
    with db().session() as sess:
        alert = services.set_alert_ack(sess, alert_id, body["acknowledged"])
    audit("alert_ack", alert_id=alert_id, acknowledged=body["acknowledged"])
    return ok(alert)


# ------------------------------------------------------------------ settings & admin


@api.get("/settings")
def get_settings():
    with db().session() as sess:
        cfg = services.get_thresholds(sess)
    s = settings()
    return ok({
        "thresholds": cfg,
        "limits": {"max_upload_bytes": s.max_upload_bytes, "max_records_per_ingest": s.max_records_per_ingest,
                   "max_stored_events": s.max_stored_events, "max_generate_count": s.max_generate_count},
        "admin_enabled": bool(s.admin_api_key),
    })


@api.put("/settings")
@require_admin
def put_settings():
    body = request.get_json(silent=True)
    updates = body.get("thresholds") if isinstance(body, dict) else None
    with db().session() as sess:
        cfg = services.update_thresholds(sess, updates)
    audit("settings_update", keys=sorted(updates.keys()))
    return ok({"thresholds": cfg})


@api.post("/admin/verify")
@require_admin
def verify_admin():
    return ok({"admin": True})


@api.post("/admin/reset")
@require_admin
def reset():
    body = request.get_json(silent=True) or {}
    if body.get("confirm") != "RESET":
        raise ValidationFailed("Confirmation required: send {\"confirm\": \"RESET\"}.")
    with db().session() as sess:
        deleted = services.reset_all(sess)
    audit("reset", **deleted)
    return ok({"deleted": deleted})
