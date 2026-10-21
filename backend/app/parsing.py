"""Log parsing, validation and normalization.

Uploaded content is only ever treated as data: it is decoded as UTF-8 text,
parsed with the standard csv/json modules and validated field by field.
Nothing from a log file is executed or evaluated.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .errors import ApiError

EVENT_TYPES: dict[str, tuple[str, str]] = {
    # event_type: (status, base severity)
    "LOGIN_SUCCESS": ("success", "INFO"),
    "LOGIN_FAILURE": ("failure", "LOW"),
    "LOGOUT": ("success", "INFO"),
    "PASSWORD_RESET": ("success", "LOW"),
    "ACCOUNT_LOCKED": ("failure", "MEDIUM"),
    "MFA_FAILURE": ("failure", "LOW"),
}
GENERIC_LOGIN_TYPES = {"LOGIN", "LOGIN_ATTEMPT", "AUTH", "AUTHENTICATION", "SIGNIN", "SIGN_IN"}
EVENT_ALIASES = {
    "LOGIN_FAILED": "LOGIN_FAILURE",
    "FAILED_LOGIN": "LOGIN_FAILURE",
    "LOGIN_FAIL": "LOGIN_FAILURE",
    "AUTH_FAILURE": "LOGIN_FAILURE",
    "LOGIN_SUCCEEDED": "LOGIN_SUCCESS",
    "SUCCESSFUL_LOGIN": "LOGIN_SUCCESS",
    "AUTH_SUCCESS": "LOGIN_SUCCESS",
    "LOCKOUT": "ACCOUNT_LOCKED",
    "ACCOUNT_LOCKOUT": "ACCOUNT_LOCKED",
    "MFA_FAILED": "MFA_FAILURE",
}
SUCCESS_WORDS = {"success", "succeeded", "successful", "ok", "true", "1", "accepted", "allow", "allowed", "pass"}
FAILURE_WORDS = {"failure", "failed", "fail", "denied", "false", "0", "rejected", "deny", "error", "invalid"}

FIELD_ALIASES = {
    "timestamp": ("timestamp", "time", "ts", "datetime", "date", "@timestamp", "event_time"),
    "source_ip": ("source_ip", "ip", "src_ip", "ip_address", "client_ip", "remote_addr", "source"),
    "username": ("username", "user", "user_name", "account", "login"),
    "event_type": ("event_type", "event", "type", "action"),
    "status": ("status", "result", "outcome"),
}
REQUIRED_FIELDS = ("timestamp", "source_ip", "username")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._@\-]{1,64}$")
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MIN_TIMESTAMP = datetime(2000, 1, 1, tzinfo=timezone.utc)


@dataclass
class ParsedRecord:
    timestamp: datetime
    source_ip: str
    username: str
    event_type: str
    status: str
    severity: str


@dataclass
class RejectedRecord:
    row: int
    reason: str
    raw: str


@dataclass
class ParseResult:
    records: list[ParsedRecord]
    rejected: list[RejectedRecord]

    @property
    def received(self) -> int:
        return len(self.records) + len(self.rejected)


class InvalidFile(ApiError):
    status_code = 400
    code = "invalid_file"


def sanitize_raw(value, limit: int = 300) -> str:
    try:
        text = value if isinstance(value, str) else json.dumps(value, default=str)
    except (TypeError, ValueError):
        text = repr(value)
    text = CONTROL_CHARS.sub("", text)
    return text[:limit] + ("…" if len(text) > limit else "")


def parse_timestamp(value) -> datetime:
    if value is None or (isinstance(value, str) and not value.strip()):
        raise ValueError("timestamp is required")
    if isinstance(value, bool):
        raise ValueError("invalid timestamp")
    if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d{9,13}(\.\d+)?", value.strip())):
        num = float(value)
        if num > 1e12:  # milliseconds
            num /= 1000.0
        try:
            dt = datetime.fromtimestamp(num, tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError("invalid epoch timestamp") from exc
    elif isinstance(value, str):
        text = value.strip().replace(" ", "T", 1) if "T" not in value else value.strip()
        if text.endswith("Z") or text.endswith("z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError(f"invalid timestamp format: {sanitize_raw(value, 40)}") from exc
        dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    else:
        raise ValueError("invalid timestamp type")
    now = datetime.now(timezone.utc)
    if dt < MIN_TIMESTAMP or dt > now + timedelta(days=1):
        raise ValueError("timestamp out of accepted range")
    return dt


def parse_ip(value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("source_ip is required")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {sanitize_raw(value, 45)}") from exc


def parse_username(value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("username is required")
    name = value.strip()
    if not USERNAME_RE.match(name):
        raise ValueError("invalid username (allowed: letters, digits, . _ @ -, max 64 chars)")
    return name.lower()


def parse_status(value) -> str | None:
    if value is None:
        return None
    word = str(value).strip().lower()
    if not word:
        return None
    if word in SUCCESS_WORDS:
        return "success"
    if word in FAILURE_WORDS:
        return "failure"
    raise ValueError(f"invalid status: {sanitize_raw(value, 30)}")


def resolve_event(event_value, status: str | None) -> tuple[str, str, str]:
    """Return (event_type, status, base_severity)."""
    etype = None
    if event_value is not None and str(event_value).strip():
        etype = re.sub(r"[\s\-]+", "_", str(event_value).strip().upper())
        etype = EVENT_ALIASES.get(etype, etype)
    if etype is None or etype in GENERIC_LOGIN_TYPES:
        if status is None:
            raise ValueError("event_type or status is required")
        etype = "LOGIN_SUCCESS" if status == "success" else "LOGIN_FAILURE"
    if etype not in EVENT_TYPES:
        raise ValueError(f"unknown event_type: {sanitize_raw(event_value, 32)}")
    expected_status, severity = EVENT_TYPES[etype]
    if status is not None and status != expected_status:
        raise ValueError(f"status '{status}' contradicts event_type '{etype}'")
    return etype, expected_status, severity


def _pick(record: dict, field: str):
    lowered = {str(k).strip().lower(): v for k, v in record.items() if k is not None}
    for alias in FIELD_ALIASES[field]:
        if alias in lowered:
            return lowered[alias]
    return None


def normalize_record(record) -> ParsedRecord:
    if not isinstance(record, dict):
        raise ValueError("record must be an object")
    missing = [f for f in REQUIRED_FIELDS if _pick(record, f) in (None, "")]
    if _pick(record, "event_type") in (None, "") and _pick(record, "status") in (None, ""):
        missing.append("event_type/status")
    if missing:
        raise ValueError("missing required field(s): " + ", ".join(missing))
    ts = parse_timestamp(_pick(record, "timestamp"))
    ip = parse_ip(_pick(record, "source_ip"))
    user = parse_username(_pick(record, "username"))
    status = parse_status(_pick(record, "status"))
    etype, status, severity = resolve_event(_pick(record, "event_type"), status)
    return ParsedRecord(timestamp=ts, source_ip=ip, username=user, event_type=etype, status=status, severity=severity)


def parse_records(items: list, max_records: int) -> ParseResult:
    if len(items) == 0:
        raise InvalidFile("The log file contains no records.", code="empty_file")
    if len(items) > max_records:
        raise InvalidFile(f"Too many records: {len(items)} (maximum {max_records}).", code="too_many_records")
    records: list[ParsedRecord] = []
    rejected: list[RejectedRecord] = []
    for idx, item in enumerate(items, start=1):
        try:
            records.append(normalize_record(item))
        except ValueError as exc:
            rejected.append(RejectedRecord(row=idx, reason=str(exc), raw=sanitize_raw(item)))
    return ParseResult(records=records, rejected=rejected)


def decode_bytes(data: bytes) -> str:
    if not data or not data.strip():
        raise InvalidFile("The uploaded file is empty.", code="empty_file")
    if b"\x00" in data[:4096]:
        raise InvalidFile("Binary files are not accepted. Upload CSV or JSON text.", code="unsupported_format")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InvalidFile("File must be UTF-8 encoded text.", code="unsupported_format") from exc


def load_csv(text: str) -> list[dict]:
    reader = csv.DictReader(io.StringIO(text))
    headers = [h.strip().lower() for h in (reader.fieldnames or []) if h]
    if not headers:
        raise InvalidFile("CSV file has no header row.", code="invalid_csv")
    has = {f: any(a in headers for a in FIELD_ALIASES[f]) for f in FIELD_ALIASES}
    missing = [f for f in REQUIRED_FIELDS if not has[f]]
    if not has["event_type"] and not has["status"]:
        missing.append("event_type or status")
    if missing:
        raise InvalidFile("CSV header is missing required column(s): " + ", ".join(missing), code="invalid_csv")
    try:
        rows = [row for row in reader if any((v or "").strip() for v in row.values() if isinstance(v, str))]
    except csv.Error as exc:
        raise InvalidFile(f"Malformed CSV: {exc}", code="invalid_csv") from exc
    return rows


def load_json(text: str) -> list:
    stripped = text.strip()
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        # Try JSON Lines / NDJSON
        items = []
        for n, line in enumerate(stripped.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise InvalidFile(f"Invalid JSON (line {n}): {exc.msg}", code="invalid_json") from exc
        return items
    if isinstance(data, dict):
        if isinstance(data.get("events"), list):
            return data["events"]
        if isinstance(data.get("logs"), list):
            return data["logs"]
        return [data]
    if isinstance(data, list):
        return data
    raise InvalidFile("JSON must be an array of log objects or {\"events\": [...]}.", code="invalid_json")


def detect_format(filename: str | None, text: str) -> str:
    name = (filename or "").lower()
    if name.endswith(".csv"):
        return "csv"
    if name.endswith((".json", ".jsonl", ".ndjson")):
        return "json"
    if name and "." in name:
        raise InvalidFile("Unsupported file type. Upload a .csv or .json file.", code="unsupported_format")
    return "json" if text.lstrip()[:1] in ("[", "{") else "csv"


def parse_file(data: bytes, filename: str | None, max_records: int) -> tuple[str, ParseResult]:
    text = decode_bytes(data)
    fmt = detect_format(filename, text)
    items = load_csv(text) if fmt == "csv" else load_json(text)
    return fmt, parse_records(items, max_records)
