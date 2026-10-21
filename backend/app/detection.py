"""Rule-based security detection engine.

These rules flag *suspicious patterns* for demonstration and educational
purposes. A detection is not proof that an account has been compromised; it
is a signal that an analyst should review.

The engine is pure Python (no database access) so it is easy to unit test.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol

from .config import PRIVILEGED_USERNAMES
from .models import SEVERITY_RANK


class EventLike(Protocol):
    timestamp: datetime
    source_ip: str
    username: str
    event_type: str
    status: str


@dataclass
class Detection:
    rule_id: str
    title: str
    description: str
    severity: str
    event_indices: list[int]
    source_ip: str | None = None
    username: str | None = None
    count: int | None = None
    threshold: float | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None
    details: dict = field(default_factory=dict)


RULES = [
    {
        "id": "BRUTE_FORCE_IP",
        "name": "Repeated failed logins from one IP",
        "description": "N or more failed logins from the same source IP within the time window. "
        "HIGH at the threshold, CRITICAL at twice the threshold.",
        "settings": ["ip_failure_threshold", "ip_failure_window_minutes"],
    },
    {
        "id": "ACCOUNT_TARGETED",
        "name": "Repeated failures against one username",
        "description": "N or more failed logins against the same username within the window. "
        "MEDIUM normally, HIGH when they come from several distinct IPs (distributed attempt).",
        "settings": ["user_failure_threshold", "user_failure_window_minutes", "distributed_ip_threshold"],
    },
    {
        "id": "HIGH_FAILURE_RATE",
        "name": "High failure rate in a time window",
        "description": "Share of failed authentication events in a fixed window is at or above the "
        "configured rate (with a minimum number of events).",
        "settings": ["failure_rate_threshold", "failure_rate_window_minutes", "failure_rate_min_events"],
    },
    {
        "id": "SUCCESS_AFTER_FAILURES",
        "name": "Successful login after a burst of failures",
        "description": "A successful login for a username that had N or more failures shortly before. "
        "Could be a user who finally remembered their password, or a guessed credential - needs review.",
        "settings": ["success_after_failures_threshold", "success_after_failures_window_minutes"],
    },
    {
        "id": "PASSWORD_SPRAY",
        "name": "Suspicious pattern: password spraying",
        "description": "One IP fails against N or more distinct usernames within the window.",
        "settings": ["spray_username_threshold", "spray_window_minutes"],
    },
    {
        "id": "OFF_HOURS_PRIVILEGED",
        "name": "Suspicious pattern: off-hours privileged login",
        "description": "Successful login to a privileged account (admin, root, ...) during configured "
        "off-hours (UTC).",
        "settings": ["off_hours_start_utc", "off_hours_end_utc"],
    },
    {
        "id": "MALFORMED_ENTRIES",
        "name": "Malformed or invalid log entries",
        "description": "Entries that fail validation are stored as MALFORMED events. An alert is raised "
        "when a single ingestion contains N or more of them.",
        "settings": ["malformed_alert_threshold"],
    },
]


def _bursts(times: list[tuple[datetime, int]], threshold: int, window: timedelta):
    """Yield (start, end) index ranges in which >= threshold items fall in `window`.

    `times` must be sorted. Once a burst is found, it is extended while the next
    item still falls within `window` of the previous item, so one long attack
    produces one alert instead of dozens of overlapping ones.
    """
    n = len(times)
    i = 0
    while i < n:
        j = i
        while j + 1 < n and times[j + 1][0] - times[i][0] <= window:
            j += 1
        if j - i + 1 >= threshold:
            while j + 1 < n and times[j + 1][0] - times[j][0] <= window:
                j += 1
            yield i, j
            i = j + 1
        else:
            i += 1


def _fmt_minutes(m) -> str:
    m = int(m)
    return f"{m} minute{'s' if m != 1 else ''}"


def detect_brute_force_ip(events: Sequence[EventLike], cfg: dict) -> list[Detection]:
    threshold = int(cfg["ip_failure_threshold"])
    window = timedelta(minutes=cfg["ip_failure_window_minutes"])
    by_ip: dict[str, list[tuple[datetime, int]]] = defaultdict(list)
    for idx, ev in enumerate(events):
        if ev.status == "failure":
            by_ip[ev.source_ip].append((ev.timestamp, idx))
    out = []
    for ip, items in by_ip.items():
        items.sort()
        for s, e in _bursts(items, threshold, window):
            chunk = items[s : e + 1]
            count = len(chunk)
            users = sorted({events[i].username for _, i in chunk})
            severity = "CRITICAL" if count >= threshold * 2 else "HIGH"
            out.append(
                Detection(
                    rule_id="BRUTE_FORCE_IP",
                    title=f"Repeated failed logins from {ip}",
                    description=(
                        f"{count} failed login attempts from {ip} (threshold {threshold} within "
                        f"{_fmt_minutes(cfg['ip_failure_window_minutes'])}). Possible brute-force activity; "
                        "rule-based signal, not proof of compromise."
                    ),
                    severity=severity,
                    event_indices=[i for _, i in chunk],
                    source_ip=ip,
                    username=users[0] if len(users) == 1 else None,
                    count=count,
                    threshold=threshold,
                    window_start=chunk[0][0],
                    window_end=chunk[-1][0],
                    details={"usernames": users[:20]},
                )
            )
    return out


def detect_account_targeted(events: Sequence[EventLike], cfg: dict) -> list[Detection]:
    threshold = int(cfg["user_failure_threshold"])
    window = timedelta(minutes=cfg["user_failure_window_minutes"])
    distributed = int(cfg["distributed_ip_threshold"])
    by_user: dict[str, list[tuple[datetime, int]]] = defaultdict(list)
    for idx, ev in enumerate(events):
        if ev.status == "failure":
            by_user[ev.username].append((ev.timestamp, idx))
    out = []
    for user, items in by_user.items():
        items.sort()
        for s, e in _bursts(items, threshold, window):
            chunk = items[s : e + 1]
            ips = sorted({events[i].source_ip for _, i in chunk})
            is_distributed = len(ips) >= distributed
            out.append(
                Detection(
                    rule_id="ACCOUNT_TARGETED",
                    title=(f"Distributed failed logins against '{user}'" if is_distributed else f"Repeated failed logins against '{user}'"),
                    description=(
                        f"{len(chunk)} failed logins for username '{user}' from {len(ips)} IP(s) "
                        f"(threshold {threshold} within {_fmt_minutes(cfg['user_failure_window_minutes'])})."
                        + (" Multiple source IPs suggest a coordinated attempt." if is_distributed else "")
                    ),
                    severity="HIGH" if is_distributed else "MEDIUM",
                    event_indices=[i for _, i in chunk],
                    source_ip=ips[0] if len(ips) == 1 else None,
                    username=user,
                    count=len(chunk),
                    threshold=threshold,
                    window_start=chunk[0][0],
                    window_end=chunk[-1][0],
                    details={"source_ips": ips[:20], "distinct_ips": len(ips)},
                )
            )
    return out


def detect_high_failure_rate(events: Sequence[EventLike], cfg: dict) -> list[Detection]:
    rate = float(cfg["failure_rate_threshold"])
    window = timedelta(minutes=cfg["failure_rate_window_minutes"])
    min_events = int(cfg["failure_rate_min_events"])
    auth = sorted(
        ((ev.timestamp, idx) for idx, ev in enumerate(events) if ev.event_type in ("LOGIN_SUCCESS", "LOGIN_FAILURE")),
    )
    if not auth:
        return []
    out = []
    start = auth[0][0]
    bucket: list[int] = []

    def flush(bucket_start: datetime, idxs: list[int]):
        if len(idxs) < min_events:
            return
        failures = [i for i in idxs if events[i].status == "failure"]
        ratio = len(failures) / len(idxs)
        if ratio >= rate:
            out.append(
                Detection(
                    rule_id="HIGH_FAILURE_RATE",
                    title=f"High login failure rate ({ratio:.0%})",
                    description=(
                        f"{len(failures)} of {len(idxs)} login attempts failed between "
                        f"{bucket_start:%H:%M} and {(bucket_start + window):%H:%M} UTC "
                        f"(threshold {rate:.0%}, minimum {min_events} events)."
                    ),
                    severity="HIGH" if ratio >= min(1.0, rate + 0.25) else "MEDIUM",
                    event_indices=failures,
                    count=len(failures),
                    threshold=rate,
                    window_start=bucket_start,
                    window_end=bucket_start + window,
                    details={"total_attempts": len(idxs), "failure_ratio": round(ratio, 3)},
                )
            )

    for ts, idx in auth:
        while ts >= start + window:
            flush(start, bucket)
            bucket = []
            start = start + window
        bucket.append(idx)
    flush(start, bucket)
    return out


def detect_success_after_failures(events: Sequence[EventLike], cfg: dict) -> list[Detection]:
    threshold = int(cfg["success_after_failures_threshold"])
    window = timedelta(minutes=cfg["success_after_failures_window_minutes"])
    by_user: dict[str, list[int]] = defaultdict(list)
    for idx, ev in enumerate(events):
        if ev.event_type in ("LOGIN_SUCCESS", "LOGIN_FAILURE"):
            by_user[ev.username].append(idx)
    out = []
    for user, idxs in by_user.items():
        idxs.sort(key=lambda i: (events[i].timestamp, i))
        pending: list[int] = []  # recent failures not yet "consumed" by a success
        for i in idxs:
            ev = events[i]
            pending = [p for p in pending if ev.timestamp - events[p].timestamp <= window]
            if ev.status == "failure":
                pending.append(i)
            elif len(pending) >= threshold:
                ips = sorted({events[p].source_ip for p in pending})
                same_ip = ev.source_ip in ips
                out.append(
                    Detection(
                        rule_id="SUCCESS_AFTER_FAILURES",
                        title=f"Successful login after {len(pending)} failures for '{user}'",
                        description=(
                            f"'{user}' logged in successfully from {ev.source_ip} after {len(pending)} failed "
                            f"attempts within {_fmt_minutes(cfg['success_after_failures_window_minutes'])} "
                            f"(threshold {threshold}). This may be a legitimate user or a guessed password "
                            "and should be reviewed."
                        ),
                        severity="CRITICAL" if len(pending) >= threshold * 2 or not same_ip else "HIGH",
                        event_indices=pending + [i],
                        source_ip=ev.source_ip,
                        username=user,
                        count=len(pending),
                        threshold=threshold,
                        window_start=events[pending[0]].timestamp,
                        window_end=ev.timestamp,
                        details={"failure_source_ips": ips[:20], "success_from_new_ip": not same_ip},
                    )
                )
                pending = []
            else:
                pending = []
    return out


def detect_password_spray(events: Sequence[EventLike], cfg: dict) -> list[Detection]:
    threshold = int(cfg["spray_username_threshold"])
    window = timedelta(minutes=cfg["spray_window_minutes"])
    by_ip: dict[str, list[tuple[datetime, int]]] = defaultdict(list)
    for idx, ev in enumerate(events):
        if ev.status == "failure":
            by_ip[ev.source_ip].append((ev.timestamp, idx))
    out = []
    for ip, items in by_ip.items():
        items.sort()
        n = len(items)
        i = 0
        while i < n:
            j = i
            users = {events[items[i][1]].username}
            while j + 1 < n and items[j + 1][0] - items[i][0] <= window:
                j += 1
                users.add(events[items[j][1]].username)
            if len(users) >= threshold:
                chunk = items[i : j + 1]
                out.append(
                    Detection(
                        rule_id="PASSWORD_SPRAY",
                        title=f"Possible password spraying from {ip}",
                        description=(
                            f"{ip} failed to log in to {len(users)} distinct accounts within "
                            f"{_fmt_minutes(cfg['spray_window_minutes'])} (threshold {threshold} usernames)."
                        ),
                        severity="HIGH",
                        event_indices=[k for _, k in chunk],
                        source_ip=ip,
                        count=len(users),
                        threshold=threshold,
                        window_start=chunk[0][0],
                        window_end=chunk[-1][0],
                        details={"usernames": sorted(users)[:20], "failed_attempts": len(chunk)},
                    )
                )
                i = j + 1
            else:
                i += 1
    return out


def _in_off_hours(hour: int, start: int, end: int) -> bool:
    if start == end:
        return False
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end  # window wraps midnight


def detect_off_hours_privileged(events: Sequence[EventLike], cfg: dict) -> list[Detection]:
    start, end = int(cfg["off_hours_start_utc"]), int(cfg["off_hours_end_utc"])
    out = []
    for idx, ev in enumerate(events):
        if ev.event_type == "LOGIN_SUCCESS" and ev.username in PRIVILEGED_USERNAMES and _in_off_hours(ev.timestamp.hour, start, end):
            out.append(
                Detection(
                    rule_id="OFF_HOURS_PRIVILEGED",
                    title=f"Off-hours login to privileged account '{ev.username}'",
                    description=(
                        f"Privileged account '{ev.username}' logged in from {ev.source_ip} at "
                        f"{ev.timestamp:%H:%M} UTC, inside the configured off-hours window "
                        f"({start:02d}:00-{end:02d}:00 UTC)."
                    ),
                    severity="MEDIUM",
                    event_indices=[idx],
                    source_ip=ev.source_ip,
                    username=ev.username,
                    count=1,
                    window_start=ev.timestamp,
                    window_end=ev.timestamp,
                )
            )
    return out


DETECTORS = [
    detect_brute_force_ip,
    detect_account_targeted,
    detect_high_failure_rate,
    detect_success_after_failures,
    detect_password_spray,
    detect_off_hours_privileged,
]


def run_detection(events: Sequence[EventLike], cfg: dict) -> list[Detection]:
    detections: list[Detection] = []
    for detector in DETECTORS:
        detections.extend(detector(events, cfg))
    detections.sort(key=lambda d: (-SEVERITY_RANK[d.severity], d.window_start or datetime.min))
    return detections


def malformed_detection(rejected_count: int, received: int, cfg: dict) -> Detection | None:
    threshold = int(cfg["malformed_alert_threshold"])
    if rejected_count < threshold:
        return None
    ratio = rejected_count / max(received, 1)
    return Detection(
        rule_id="MALFORMED_ENTRIES",
        title=f"{rejected_count} malformed log entries in one ingestion",
        description=(
            f"{rejected_count} of {received} entries failed validation (threshold {threshold}). "
            "This can indicate a broken log shipper, a format change, or log tampering."
        ),
        severity="MEDIUM" if ratio >= 0.25 else "LOW",
        event_indices=[],
        count=rejected_count,
        threshold=threshold,
        details={"received": received, "rejected_ratio": round(ratio, 3)},
    )
