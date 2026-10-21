"""Synthetic security log generator.

All generated data is fake. IP addresses come from the documentation ranges
reserved by RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and the
private 10.0.0.0/8 range, so they can never point at a real third party.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

USERS = [
    "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy",
    "mallory", "niaj", "olivia", "peggy", "rupert", "sybil", "trent", "victor", "walter", "admin",
]
INTERNAL_IPS = [f"10.20.{a}.{b}" for a, b in [(1, 15), (1, 22), (2, 8), (2, 41), (3, 3), (3, 77), (4, 12), (5, 90)]]
EXTERNAL_IPS = [f"198.51.100.{n}" for n in (14, 23, 57, 88, 102, 140)]
ATTACKER_IPS = [f"203.0.113.{n}" for n in (7, 13, 42, 66, 99, 131, 177, 200, 222)]
SPRAY_IP = "192.0.2.45"

SCENARIOS = [
    "baseline",
    "brute_force",
    "password_spray",
    "distributed_account_attack",
    "success_after_failures",
    "off_hours_admin",
    "failure_burst",
    "malformed",
]


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _ev(ts: datetime, ip: str, user: str, event_type: str, status: str) -> dict:
    return {"timestamp": _iso(ts), "source_ip": ip, "username": user, "event_type": event_type, "status": status}


def generate(count: int = 250, seed: int | None = None, now: datetime | None = None, scenarios: list[str] | None = None) -> list[dict]:
    """Return a list of raw log records (dicts) including attack scenarios."""
    rng = random.Random(seed)
    now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    enabled = set(scenarios or SCENARIOS)
    start = now - timedelta(hours=24)
    out: list[dict] = []

    # Normal traffic over the last 24h with a day/night pattern (busier 08-18 UTC):
    # mostly successes, rare single typos, logouts and resets.
    if "baseline" in enabled:
        for _ in range(max(count, 0)):
            while True:
                ts = start + timedelta(seconds=rng.randint(0, 24 * 3600 - 60))
                weight = 1.0 if 8 <= ts.hour < 18 else 0.25
                if rng.random() < weight:
                    break
            user = rng.choice(USERS[:-1])
            ip = rng.choice(INTERNAL_IPS + EXTERNAL_IPS[:3])
            roll = rng.random()
            if roll < 0.80:
                out.append(_ev(ts, ip, user, "LOGIN_SUCCESS", "success"))
            elif roll < 0.88:
                out.append(_ev(ts, ip, user, "LOGIN_FAILURE", "failure"))
                out.append(_ev(ts + timedelta(seconds=rng.randint(10, 50)), ip, user, "LOGIN_SUCCESS", "success"))
            elif roll < 0.97:
                out.append(_ev(ts, ip, user, "LOGOUT", "success"))
            elif roll < 0.99:
                out.append(_ev(ts, ip, user, "PASSWORD_RESET", "success"))
            else:
                out.append(_ev(ts, ip, user, "MFA_FAILURE", "failure"))

    # 1. Brute force: 12 failures from one IP against one user in ~3 minutes.
    if "brute_force" in enabled:
        t0 = now - timedelta(minutes=95)
        ip = ATTACKER_IPS[0]
        for i in range(12):
            out.append(_ev(t0 + timedelta(seconds=15 * i), ip, "bob", "LOGIN_FAILURE", "failure"))
        out.append(_ev(t0 + timedelta(seconds=190), ip, "bob", "ACCOUNT_LOCKED", "failure"))

    # 2. Password spray: one IP tries 8 different accounts once or twice.
    if "password_spray" in enabled:
        t0 = now - timedelta(minutes=70)
        for i, user in enumerate(["alice", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan"]):
            out.append(_ev(t0 + timedelta(seconds=40 * i), SPRAY_IP, user, "LOGIN_FAILURE", "failure"))

    # 3. Distributed attack on one account from many IPs (each IP stays below its threshold).
    if "distributed_account_attack" in enabled:
        t0 = now - timedelta(minutes=50)
        for i, ip in enumerate(ATTACKER_IPS[1:7]):
            out.append(_ev(t0 + timedelta(seconds=30 * i), ip, "judy", "LOGIN_FAILURE", "failure"))

    # 4. Success after a burst of failures (possible guessed password).
    if "success_after_failures" in enabled:
        t0 = now - timedelta(minutes=30)
        ip = ATTACKER_IPS[7]
        for i in range(4):
            out.append(_ev(t0 + timedelta(seconds=20 * i), ip, "mallory", "LOGIN_FAILURE", "failure"))
        out.append(_ev(t0 + timedelta(seconds=100), ip, "mallory", "LOGIN_SUCCESS", "success"))

    # 5. Off-hours privileged login (placed at 02:xx UTC of the most recent night).
    if "off_hours_admin" in enabled:
        night = now.replace(hour=2, minute=rng.randint(5, 50), second=0)
        if night > now:
            night -= timedelta(days=1)
        out.append(_ev(night, EXTERNAL_IPS[4], "admin", "LOGIN_SUCCESS", "success"))

    # 6. Failure burst: credential-stuffing style wave pushing the failure rate up.
    if "failure_burst" in enabled:
        t0 = now - timedelta(minutes=15)
        for i in range(36):
            ip = ATTACKER_IPS[(i % 4) + 3]
            user = rng.choice(USERS)
            out.append(_ev(t0 + timedelta(seconds=6 * i), ip, user, "LOGIN_FAILURE", "failure"))

    # 7. Malformed entries (exercise validation; stored as MALFORMED events).
    if "malformed" in enabled:
        t0 = now - timedelta(minutes=10)
        out.extend(
            [
                {"timestamp": "not-a-date", "source_ip": "10.20.1.15", "username": "alice", "event_type": "LOGIN_SUCCESS"},
                {"timestamp": _iso(t0), "source_ip": "999.1.1.1", "username": "bob", "event_type": "LOGIN_FAILURE"},
                {"timestamp": _iso(t0), "source_ip": "10.20.2.8", "event_type": "LOGIN_FAILURE"},
                {"timestamp": _iso(t0), "source_ip": "10.20.2.8", "username": "carol", "event_type": "TELEPORT"},
                {"timestamp": _iso(t0), "source_ip": "10.20.3.3", "username": "dave; DROP TABLE users", "status": "failure"},
                {"timestamp": _iso(t0), "source_ip": "10.20.3.3", "username": "erin", "event_type": "LOGIN_SUCCESS", "status": "failure"},
            ]
        )

    out.sort(key=lambda r: str(r.get("timestamp")))
    return out


def sample_records() -> list[dict]:
    """Small deterministic sample used for the downloadable sample file."""
    base = datetime.now(timezone.utc).replace(microsecond=0, second=0) - timedelta(hours=1)
    recs = [
        _ev(base, "10.20.1.15", "alice", "LOGIN_SUCCESS", "success"),
        _ev(base + timedelta(minutes=2), "10.20.2.8", "carol", "LOGIN_FAILURE", "failure"),
        _ev(base + timedelta(minutes=2, seconds=30), "10.20.2.8", "carol", "LOGIN_SUCCESS", "success"),
    ]
    for i in range(6):
        recs.append(_ev(base + timedelta(minutes=10, seconds=20 * i), "203.0.113.7", "bob", "LOGIN_FAILURE", "failure"))
    for i in range(3):
        recs.append(_ev(base + timedelta(minutes=20, seconds=15 * i), "203.0.113.99", "mallory", "LOGIN_FAILURE", "failure"))
    recs.append(_ev(base + timedelta(minutes=21), "203.0.113.99", "mallory", "LOGIN_SUCCESS", "success"))
    recs.append(_ev(base + timedelta(minutes=30), "10.20.1.15", "alice", "LOGOUT", "success"))
    return recs
