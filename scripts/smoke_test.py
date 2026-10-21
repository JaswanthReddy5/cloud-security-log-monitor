"""End-to-end smoke test against a running deployment (local or production).

Usage:
    python scripts/smoke_test.py http://127.0.0.1:5000
    python scripts/smoke_test.py https://your-app.vercel.app [--reset]

The admin key (only needed for --reset and the admin checks) is read from the
ADMIN_API_KEY environment variable or a local .env file; it is never printed.
Only the Python standard library is used.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
import uuid

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000").rstrip("/")
RESET = "--reset" in sys.argv


def admin_key() -> str:
    key = os.environ.get("ADMIN_API_KEY", "")
    env = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if not key and os.path.exists(env):
        for line in open(env, encoding="utf-8"):
            if line.startswith("ADMIN_API_KEY="):
                key = line.split("=", 1)[1].strip()
    return key


def call(method: str, path: str, body=None, headers=None, raw: bytes | None = None, ctype: str | None = None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    h = {"User-Agent": "seclog-smoke-test/1.0", **(headers or {})}
    if data is not None:
        h["Content-Type"] = ctype or "application/json"
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            txt = r.read().decode()
            return r.status, (json.loads(txt) if r.headers.get_content_type() == "application/json" else txt)
    except urllib.error.HTTPError as e:
        txt = e.read().decode()
        try:
            return e.code, json.loads(txt)
        except json.JSONDecodeError:
            return e.code, txt


passed = failed = 0


def check(name: str, cond: bool, info: str = ""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name} {info}")


def multipart(filename: str, content: bytes):
    boundary = uuid.uuid4().hex
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


print(f"Smoke test against {BASE}")
key = admin_key()
admin = {"X-Admin-Key": key}

s, b = call("GET", "/api/health")
check("health reachable + database connected", s == 200 and b["data"]["database"]["reachable"], str(b))
print(f"        database dialect: {b.get('data', {}).get('database', {}).get('dialect')}")

if RESET:
    s, b = call("POST", "/api/admin/reset", {"confirm": "RESET"}, admin)
    check("admin reset", s == 200, str(b))

s, before = call("GET", "/api/stats")
check("stats endpoint", s == 200)
n0 = before["data"]["total_events"]

s, b = call("POST", "/api/logs/generate", {"count": 250})
check("generate synthetic logs (201)", s == 201, str(b)[:200])
batch = b["data"]["batch"] if s == 201 else {}
print(f"        imported={batch.get('imported')} rejected={batch.get('rejected')} alerts={batch.get('alerts_created')}")

s, after = call("GET", "/api/stats")
st = after["data"]
check("dashboard stats updated", st["total_events"] > n0, f"{n0} -> {st['total_events']}")
check("synthetic data flagged", st["data_mode"]["synthetic_events"] > 0)
check("critical + high events present", st["critical_events"] > 0 and st["high_events"] > 0)

s, al = call("GET", "/api/alerts?page_size=200&status=all")
rules = {a["rule_id"] for a in al["data"]}
expected = {"BRUTE_FORCE_IP", "ACCOUNT_TARGETED", "HIGH_FAILURE_RATE", "SUCCESS_AFTER_FAILURES", "PASSWORD_SPRAY",
            "OFF_HOURS_PRIVILEGED", "MALFORMED_ENTRIES"}
check("all 7 detection rules fired", expected <= rules, f"missing {expected - rules}")

s, ev = call("GET", "/api/events?severity=CRITICAL&page_size=5")
check("event filter by severity", s == 200 and all(e["severity"] == "CRITICAL" for e in ev["data"]) and ev["data"])
s, ev = call("GET", "/api/events?search=203.0.113.7&sort=timestamp&order=asc")
check("event search + sort", s == 200 and ev["meta"]["total"] > 0)

target = next(a for a in al["data"] if not a["acknowledged"])
s, b = call("PATCH", f"/api/alerts/{target['id']}", {"acknowledged": True})
check("acknowledge alert", s == 200 and b["data"]["acknowledged"] is True)
s, b = call("GET", "/api/alerts?status=acknowledged&page_size=200")
check("acknowledgement persisted (re-read)", any(a["id"] == target["id"] for a in b["data"]))
s, b = call("PATCH", f"/api/alerts/{target['id']}", {"acknowledged": False})
check("unacknowledge alert", s == 200 and b["data"]["acknowledged"] is False)

s, sample = call("GET", "/api/logs/sample?format=csv")
check("download sample CSV", s == 200 and "timestamp,source_ip" in sample)
body, ctype = multipart("sample.csv", sample.encode())
s, b = call("POST", "/api/logs/upload", raw=body, ctype=ctype)
check("upload CSV", s == 201 and b["data"]["batch"]["imported"] > 0, str(b)[:200])
body, ctype = multipart("bad.json", b"{not json")
s, b = call("POST", "/api/logs/upload", raw=body, ctype=ctype)
check("invalid JSON rejected (400)", s == 400 and b["ok"] is False)
body, ctype = multipart("empty.csv", b"")
s, b = call("POST", "/api/logs/upload", raw=body, ctype=ctype)
check("empty file rejected (400)", s == 400)

s, b = call("POST", "/api/admin/reset", {"confirm": "RESET"})
check("reset blocked without admin key (401/403)", s in (401, 403))
s, b = call("PUT", "/api/settings", {"thresholds": {"ip_failure_threshold": 2}})
check("settings change blocked without admin key", s in (401, 403))
if key:
    s, b = call("POST", "/api/admin/verify", headers=admin)
    check("admin key accepted", s == 200, str(b))

s, b = call("GET", "/api/does-not-exist")
check("unknown endpoint -> JSON 404", s == 404 and b["ok"] is False)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
