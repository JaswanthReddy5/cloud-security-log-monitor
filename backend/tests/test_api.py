"""API, persistence and error-handling tests (SQLite test database)."""
import io
import json

from conftest import ADMIN

GOOD_CSV = (
    "timestamp,source_ip,username,event_type,status\n"
    + "".join(f"2026-01-15T12:00:{i * 10:02d}Z,203.0.113.7,bob,LOGIN_FAILURE,failure\n" for i in range(5))
    + "2026-01-15T12:01:00Z,10.0.0.1,alice,LOGIN_SUCCESS,success\n"
    + "garbage,10.0.0.1,alice,LOGIN_SUCCESS,success\n"
)


def upload(client, content: bytes, name: str):
    return client.post("/api/logs/upload", data={"file": (io.BytesIO(content), name)}, content_type="multipart/form-data")


def test_health_ok(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True and body["data"]["database"]["reachable"] is True


def test_security_headers(client):
    r = client.get("/api/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"


def test_empty_stats(client):
    data = client.get("/api/stats").get_json()["data"]
    assert data["total_events"] == 0 and data["alerts"]["total"] == 0
    assert data["data_mode"]["is_demo"] is True


def test_generate_synthetic_logs_triggers_all_rules(client):
    r = client.post("/api/logs/generate", json={"count": 200})
    assert r.status_code == 201
    batch = r.get_json()["data"]["batch"]
    assert batch["is_synthetic"] and batch["imported"] > 200 and batch["rejected"] == 6
    assert batch["analyzed"] == batch["imported"]
    alerts = client.get("/api/alerts?page_size=200").get_json()["data"]
    rules = {a["rule_id"] for a in alerts}
    assert {"BRUTE_FORCE_IP", "ACCOUNT_TARGETED", "HIGH_FAILURE_RATE", "SUCCESS_AFTER_FAILURES",
            "PASSWORD_SPRAY", "OFF_HOURS_PRIVILEGED", "MALFORMED_ENTRIES"} <= rules
    stats = client.get("/api/stats").get_json()["data"]
    assert stats["critical_events"] > 0 and stats["high_events"] > 0
    assert stats["suspicious_ips"] >= 3
    assert stats["malformed_events"] == 6
    assert stats["data_mode"]["synthetic_events"] == stats["total_events"]
    assert stats["timeline"]["points"]


def test_generate_validation(client):
    assert client.post("/api/logs/generate", json={"count": -1}).status_code == 422
    assert client.post("/api/logs/generate", json={"count": "lots"}).status_code == 422
    assert client.post("/api/logs/generate", json={"scenarios": ["hack_nasa"]}).status_code == 422


def test_csv_upload_and_persistence(client, app):
    r = upload(client, GOOD_CSV.encode(), "logs.csv")
    assert r.status_code == 201, r.get_json()
    batch = r.get_json()["data"]["batch"]
    assert (batch["imported"], batch["rejected"], batch["source"]) == (6, 1, "csv")
    assert batch["is_synthetic"] is False
    # Persistence: a brand-new app instance on the same database sees the data.
    from app import create_app
    other = create_app(app.config["SETTINGS"], database_url=app.config["DB"].url, testing=True)
    stats = other.test_client().get("/api/stats").get_json()["data"]
    assert stats["total_events"] == 7 and stats["failed_logins"] == 5
    alerts = other.test_client().get("/api/alerts?severity=HIGH").get_json()["data"]
    assert any(a["rule_id"] == "BRUTE_FORCE_IP" and a["source_ip"] == "203.0.113.7" for a in alerts)


def test_json_upload(client):
    events = [{"timestamp": "2026-01-15T12:00:00Z", "source_ip": "10.0.0.1", "username": "a", "status": "success"}]
    r = upload(client, json.dumps({"events": events}).encode(), "logs.json")
    assert r.status_code == 201 and r.get_json()["data"]["batch"]["imported"] == 1


def test_invalid_uploads(client):
    assert upload(client, b"", "empty.csv").status_code == 400
    assert upload(client, b"{broken", "x.json").status_code == 400
    assert upload(client, b"a,b\n1,2", "x.csv").status_code == 400
    assert upload(client, b"MZ\x00\x00binary", "x.exe").status_code == 400
    r = upload(client, b"timestamp,source_ip,username,status\nbad,bad,bad,bad\n", "x.csv")
    assert r.status_code == 400 and r.get_json()["error"]["code"] == "no_valid_records"
    r = client.post("/api/logs/upload", data={}, content_type="multipart/form-data")
    assert r.status_code == 400 and r.get_json()["error"]["code"] == "missing_file"


def test_upload_too_large(make_app):
    client = make_app(max_upload_bytes=100).test_client()
    r = upload(client, GOOD_CSV.encode(), "logs.csv")
    assert r.status_code == 413


def test_json_ingest_endpoint(client):
    r = client.post("/api/logs/ingest", json={"events": [
        {"timestamp": "2026-01-15T12:00:00Z", "source_ip": "10.0.0.1", "username": "a", "status": "failure"}]})
    assert r.status_code == 201
    assert client.post("/api/logs/ingest", data="nope", content_type="text/plain").status_code == 400


def test_events_filter_search_sort_paginate(client):
    upload(client, GOOD_CSV.encode(), "logs.csv")
    d = client.get("/api/events?status=failure").get_json()
    assert d["meta"]["total"] == 5 and all(e["status"] == "failure" for e in d["data"])
    d = client.get("/api/events?search=alice").get_json()
    assert d["meta"]["total"] == 1
    d = client.get("/api/events?event_type=MALFORMED").get_json()
    assert d["meta"]["total"] == 1 and d["data"][0]["raw"]
    d = client.get("/api/events?sort=timestamp&order=asc&page_size=2&page=1").get_json()
    assert len(d["data"]) == 2 and d["meta"]["pages"] == 4
    d = client.get("/api/events?severity=HIGH").get_json()
    assert d["meta"]["total"] == 5 and all(e["detection_rule"] == "BRUTE_FORCE_IP" for e in d["data"])
    assert d["data"][0]["count"] == 5 and d["data"][0]["threshold"] == 5


def test_events_bad_params(client):
    for q in ("severity=SUPER", "sort=password", "order=sideways", "page=0", "page_size=1000", "page=abc"):
        r = client.get(f"/api/events?{q}")
        assert r.status_code == 422, q
        assert r.get_json()["ok"] is False


def test_alert_acknowledge_workflow(client):
    upload(client, GOOD_CSV.encode(), "logs.csv")
    open_before = client.get("/api/alerts?status=open").get_json()["meta"]["total"]
    alert = client.get("/api/alerts").get_json()["data"][0]
    assert alert["acknowledged"] is False
    r = client.patch(f"/api/alerts/{alert['id']}", json={"acknowledged": True})
    assert r.status_code == 200 and r.get_json()["data"]["acknowledged"] is True
    assert r.get_json()["data"]["acknowledged_at"]
    assert client.get("/api/alerts?status=open").get_json()["meta"]["total"] == open_before - 1
    assert client.get("/api/alerts?status=acknowledged").get_json()["meta"]["total"] == 1
    r = client.patch(f"/api/alerts/{alert['id']}", json={"acknowledged": False})
    assert r.get_json()["data"]["acknowledged"] is False and r.get_json()["data"]["acknowledged_at"] is None
    assert client.patch("/api/alerts/99999", json={"acknowledged": True}).status_code == 404
    assert client.patch(f"/api/alerts/{alert['id']}", json={"acknowledged": "yes"}).status_code == 422
    assert client.get("/api/alerts?status=whatever").status_code == 422


def test_reset_requires_admin_and_confirmation(client):
    client.post("/api/logs/generate", json={"count": 10})
    assert client.post("/api/admin/reset", json={"confirm": "RESET"}).status_code == 401
    assert client.post("/api/admin/reset", json={"confirm": "RESET"}, headers={"X-Admin-Key": "wrong"}).status_code == 401
    assert client.post("/api/admin/reset", json={}, headers=ADMIN).status_code == 422
    r = client.post("/api/admin/reset", json={"confirm": "RESET"}, headers=ADMIN)
    assert r.status_code == 200 and r.get_json()["data"]["deleted"]["events"] > 0
    assert client.get("/api/stats").get_json()["data"]["total_events"] == 0


def test_admin_disabled_without_key(make_app):
    client = make_app(admin_key=None).test_client()
    r = client.post("/api/admin/reset", json={"confirm": "RESET"}, headers={"X-Admin-Key": ""})
    assert r.status_code == 403 and r.get_json()["error"]["code"] == "admin_disabled"


def test_settings_update_and_effect(client):
    cfg = client.get("/api/settings").get_json()["data"]["thresholds"]
    assert cfg["ip_failure_threshold"] == 5
    assert client.put("/api/settings", json={"thresholds": {"ip_failure_threshold": 3}}).status_code == 401
    r = client.put("/api/settings", json={"thresholds": {"ip_failure_threshold": 99999}}, headers=ADMIN)
    assert r.status_code == 422
    r = client.put("/api/settings", json={"thresholds": {"bogus": 1}}, headers=ADMIN)
    assert r.status_code == 422
    r = client.put("/api/settings", json={"thresholds": {"ip_failure_threshold": 3}}, headers=ADMIN)
    assert r.status_code == 200 and r.get_json()["data"]["thresholds"]["ip_failure_threshold"] == 3
    csv_data = "timestamp,source_ip,username,status\n" + "".join(
        f"2026-01-15T12:00:0{i}Z,10.0.0.9,zed,failure\n" for i in range(3))
    upload(client, csv_data.encode(), "x.csv")
    assert any(a["rule_id"] == "BRUTE_FORCE_IP" for a in client.get("/api/alerts").get_json()["data"])


def test_rules_and_sample_endpoints(client):
    rules = client.get("/api/rules").get_json()["data"]
    assert len(rules) == 7 and all("current" in r for r in rules)
    r = client.get("/api/logs/sample?format=csv")
    assert r.status_code == 200 and "attachment" in r.headers["Content-Disposition"]
    # The sample must itself be a valid upload.
    assert upload(client, r.data, "sample.csv").status_code == 201
    r = client.get("/api/logs/sample?format=json")
    assert r.status_code == 200 and json.loads(r.data)["events"]
    assert client.get("/api/logs/sample?format=xml").status_code == 422


def test_unknown_route_and_method(client):
    r = client.get("/api/nope")
    assert r.status_code == 404 and r.get_json()["ok"] is False
    assert client.delete("/api/stats").status_code == 405


def test_database_not_configured(make_app):
    client = make_app(database_url="").test_client()
    r = client.get("/api/stats")
    assert r.status_code == 503 and r.get_json()["error"]["code"] == "database_unavailable"
    h = client.get("/api/health")
    assert h.status_code == 503 and h.get_json()["data"]["database"]["configured"] is False


def test_database_unreachable(make_app):
    client = make_app(database_url="postgresql+psycopg://user:pw@127.0.0.1:1/nodb").test_client()
    r = client.get("/api/events")
    assert r.status_code == 503 and r.get_json()["error"]["code"] == "database_unavailable"
    assert "pw" not in r.get_data(as_text=True)  # never leak connection details
    assert client.get("/api/health").get_json()["data"]["status"] == "degraded"


def test_production_requires_database_url():
    from app.config import Settings
    assert Settings(environment="production").resolved_database_url() is None
    s = Settings(environment="production", database_url="postgres://u:p@host/db")
    assert s.resolved_database_url().startswith("postgresql+psycopg://")


def test_env_values_are_sanitized(monkeypatch):
    from app.config import Settings
    monkeypatch.setenv("DATABASE_URL", "﻿postgresql://u:p@host/db\n")
    monkeypatch.setenv("ADMIN_API_KEY", "﻿secret-key \r\n")
    s = Settings.from_env()
    assert s.database_url == "postgresql://u:p@host/db"
    assert s.admin_api_key == "secret-key"


def test_rate_limit(make_app):
    app = make_app()
    app.config["TESTING_DISABLE_RATE_LIMIT"] = False
    client = app.test_client()
    codes = [client.post("/api/logs/generate", json={"count": 0, "scenarios": ["baseline"]}).status_code for _ in range(12)]
    assert 429 in codes
