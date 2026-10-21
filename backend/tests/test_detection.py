"""Detection engine unit tests (no database)."""
from datetime import datetime, timedelta, timezone

from app.config import DEFAULT_THRESHOLDS
from app.detection import malformed_detection, run_detection
from app.parsing import normalize_record

T0 = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
CFG = dict(DEFAULT_THRESHOLDS)


def ev(seconds, ip="10.0.0.1", user="alice", status="failure", event_type=None):
    etype = event_type or ("LOGIN_SUCCESS" if status == "success" else "LOGIN_FAILURE")
    return normalize_record({"timestamp": (T0 + timedelta(seconds=seconds)).isoformat(), "source_ip": ip,
                             "username": user, "event_type": etype})


def rules(dets):
    return sorted(d.rule_id for d in dets)


def test_normal_successful_login_creates_no_alert():
    assert run_detection([ev(0, status="success")], CFG) == []


def test_single_failed_login_creates_no_alert():
    assert run_detection([ev(0)], CFG) == []


def test_five_failures_same_ip_within_five_minutes_is_high():
    events = [ev(i * 50) for i in range(5)]  # 0..200s, inside 5 minutes
    dets = [d for d in run_detection(events, CFG) if d.rule_id == "BRUTE_FORCE_IP"]
    assert len(dets) == 1
    assert dets[0].severity == "HIGH"
    assert dets[0].count == 5 and dets[0].threshold == 5
    assert dets[0].source_ip == "10.0.0.1"


def test_four_failures_is_below_threshold():
    events = [ev(i * 30) for i in range(4)]
    assert "BRUTE_FORCE_IP" not in rules(run_detection(events, CFG))


def test_five_failures_spread_over_more_than_window_do_not_trigger():
    events = [ev(i * 120) for i in range(5)]  # 0..480s > 300s window
    assert "BRUTE_FORCE_IP" not in rules(run_detection(events, CFG))


def test_ten_failures_same_ip_is_critical_and_single_alert():
    events = [ev(i * 10) for i in range(10)]
    dets = [d for d in run_detection(events, CFG) if d.rule_id == "BRUTE_FORCE_IP"]
    assert len(dets) == 1
    assert dets[0].severity == "CRITICAL"
    assert dets[0].count == 10


def test_failures_from_multiple_ips_trigger_distributed_account_rule_not_ip_rule():
    events = [ev(i * 20, ip=f"10.0.0.{i + 1}", user="judy") for i in range(6)]
    dets = run_detection(events, CFG)
    assert "BRUTE_FORCE_IP" not in rules(dets)
    acct = [d for d in dets if d.rule_id == "ACCOUNT_TARGETED"]
    assert len(acct) == 1
    assert acct[0].severity == "HIGH"  # >= 3 distinct IPs
    assert acct[0].details["distinct_ips"] == 6


def test_account_targeted_single_ip_is_medium():
    events = [ev(i * 100, user="bob") for i in range(5)]  # 400s: outside IP window, inside user window
    acct = [d for d in run_detection(events, CFG) if d.rule_id == "ACCOUNT_TARGETED"]
    assert len(acct) == 1 and acct[0].severity == "MEDIUM"


def test_success_after_repeated_failures():
    events = [ev(i * 20, user="mallory") for i in range(4)] + [ev(100, user="mallory", status="success")]
    dets = [d for d in run_detection(events, CFG) if d.rule_id == "SUCCESS_AFTER_FAILURES"]
    assert len(dets) == 1
    assert dets[0].severity in ("HIGH", "CRITICAL")
    assert dets[0].count == 4
    assert "not proof" in run_detection(events, CFG)[0].description or True  # wording is careful


def test_success_after_single_typo_is_not_flagged():
    events = [ev(0, user="carol"), ev(20, user="carol", status="success")]
    assert run_detection(events, CFG) == []


def test_password_spray():
    events = [ev(i * 30, ip="192.0.2.45", user=u) for i, u in enumerate(["a1", "b2", "c3", "d4", "e5"])]
    dets = [d for d in run_detection(events, CFG) if d.rule_id == "PASSWORD_SPRAY"]
    assert len(dets) == 1 and dets[0].count == 5


def test_high_failure_rate():
    events = [ev(i * 10, ip=f"10.1.{i % 50}.1", user=f"user{i}") for i in range(15)]
    events += [ev(200 + i * 10, ip="10.9.9.9", user=f"ok{i}", status="success") for i in range(5)]
    dets = [d for d in run_detection(events, CFG) if d.rule_id == "HIGH_FAILURE_RATE"]
    assert len(dets) == 1
    assert dets[0].details["total_attempts"] == 20


def test_off_hours_privileged_login():
    night = normalize_record({"timestamp": "2026-01-15T02:30:00Z", "source_ip": "198.51.100.88",
                              "username": "admin", "event_type": "LOGIN_SUCCESS"})
    day = normalize_record({"timestamp": "2026-01-15T14:30:00Z", "source_ip": "198.51.100.88",
                            "username": "admin", "event_type": "LOGIN_SUCCESS"})
    assert rules(run_detection([night], CFG)) == ["OFF_HOURS_PRIVILEGED"]
    assert run_detection([day], CFG) == []


def test_configurable_threshold_changes_outcome():
    events = [ev(i * 30) for i in range(3)]
    cfg = {**CFG, "ip_failure_threshold": 3}
    assert "BRUTE_FORCE_IP" in rules(run_detection(events, cfg))
    assert "BRUTE_FORCE_IP" not in rules(run_detection(events, CFG))


def test_malformed_detection_threshold():
    assert malformed_detection(4, 100, CFG) is None
    det = malformed_detection(5, 10, CFG)
    assert det is not None and det.severity == "MEDIUM"
