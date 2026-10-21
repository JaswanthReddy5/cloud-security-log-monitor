"""Parsing and validation tests."""
import json

import pytest

from app.parsing import InvalidFile, normalize_record, parse_file


def test_valid_record_is_normalized():
    rec = normalize_record({"Timestamp": "2026-01-15 12:00:00", "IP": "10.0.0.1", "User": "Alice", "status": "failed"})
    assert rec.event_type == "LOGIN_FAILURE" and rec.status == "failure"
    assert rec.username == "alice"
    assert rec.timestamp.tzinfo is not None


@pytest.mark.parametrize("ts", ["not-a-date", "2026-13-45T00:00:00Z", "", "1999-01-01T00:00:00Z", "2999-01-01T00:00:00Z"])
def test_invalid_timestamps_are_rejected(ts):
    with pytest.raises(ValueError):
        normalize_record({"timestamp": ts, "source_ip": "10.0.0.1", "username": "a", "event_type": "LOGIN_SUCCESS"})


def test_epoch_timestamp_accepted():
    rec = normalize_record({"timestamp": 1768478400, "source_ip": "10.0.0.1", "username": "a", "status": "success"})
    assert rec.timestamp.year == 2026


@pytest.mark.parametrize("missing", ["timestamp", "source_ip", "username"])
def test_missing_required_fields(missing):
    rec = {"timestamp": "2026-01-15T12:00:00Z", "source_ip": "10.0.0.1", "username": "a", "event_type": "LOGIN_SUCCESS"}
    rec.pop(missing)
    with pytest.raises(ValueError, match="missing required"):
        normalize_record(rec)


def test_missing_event_type_and_status():
    with pytest.raises(ValueError, match="event_type/status"):
        normalize_record({"timestamp": "2026-01-15T12:00:00Z", "source_ip": "10.0.0.1", "username": "a"})


@pytest.mark.parametrize("field,value", [("source_ip", "999.1.1.1"), ("username", "bob; DROP TABLE"),
                                         ("event_type", "TELEPORT"), ("status", "maybe")])
def test_invalid_field_values(field, value):
    rec = {"timestamp": "2026-01-15T12:00:00Z", "source_ip": "10.0.0.1", "username": "a", "event_type": "LOGIN_SUCCESS"}
    rec[field] = value
    with pytest.raises(ValueError):
        normalize_record(rec)


def test_contradictory_status_rejected():
    with pytest.raises(ValueError, match="contradicts"):
        normalize_record({"timestamp": "2026-01-15T12:00:00Z", "source_ip": "10.0.0.1", "username": "a",
                          "event_type": "LOGIN_SUCCESS", "status": "failure"})


def test_csv_file_partial_rejection():
    data = b"timestamp,source_ip,username,status\n2026-01-15T12:00:00Z,10.0.0.1,alice,success\nbad,10.0.0.1,bob,failure\n"
    fmt, res = parse_file(data, "logs.csv", 100)
    assert fmt == "csv" and len(res.records) == 1 and len(res.rejected) == 1
    assert res.rejected[0].row == 2


def test_json_formats():
    one = {"timestamp": "2026-01-15T12:00:00Z", "source_ip": "10.0.0.1", "username": "a", "status": "success"}
    for payload in (json.dumps([one]), json.dumps({"events": [one]}), json.dumps(one) + "\n" + json.dumps(one)):
        _, res = parse_file(payload.encode(), "x.json", 100)
        assert len(res.records) >= 1


@pytest.mark.parametrize("data,name,code", [
    (b"", "a.csv", "empty_file"),
    (b"   \n  ", "a.json", "empty_file"),
    (b"[]", "a.json", "empty_file"),
    (b"timestamp,source_ip,username,status\n", "a.csv", "empty_file"),
    (b"{not json", "a.json", "invalid_json"),
    (b"\"just a string\"", "a.json", "invalid_json"),
    (b"foo,bar\n1,2\n", "a.csv", "invalid_csv"),
    (b"\x89PNG\r\n\x1a\n\x00\x00", "a.csv", "unsupported_format"),
    (b"\xff\xfe\xfa", "a.csv", "unsupported_format"),
    (b"print('hi')", "evil.py", "unsupported_format"),
])
def test_invalid_files(data, name, code):
    with pytest.raises(InvalidFile) as exc:
        parse_file(data, name, 100)
    assert exc.value.code == code


def test_too_many_records():
    rows = "\n".join("2026-01-15T12:00:00Z,10.0.0.1,a,success" for _ in range(11))
    with pytest.raises(InvalidFile) as exc:
        parse_file(("timestamp,source_ip,username,status\n" + rows).encode(), "a.csv", 10)
    assert exc.value.code == "too_many_records"


def test_formula_like_content_is_just_data():
    data = b"timestamp,source_ip,username,status\n2026-01-15T12:00:00Z,10.0.0.1,=cmd|' /C calc'!A0,success\n"
    _, res = parse_file(data, "a.csv", 10)
    assert len(res.rejected) == 1 and "invalid username" in res.rejected[0].reason
