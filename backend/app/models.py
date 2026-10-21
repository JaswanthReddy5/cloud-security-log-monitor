"""Database schema (SQLAlchemy 2.x ORM)."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


class Base(DeclarativeBase):
    pass


class IngestBatch(Base):
    """One ingestion run: a synthetic generation, an upload, or an API push."""

    __tablename__ = "ingest_batches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(20))  # synthetic | csv | json | api
    filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    received: Mapped[int] = mapped_column(Integer, default=0)
    imported: Mapped[int] = mapped_column(Integer, default=0)
    rejected: Mapped[int] = mapped_column(Integer, default=0)
    analyzed: Mapped[int] = mapped_column(Integer, default=0)
    alerts_created: Mapped[int] = mapped_column(Integer, default=0)
    client_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": self.source,
            "filename": self.filename,
            "is_synthetic": self.is_synthetic,
            "received": self.received,
            "imported": self.imported,
            "rejected": self.rejected,
            "analyzed": self.analyzed,
            "alerts_created": self.alerts_created,
            "created_at": _iso(self.created_at),
        }


class LogEvent(Base):
    """A normalized security log event."""

    __tablename__ = "log_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    batch_id: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    username: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True)  # success | failure | unknown | invalid
    severity: Mapped[str] = mapped_column(String(10), index=True, default="INFO")
    description: Mapped[str] = mapped_column(Text, default="")
    detection_rule: Mapped[str | None] = mapped_column(String(48), nullable=True, index=True)
    rule_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rule_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    raw: Mapped[str | None] = mapped_column(Text, nullable=True)  # only kept for malformed rows
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (Index("ix_events_ip_ts", "source_ip", "timestamp"),)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "batch_id": self.batch_id,
            "timestamp": _iso(self.timestamp),
            "source_ip": self.source_ip,
            "username": self.username,
            "event_type": self.event_type,
            "status": self.status,
            "severity": self.severity,
            "description": self.description,
            "detection_rule": self.detection_rule,
            "count": self.rule_count,
            "threshold": self.rule_threshold,
            "is_synthetic": self.is_synthetic,
            "raw": self.raw,
        }


class Alert(Base):
    """A rule-based detection. Not proof of compromise."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    batch_id: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)
    rule_id: Mapped[str] = mapped_column(String(48), index=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(10), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    failed_attempts: Mapped[int | None] = mapped_column(Integer, nullable=True)
    threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "batch_id": self.batch_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "username": self.username,
            "failed_attempts": self.failed_attempts,
            "threshold": self.threshold,
            "window_start": _iso(self.window_start),
            "window_end": _iso(self.window_end),
            "detected_at": _iso(self.detected_at),
            "acknowledged": self.acknowledged,
            "acknowledged_at": _iso(self.acknowledged_at),
            "is_synthetic": self.is_synthetic,
            "details": self.details or {},
        }


class AppSetting(Base):
    """Runtime-editable key/value settings (detection thresholds)."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[float] = mapped_column(Float)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:  # SQLite returns naive datetimes; values are stored as UTC.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
