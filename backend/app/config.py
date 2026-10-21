"""Environment-based configuration.

All secrets come from environment variables. Nothing sensitive is hardcoded.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


# Default detection thresholds. They can be overridden by env vars at startup
# and changed at runtime through the admin-protected settings API.
DEFAULT_THRESHOLDS: dict[str, float] = {
    # Rule 1: repeated failed logins from the same IP
    "ip_failure_threshold": _int("IP_FAILURE_THRESHOLD", 5),
    "ip_failure_window_minutes": _int("IP_FAILURE_WINDOW_MINUTES", 5),
    # Rule 2: many failures against the same username
    "user_failure_threshold": _int("USER_FAILURE_THRESHOLD", 5),
    "user_failure_window_minutes": _int("USER_FAILURE_WINDOW_MINUTES", 10),
    "distributed_ip_threshold": _int("DISTRIBUTED_IP_THRESHOLD", 3),
    # Rule 3: high overall failure rate in a time window
    "failure_rate_threshold": _float("FAILURE_RATE_THRESHOLD", 0.5),
    "failure_rate_window_minutes": _int("FAILURE_RATE_WINDOW_MINUTES", 10),
    "failure_rate_min_events": _int("FAILURE_RATE_MIN_EVENTS", 20),
    # Rule 4: success after a burst of failures
    "success_after_failures_threshold": _int("SUCCESS_AFTER_FAILURES_THRESHOLD", 3),
    "success_after_failures_window_minutes": _int("SUCCESS_AFTER_FAILURES_WINDOW_MINUTES", 10),
    # Rule 5: suspicious patterns (password spraying / off-hours privileged logins)
    "spray_username_threshold": _int("SPRAY_USERNAME_THRESHOLD", 5),
    "spray_window_minutes": _int("SPRAY_WINDOW_MINUTES", 10),
    "off_hours_start_utc": _int("OFF_HOURS_START_UTC", 0),
    "off_hours_end_utc": _int("OFF_HOURS_END_UTC", 5),
    # Rule 6: malformed entries
    "malformed_alert_threshold": _int("MALFORMED_ALERT_THRESHOLD", 5),
}

# Bounds used to validate threshold updates (min, max).
THRESHOLD_BOUNDS: dict[str, tuple[float, float]] = {
    "ip_failure_threshold": (2, 1000),
    "ip_failure_window_minutes": (1, 1440),
    "user_failure_threshold": (2, 1000),
    "user_failure_window_minutes": (1, 1440),
    "distributed_ip_threshold": (2, 100),
    "failure_rate_threshold": (0.05, 1.0),
    "failure_rate_window_minutes": (1, 1440),
    "failure_rate_min_events": (2, 10000),
    "success_after_failures_threshold": (1, 1000),
    "success_after_failures_window_minutes": (1, 1440),
    "spray_username_threshold": (2, 1000),
    "spray_window_minutes": (1, 1440),
    "off_hours_start_utc": (0, 23),
    "off_hours_end_utc": (0, 23),
    "malformed_alert_threshold": (1, 10000),
}

PRIVILEGED_USERNAMES = {"admin", "root", "administrator", "svc_backup", "dbadmin"}


@dataclass
class Settings:
    database_url: str | None = None
    admin_api_key: str | None = None
    ip_hash_salt: str = ""
    cors_origins: list[str] = field(default_factory=list)
    is_vercel: bool = False
    environment: str = "development"
    max_upload_bytes: int = 2 * 1024 * 1024
    max_records_per_ingest: int = 5000
    max_stored_events: int = 20000
    max_generate_count: int = 2000
    rate_limit_ingest_per_10min: int = 20
    testing: bool = False

    @classmethod
    def from_env(cls) -> Settings:
        is_vercel = bool(os.environ.get("VERCEL"))
        env = os.environ.get("APP_ENV") or ("production" if is_vercel else "development")
        db_url = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
        origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()]
        return cls(
            database_url=db_url,
            admin_api_key=os.environ.get("ADMIN_API_KEY") or None,
            ip_hash_salt=os.environ.get("IP_HASH_SALT", ""),
            cors_origins=origins,
            is_vercel=is_vercel,
            environment=env,
            max_upload_bytes=_int("MAX_UPLOAD_BYTES", 2 * 1024 * 1024),
            max_records_per_ingest=_int("MAX_RECORDS_PER_INGEST", 5000),
            max_stored_events=_int("MAX_STORED_EVENTS", 20000),
            max_generate_count=_int("MAX_GENERATE_COUNT", 2000),
            rate_limit_ingest_per_10min=_int("RATE_LIMIT_INGEST_PER_10MIN", 20),
        )

    def resolved_database_url(self) -> str | None:
        """Return a SQLAlchemy URL. Falls back to local SQLite only outside production."""
        url = self.database_url
        if url:
            if url.startswith("postgres://"):
                url = "postgresql+psycopg://" + url[len("postgres://"):]
            elif url.startswith("postgresql://"):
                url = "postgresql+psycopg://" + url[len("postgresql://"):]
            return url
        if self.environment == "production":
            return None  # Production must use a managed database.
        here = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(os.path.dirname(here), "instance", "local.db")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        return "sqlite:///" + db_path.replace("\\", "/")
