"""Access control, client identification, rate limiting and security headers."""
from __future__ import annotations

import hashlib
import hmac
import threading
import time
from collections import defaultdict, deque
from functools import wraps

from flask import Flask, current_app, g, request

from .errors import ApiError


def client_ip() -> str:
    # On Vercel the real client address is in x-forwarded-for (set by the platform edge).
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd and current_app.config["SETTINGS"].is_vercel:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "unknown"


def client_hash() -> str:
    """Privacy-preserving client identifier (we never store raw visitor IPs)."""
    salt = current_app.config["SETTINGS"].ip_hash_salt
    return hashlib.sha256(f"{salt}:{client_ip()}".encode()).hexdigest()


def require_admin(fn):
    """Protect destructive/administrative endpoints with an admin API key.

    The key is read from the ADMIN_API_KEY environment variable and compared in
    constant time. If no key is configured, admin endpoints are disabled.
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        expected = current_app.config["SETTINGS"].admin_api_key
        if not expected:
            raise ApiError("Administrative actions are disabled: ADMIN_API_KEY is not configured.",
                           status_code=403, code="admin_disabled")
        supplied = request.headers.get("X-Admin-Key", "")
        if not supplied or not hmac.compare_digest(supplied.encode(), expected.encode()):
            raise ApiError("A valid admin key is required for this action.", status_code=401, code="unauthorized")
        return fn(*args, **kwargs)

    return wrapper


class MemoryRateLimiter:
    """Sliding-window limiter. Per server instance; complemented by a DB-backed
    limit on ingestion so it also holds across serverless instances."""

    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_s: int) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window_s:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            if len(self._hits) > 10000:  # bound memory
                self._hits.clear()
            return True


limiter = MemoryRateLimiter()


def rate_limit(name: str, limit: int, window_s: int):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_app.config.get("TESTING_DISABLE_RATE_LIMIT"):
                if not limiter.check(f"{name}:{client_hash()}", limit, window_s):
                    raise ApiError("Too many requests. Please slow down.", status_code=429, code="rate_limited")
            return fn(*args, **kwargs)

        return wrapper

    return deco


def install_security_headers(app: Flask) -> None:
    @app.before_request
    def _start_timer():
        g.start = time.perf_counter()

    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        resp.headers.setdefault("Cache-Control", "no-store")
        if request.path.startswith("/api/") and hasattr(g, "start"):
            resp.headers["Server-Timing"] = f"app;dur={(time.perf_counter() - g.start) * 1000:.1f}"
        origins = app.config["SETTINGS"].cors_origins
        origin = request.headers.get("Origin")
        if origin and origin in origins:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Vary"] = "Origin"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Admin-Key"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, PUT, OPTIONS"
        return resp
