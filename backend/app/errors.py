"""Consistent JSON error handling."""
from __future__ import annotations

import logging

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

log = logging.getLogger("seclog")


class ApiError(Exception):
    status_code = 400
    code = "bad_request"

    def __init__(self, message: str, *, status_code: int | None = None, code: str | None = None, details=None):
        super().__init__(message)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        if code is not None:
            self.code = code
        self.details = details


class ValidationFailed(ApiError):
    status_code = 422
    code = "validation_failed"


class DatabaseUnavailable(ApiError):
    status_code = 503
    code = "database_unavailable"


def error_body(code: str, message: str, details=None) -> dict:
    body = {"ok": False, "error": {"code": code, "message": message}}
    if details is not None:
        body["error"]["details"] = details
    return body


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(ApiError)
    def _api_error(err: ApiError):
        if isinstance(err, DatabaseUnavailable):
            log.error("database error: %s (cause: %r)", err.message, err.__cause__)
        return jsonify(error_body(err.code, err.message, err.details)), err.status_code

    @app.errorhandler(HTTPException)
    def _http_error(err: HTTPException):
        code = (err.name or "error").lower().replace(" ", "_")
        message = err.description or err.name
        if err.code == 413:
            message = "Uploaded payload is too large."
        return jsonify(error_body(code, message)), err.code

    @app.errorhandler(Exception)
    def _unhandled(err: Exception):
        log.exception("unhandled error")
        return jsonify(error_body("internal_error", "An unexpected error occurred.")), 500
