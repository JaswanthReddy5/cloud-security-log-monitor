"""Flask application factory."""
from __future__ import annotations

import logging

from flask import Flask, jsonify

from .config import Settings
from .db import Database
from .errors import error_body, register_error_handlers
from .routes import api
from .security import install_security_headers


def create_app(settings: Settings | None = None, *, database_url: str | None = None, testing: bool = False) -> Flask:
    settings = settings or Settings.from_env()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    app = Flask(__name__)
    app.config["SETTINGS"] = settings
    app.config["TESTING"] = testing
    # Hard cap on request bodies (multipart overhead included).
    app.config["MAX_CONTENT_LENGTH"] = settings.max_upload_bytes + 64 * 1024
    url = database_url if database_url is not None else settings.resolved_database_url()
    app.config["DB"] = Database(url)

    install_security_headers(app)
    register_error_handlers(app)
    app.register_blueprint(api)

    @app.get("/")
    def root():
        return jsonify({"ok": True, "data": {"service": "cloud-security-log-monitor API", "docs": "/api/health"}})

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify(error_body("not_found", "Resource not found.")), 404

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return jsonify(error_body("method_not_allowed", "Method not allowed for this endpoint.")), 405

    return app
