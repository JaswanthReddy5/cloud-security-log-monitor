"""Database engine/session management.

The engine is created lazily so the app can start (and report a clear error)
even when the database is misconfigured or unreachable.
"""
from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from .errors import DatabaseUnavailable
from .models import Base


class Database:
    def __init__(self, url: str | None):
        self.url = url
        self._engine: Engine | None = None
        self._sessionmaker: sessionmaker | None = None
        self._schema_ready = False
        self._lock = threading.Lock()

    @property
    def configured(self) -> bool:
        return bool(self.url)

    @property
    def dialect(self) -> str | None:
        if not self.url:
            return None
        return self.url.split(":", 1)[0].split("+", 1)[0]

    def engine(self) -> Engine:
        if not self.url:
            raise DatabaseUnavailable("Database is not configured. Set DATABASE_URL.")
        if self._engine is None:
            with self._lock:
                if self._engine is None:
                    kwargs: dict = {"future": True}
                    if self.url.startswith("sqlite"):
                        kwargs["connect_args"] = {"check_same_thread": False}
                    else:
                        # Serverless functions: don't hold idle connections;
                        # Neon's pooled endpoint handles connection reuse.
                        kwargs["poolclass"] = NullPool
                        kwargs["connect_args"] = {"connect_timeout": 10}
                    self._engine = create_engine(self.url, **kwargs)
                    self._sessionmaker = sessionmaker(bind=self._engine, expire_on_commit=False)
        return self._engine

    def ensure_schema(self) -> None:
        """Create tables if missing (idempotent schema initialization)."""
        if self._schema_ready:
            return
        try:
            Base.metadata.create_all(self.engine())
            self._schema_ready = True
        except SQLAlchemyError as exc:
            raise DatabaseUnavailable("Could not initialize database schema.") from exc

    @contextmanager
    def session(self) -> Iterator[Session]:
        self.ensure_schema()
        assert self._sessionmaker is not None
        sess: Session = self._sessionmaker()
        try:
            yield sess
            sess.commit()
        except SQLAlchemyError as exc:
            sess.rollback()
            raise DatabaseUnavailable("A database error occurred.") from exc
        except Exception:
            sess.rollback()
            raise
        finally:
            sess.close()

    def ping(self) -> bool:
        try:
            with self.engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except (SQLAlchemyError, DatabaseUnavailable):
            return False
