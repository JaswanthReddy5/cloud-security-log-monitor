import pytest

from app import create_app
from app.config import Settings


@pytest.fixture
def make_app(tmp_path):
    def _make(admin_key: str | None = "test-admin-key", database_url: str | None = None, **overrides):
        settings = Settings(admin_api_key=admin_key, environment="test", **overrides)
        url = database_url if database_url is not None else f"sqlite:///{(tmp_path / 'test.db').as_posix()}"
        app = create_app(settings, database_url=url, testing=True)
        app.config["TESTING_DISABLE_RATE_LIMIT"] = True
        return app

    return _make


@pytest.fixture
def app(make_app):
    return make_app()


@pytest.fixture
def client(app):
    return app.test_client()


ADMIN = {"X-Admin-Key": "test-admin-key"}
