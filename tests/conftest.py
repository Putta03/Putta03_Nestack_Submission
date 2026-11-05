import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS_DIR))
sys.path.insert(0, str(TESTS_DIR.parent))

import pytest
from fastapi.testclient import TestClient

from app import db, repositories
from app.config import Settings
from app.main import create_app
from common import PASSWORD


@pytest.fixture
def settings(tmp_path):
    return Settings(
        db_path=str(tmp_path / "test.db"),
        session_ttl=3600,
        lockout_threshold=5,
        lockout_seconds=60,
        max_body_bytes=64 * 1024,
        scrypt_n=2**14,
        enable_docs=False,
    )


@pytest.fixture
def application(settings):
    return create_app(settings)


@pytest.fixture
def client(application):
    with TestClient(application) as test_client:
        yield test_client


@pytest.fixture
def register(client):
    def _register(username="alice", password=PASSWORD):
        return client.post(
            "/register",
            json={"username": username, "password": password},
        )

    return _register


@pytest.fixture
def login(client):
    def _login(username="alice", password=PASSWORD):
        return client.post(
            "/login",
            json={"username": username, "password": password},
        )

    return _login


@pytest.fixture
def auth():
    def _auth(token):
        return {"Authorization": f"Bearer {token}"}

    return _auth


@pytest.fixture
def db_conn(settings):
    conn = db.connect(settings.db_path)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def promote(settings):
    def _promote(username, role="admin"):
        conn = db.connect(settings.db_path)
        try:
            user = repositories.get_user_by_username(conn, username)
            assert user is not None, f"no such user: {username}"
            repositories.set_role(conn, user["id"], role)
        finally:
            conn.close()

    return _promote


@pytest.fixture
def clock(application):
    real_clock = application.state.clock
    state = {"offset": 0.0}
    application.state.clock = lambda: real_clock() + state["offset"]
    return state
