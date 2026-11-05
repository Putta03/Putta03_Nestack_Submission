import hashlib

from app import repositories
from common import PASSWORD, db_bytes


def test_register_creates_a_normal_user(client):
    response = client.post("/register", json={"username": "alice", "password": PASSWORD})
    assert response.status_code == 201
    body = response.json()
    assert body["username"] == "alice"
    assert body["role"] == "user"
    assert "password" not in body
    assert "password_hash" not in response.text


def test_register_rejects_a_client_supplied_role(client):
    response = client.post(
        "/register",
        json={"username": "alice", "password": PASSWORD, "role": "admin"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "role_assignment_forbidden"


def test_register_rejects_unknown_privilege_fields(client):
    response = client.post(
        "/register",
        json={"username": "alice", "password": PASSWORD, "is_admin": True},
    )
    assert response.status_code == 400


def test_duplicate_username_is_case_insensitive(client):
    first = client.post("/register", json={"username": "Alice", "password": PASSWORD})
    second = client.post("/register", json={"username": "alice", "password": PASSWORD})
    assert first.status_code == 201
    assert second.status_code == 409


def test_register_rejects_a_short_password(client):
    response = client.post("/register", json={"username": "alice", "password": "short"})
    assert response.status_code == 400


def test_register_rejects_an_invalid_username(client):
    response = client.post("/register", json={"username": "al ice", "password": PASSWORD})
    assert response.status_code == 400


def test_login_returns_an_opaque_bearer_token(client, register, login):
    register()
    response = login()
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "Bearer"
    assert len(body["token"]) == 43
    assert body["expires_in"] == 3600
    assert body["expires_at"].endswith("Z")


def test_wrong_password_and_unknown_user_are_indistinguishable(client, register):
    register()
    wrong = client.post("/login", json={"username": "alice", "password": "wrong password"})
    unknown = client.post("/login", json={"username": "nobody", "password": "wrong password"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_passwords_are_salted_and_not_recoverable_from_the_database(
    client, db_conn, settings
):
    client.post("/register", json={"username": "alice", "password": PASSWORD})
    client.post("/register", json={"username": "bob", "password": PASSWORD})

    alice = repositories.get_user_by_username(db_conn, "alice")
    bob = repositories.get_user_by_username(db_conn, "bob")

    assert alice["password_hash"].startswith("scrypt$")
    assert alice["password_hash"] != bob["password_hash"]
    assert PASSWORD not in alice["password_hash"]
    assert PASSWORD.encode() not in db_bytes(settings.db_path)


def test_session_tokens_are_hashed_at_rest(client, register, login, db_conn):
    register()
    token = login().json()["token"]
    row = db_conn.execute("SELECT token_hash FROM sessions").fetchone()
    assert row["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
    assert token != row["token_hash"]
