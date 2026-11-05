from app import repositories


def test_records_require_authentication(client):
    response = client.post("/records", json={"title": "Note", "body": "body"})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_malformed_authorization_headers_are_rejected(client):
    for header in ("token", "Basic abc", "Bearer", "Bearer   "):
        response = client.post(
            "/records",
            json={"title": "Note", "body": "body"},
            headers={"Authorization": header},
        )
        assert response.status_code == 401, header


def test_invalid_token_is_rejected(client):
    response = client.post(
        "/records",
        json={"title": "Note", "body": "body"},
        headers={"Authorization": "Bearer " + "A" * 43},
    )
    assert response.status_code == 401


def test_valid_token_allows_record_creation(client, register, login, auth):
    register()
    token = login().json()["token"]
    response = client.post(
        "/records",
        json={"title": "Note", "body": "body"},
        headers=auth(token),
    )
    assert response.status_code == 201


def test_expired_token_is_rejected(client, register, login, auth, clock):
    register()
    token = login().json()["token"]
    clock["offset"] = 3601
    response = client.post(
        "/records",
        json={"title": "Note", "body": "body"},
        headers=auth(token),
    )
    assert response.status_code == 401


def test_logout_revokes_the_session(client, register, login, auth):
    register()
    token = login().json()["token"]
    headers = auth(token)
    assert client.post("/logout", headers=headers).status_code == 204
    assert client.post("/records", json={"title": "N", "body": "B"}, headers=headers).status_code == 401
    assert client.post("/logout", headers=headers).status_code == 401


def test_record_owner_comes_from_the_session(client, register, login, auth, db_conn):
    register("alice")
    register("bob")
    alice = login("alice").json()["token"]
    bob = login("bob").json()["token"]

    first = client.post(
        "/records", json={"title": "A", "body": "A"}, headers=auth(alice)
    )
    second = client.post(
        "/records", json={"title": "B", "body": "B"}, headers=auth(bob)
    )
    assert first.status_code == second.status_code == 201

    alice_row = repositories.get_user_by_username(db_conn, "alice")
    bob_row = repositories.get_user_by_username(db_conn, "bob")
    owner_a = db_conn.execute(
        "SELECT owner_id FROM records WHERE id = ?", (first.json()["id"],)
    ).fetchone()["owner_id"]
    owner_b = db_conn.execute(
        "SELECT owner_id FROM records WHERE id = ?", (second.json()["id"],)
    ).fetchone()["owner_id"]
    assert owner_a == alice_row["id"]
    assert owner_b == bob_row["id"]
