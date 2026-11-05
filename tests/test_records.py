def create_record(client, headers, title="Private note", body="only alice can read this"):
    return client.post(
        "/records",
        json={"title": title, "body": body},
        headers=headers,
    )


def test_owner_can_read_their_record(client, register, login, auth):
    register()
    headers = auth(login().json()["token"])
    created = create_record(client, headers)
    assert created.status_code == 201

    response = client.get(f"/records/{created.json()['id']}", headers=headers)
    assert response.status_code == 200
    assert response.json()["title"] == "Private note"
    assert response.json()["body"] == "only alice can read this"


def test_another_user_gets_404_and_no_record_data(client, register, login, auth):
    register("alice")
    register("bob")
    alice = auth(login("alice").json()["token"])
    bob = auth(login("bob").json()["token"])
    created = create_record(client, alice)

    response = client.get(f"/records/{created.json()['id']}", headers=bob)
    assert response.status_code == 404
    assert "only alice can read this" not in response.text


def test_admin_can_read_any_record(client, register, login, auth, promote):
    register("alice")
    register("bob")
    alice = auth(login("alice").json()["token"])
    created = create_record(client, alice)

    promote("bob")
    bob = auth(login("bob").json()["token"])
    response = client.get(f"/records/{created.json()['id']}", headers=bob)
    assert response.status_code == 200
    assert response.json()["body"] == "only alice can read this"


def test_admin_does_not_need_ownership_but_still_needs_a_record(client, register, login, auth, promote):
    register("alice")
    register("bob")
    promote("bob")
    bob = auth(login("bob").json()["token"])
    response = client.get("/records/9999", headers=bob)
    assert response.status_code == 404


def test_missing_record_returns_404(client, register, login, auth):
    register()
    headers = auth(login().json()["token"])
    response = client.get("/records/123456", headers=headers)
    assert response.status_code == 404


def test_owner_id_cannot_be_spoofed_in_the_body(client, register, login, auth):
    register()
    headers = auth(login().json()["token"])
    response = client.post(
        "/records",
        json={"title": "Note", "body": "body", "owner_id": 1},
        headers=headers,
    )
    assert response.status_code == 400


def test_sql_injection_in_the_path_is_rejected(client, register, login, auth):
    register()
    headers = auth(login().json()["token"])
    response = client.get("/records/1%20OR%201%3D1", headers=headers)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_input"


def test_unauthenticated_user_cannot_read_a_record(client, register, login):
    register()
    token = login().json()["token"]
    created = create_record(client, {"Authorization": f"Bearer {token}"})
    response = client.get(f"/records/{created.json()['id']}")
    assert response.status_code == 401
