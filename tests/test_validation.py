def test_record_requires_both_fields(client, register, login, auth):
    register()
    headers = auth(login().json()["token"])
    assert client.post("/records", json={"title": "Only title"}, headers=headers).status_code == 400
    assert client.post("/records", json={"body": "Only body"}, headers=headers).status_code == 400


def test_wrong_types_are_rejected(client, register, login, auth):
    register()
    headers = auth(login().json()["token"])
    assert client.post("/records", json={"title": 123, "body": "body"}, headers=headers).status_code == 400
    assert client.post("/records", json={"title": "Note", "body": ["body"]}, headers=headers).status_code == 400


def test_oversized_fields_are_rejected(client, register, login, auth):
    register()
    headers = auth(login().json()["token"])
    title = client.post("/records", json={"title": "x" * 201, "body": "body"}, headers=headers)
    body = client.post("/records", json={"title": "Note", "body": "x" * 16_385}, headers=headers)
    assert title.status_code == 400
    assert body.status_code == 400


def test_empty_and_blank_values_are_rejected(client, register, login, auth):
    register()
    headers = auth(login().json()["token"])
    assert client.post("/records", json={"title": "   ", "body": "body"}, headers=headers).status_code == 400
    assert client.post("/records", json={"title": "Note", "body": "   "}, headers=headers).status_code == 400


def test_nul_bytes_are_rejected(client, register, login, auth):
    register()
    headers = auth(login().json()["token"])
    response = client.post("/records", json={"title": "Note", "body": "a\x00b"}, headers=headers)
    assert response.status_code == 400


def test_malformed_json_returns_400(client):
    response = client.post(
        "/register",
        content=b'{"username": "alice", "password":',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_input"


def test_oversized_http_body_returns_400(client):
    response = client.post(
        "/register",
        content=b"x" * 70_000,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "payload_too_large"


def test_non_integer_record_id_returns_400(client, register, login, auth):
    register()
    headers = auth(login().json()["token"])
    response = client.get("/records/not-an-integer", headers=headers)
    assert response.status_code == 400


def test_extra_fields_are_rejected(client, register, login, auth):
    register()
    headers = auth(login().json()["token"])
    response = client.post(
        "/records",
        json={"title": "Note", "body": "body", "unexpected": "field"},
        headers=headers,
    )
    assert response.status_code == 400


def test_error_responses_do_not_leak_internals(client):
    response = client.post("/register", json={"username": "a", "password": "b"})
    assert response.status_code == 400
    assert "Traceback" not in response.text
    assert "sqlite" not in response.text.lower()


def test_chunked_oversized_body_returns_400(client):
    def body():
        yield b"x" * 40_000
        yield b"x" * 40_000

    response = client.post(
        "/register",
        content=body(),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "payload_too_large"
