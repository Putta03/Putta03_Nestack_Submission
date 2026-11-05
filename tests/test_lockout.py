from common import PASSWORD

WRONG = "this is the wrong password"


def fail(client, username="alice", password=WRONG):
    return client.post("/login", json={"username": username, "password": password})


def test_account_locks_after_five_failures(client, register):
    register()
    for _ in range(4):
        assert fail(client).status_code == 401

    fifth = fail(client)
    assert fifth.status_code == 429
    assert int(fifth.headers["retry-after"]) >= 1

    sixth = fail(client)
    assert sixth.status_code == 429


def test_correct_password_is_refused_while_locked(client, register):
    register()
    for _ in range(5):
        fail(client)

    response = client.post(
        "/login", json={"username": "alice", "password": PASSWORD}
    )
    assert response.status_code == 429


def test_lock_expires_and_counters_reset(client, register, login, clock):
    register()
    for _ in range(5):
        fail(client)

    clock["offset"] = 61
    response = login()
    assert response.status_code == 200


def test_successful_login_resets_the_failure_count(client, register, login):
    register()
    for _ in range(3):
        assert fail(client).status_code == 401

    assert login().status_code == 200
    assert fail(client).status_code == 401


def test_lockout_is_per_account_not_per_client(client, register, login):
    register("alice")
    register("bob")
    for _ in range(5):
        fail(client, "alice")

    assert login("bob").status_code == 200


def test_unknown_usernames_are_not_tracked(client):
    for _ in range(10):
        assert fail(client, "nobody").status_code == 401


def test_lockout_is_case_insensitive(client, register):
    register("Alice")
    for _ in range(4):
        assert fail(client, "alice").status_code == 401
    assert fail(client, "alice").status_code == 429
    response = client.post(
        "/login", json={"username": "Alice", "password": PASSWORD}
    )
    assert response.status_code == 429
