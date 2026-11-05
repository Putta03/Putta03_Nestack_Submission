import re

from fastapi.testclient import TestClient


def test_security_headers_are_present(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert re.fullmatch(r"[0-9a-f]{32}", response.headers["x-request-id"])


def test_client_request_id_is_echoed_when_valid(client):
    response = client.get("/healthz", headers={"X-Request-ID": "abcdef1234567890"})
    assert response.headers["x-request-id"] == "abcdef1234567890"


def test_invalid_client_request_id_is_replaced(client):
    response = client.get("/healthz", headers={"X-Request-ID": "bad id!"})
    assert response.headers["x-request-id"] != "bad id!"
    assert re.fullmatch(r"[0-9a-f]{32}", response.headers["x-request-id"])


def test_unknown_route_returns_json_404(client):
    response = client.get("/does-not-exist")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_wrong_method_returns_json_405(client):
    response = client.get("/register")
    assert response.status_code == 405
    assert response.json()["error"]["code"] == "method_not_allowed"


def test_docs_are_disabled_in_the_test_configuration(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_internal_errors_are_generic(application):
    @application.get("/boom")
    def boom():
        raise RuntimeError("database password is hunter2")

    with TestClient(application, raise_server_exceptions=False) as test_client:
        response = test_client.get("/boom")

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    assert "hunter2" not in response.text
    assert "Traceback" not in response.text
