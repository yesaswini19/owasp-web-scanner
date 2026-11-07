import pytest
from werkzeug.security import generate_password_hash

import app as flask_app


_TEST_PASSWORD_HASH = generate_password_hash(
    "test-admin-password", method="scrypt:32768:8:1", salt_length=16,
)


@pytest.fixture(autouse=True)
def configured_test_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("SECRET_KEY", "test-only-secret-key-with-at-least-32-bytes")
    monkeypatch.setenv("SCANNER_ADMIN_USERNAME", "scanner-admin")
    monkeypatch.setenv("SCANNER_ADMIN_PASSWORD_HASH", _TEST_PASSWORD_HASH)
    monkeypatch.setenv(
        "SCANNER_ALLOWED_TARGETS",
        "https://example.test:443,http://example.test:80,http://dvwa:80",
    )
    monkeypatch.setenv("SCANNER_COOKIE_SECURE", "true")
    monkeypatch.setenv("SCANNER_ENV", "test")
    flask_app.app.config["SECRET_KEY"] = "test-only-secret-key-with-at-least-32-bytes"
    flask_app.app.config["LOGIN_RATE_LIMIT_DB"] = str(tmp_path / "login-attempts.sqlite3")


@pytest.fixture
def client():
    test_client = flask_app.app.test_client()
    test_client.environ_base["wsgi.url_scheme"] = "https"
    return test_client


@pytest.fixture
def authenticated_client(client):
    response = client.get("/login")
    assert response.status_code == 200
    with client.session_transaction() as stored_session:
        csrf_token = stored_session["csrf_token"]
    response = client.post(
        "/login",
        data={
            "username": "scanner-admin",
            "password": "test-admin-password",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 302
    return client
