import json

import app as flask_app


def _report():
    return {
        "meta": {
            "tool": "OWASP Top 10 Security Scanner",
            "version": "2.0.0",
            "target": "https://example.test",
            "generated_at": "2026-01-01T00:00:00Z",
            "disclaimer": "Authorized testing only.",
            "coverage": {"supported_categories": {}, "unsupported_categories": {}},
            "limitations": [],
        },
        "summary": {
            "total_checks": 0,
            "vulnerabilities_detected": 0,
            "possible_findings": 0,
            "confirmed_findings": 0,
            "checks_with_errors": 0,
            "passed": 0,
            "overall_risk": "LOW",
            "severity_breakdown": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0},
            "detected_names": [],
        },
        "scan_performance": {
            "duration_seconds": 0,
            "pages_crawled": 1,
            "total_pages_scanned": 1,
            "checks_run": 0,
            "total_checks_performed": 0,
            "threads_used": 1,
            "pages": [],
        },
        "results": [],
    }


def _csrf_token(client):
    with client.session_transaction() as stored_session:
        return stored_session["csrf_token"]


def _post_json(client, path, payload, csrf=True):
    headers = {"X-CSRF-Token": _csrf_token(client)} if csrf else {}
    return client.post(path, json=payload, headers=headers)


def test_health_and_login_are_public_but_dashboard_requires_login(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"

    dashboard = client.get("/")
    assert dashboard.status_code == 302
    assert dashboard.headers["Location"].endswith("/login")
    assert client.get("/login").status_code == 200


def test_all_scan_and_export_routes_reject_unauthenticated_requests(client):
    assert client.post("/scan", json={}).status_code == 401
    assert client.post("/export/json", json={}).status_code == 401
    assert client.post("/export/pdf", json={}).status_code == 401
    assert client.post("/export", json={}).status_code == 401


def test_missing_authentication_configuration_fails_closed(client, monkeypatch):
    monkeypatch.delenv("SECRET_KEY")
    assert client.get("/health").status_code == 503
    assert client.get("/login").status_code == 503
    assert client.post("/scan", json={}).status_code == 503


def test_insecure_cookie_mode_is_development_only(client, monkeypatch):
    monkeypatch.setenv("SCANNER_COOKIE_SECURE", "false")
    assert client.get("/health").status_code == 503

    monkeypatch.setenv("SCANNER_ENV", "development")
    assert client.get("/health").status_code == 200


def test_successful_login_sets_secure_session_and_invalid_login_fails(client):
    login_page = client.get("/login")
    token = _csrf_token(client)
    assert b'name="csrf_token"' in login_page.data

    invalid = client.post(
        "/login",
        data={"username": "scanner-admin", "password": "wrong", "csrf_token": token},
    )
    assert invalid.status_code == 401
    assert b"Invalid username or password" in invalid.data

    token = _csrf_token(client)
    response = client.post(
        "/login",
        data={
            "username": "scanner-admin",
            "password": "test-admin-password",
            "csrf_token": token,
        },
    )
    assert response.status_code == 302
    cookie = response.headers["Set-Cookie"]
    assert "Secure" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
    assert client.get("/").status_code == 200


def test_logout_invalidates_session_and_requires_csrf(authenticated_client):
    missing_token = authenticated_client.post("/logout")
    assert missing_token.status_code == 400
    assert authenticated_client.get("/").status_code == 200

    response = authenticated_client.post(
        "/logout", data={"csrf_token": _csrf_token(authenticated_client)},
    )
    assert response.status_code == 302
    assert authenticated_client.get("/").status_code == 302


def test_csrf_protects_login_scan_and_report_posts(client, authenticated_client):
    assert client.post(
        "/login", data={"username": "scanner-admin", "password": "wrong"},
    ).status_code == 400
    assert _post_json(authenticated_client, "/scan", {"url": "https://example.test"}, csrf=False).status_code == 400
    assert _post_json(authenticated_client, "/export/json", {"report": _report()}, csrf=False).status_code == 400
    assert _post_json(authenticated_client, "/export/pdf", {"report": _report()}, csrf=False).status_code == 400


def test_login_rate_limit_throttles_repeated_failures(client):
    client.get("/login")
    for _ in range(5):
        response = client.post(
            "/login",
            data={
                "username": "scanner-admin",
                "password": "incorrect",
                "csrf_token": _csrf_token(client),
            },
        )
        assert response.status_code == 401

    limited = client.post(
        "/login",
        data={
            "username": "scanner-admin",
            "password": "incorrect",
            "csrf_token": _csrf_token(client),
        },
    )
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) > 0


def test_scan_rejects_malformed_and_non_boolean_options(authenticated_client):
    assert _post_json(authenticated_client, "/scan", []).status_code == 400
    response = _post_json(
        authenticated_client, "/scan",
        {"url": "https://example.test", "crawl": "false"},
    )
    assert response.status_code == 400
    assert "crawl" in response.get_json()["error"]


def test_missing_target_allowlist_disables_scan(authenticated_client, monkeypatch):
    monkeypatch.setenv("SCANNER_ALLOWED_TARGETS", "")
    response = _post_json(
        authenticated_client, "/scan", {"url": "https://example.test:443"},
    )
    assert response.status_code == 400
    assert "Scanning is disabled" in response.get_json()["error"]


def test_authenticated_scan_requires_opt_in_lab_scope_and_credentials(
    authenticated_client, monkeypatch,
):
    monkeypatch.setattr(flask_app, "_validate_url", lambda value: value)
    monkeypatch.setattr(
        flask_app, "validate_local_lab_auth_target",
        lambda value: (_ for _ in ()).throw(flask_app.URLValidationError("lab only")),
    )

    outside_scope = _post_json(authenticated_client, "/scan", {
        "url": "https://example.test", "authenticated": True,
        "username": "user", "password": "secret",
    })
    credentials_without_opt_in = _post_json(authenticated_client, "/scan", {
        "url": "https://example.test", "username": "user", "password": "secret",
    })
    missing_password = _post_json(authenticated_client, "/scan", {
        "url": "https://example.test", "authenticated": True, "username": "user",
    })

    assert outside_scope.status_code == 400
    assert credentials_without_opt_in.status_code == 400
    assert missing_password.status_code == 400
    assert "secret" not in outside_scope.get_data(as_text=True)
    assert "secret" not in credentials_without_opt_in.get_data(as_text=True)


def test_authenticated_scan_does_not_log_or_report_credentials(
    authenticated_client, monkeypatch, caplog,
):
    monkeypatch.setattr(flask_app, "_validate_url", lambda value: value)
    monkeypatch.setattr(flask_app, "validate_local_lab_auth_target", lambda _value: None)
    caplog.set_level("INFO")
    received = {}

    def run_scan(url, crawl, credentials):
        received.update(credentials)
        return _report(), object()

    monkeypatch.setattr(flask_app, "_run_scan", run_scan)
    response = _post_json(authenticated_client, "/scan", {
        "url": "http://dvwa:80", "crawl": True, "authenticated": True,
        "username": "demo-user", "password": "secret-password",
    })

    assert response.status_code == 200
    assert received == {"username": "demo-user", "password": "secret-password"}
    assert "secret-password" not in caplog.text
    assert "secret-password" not in response.get_data(as_text=True)


def test_scan_returns_report_and_limits_concurrent_scans(authenticated_client, monkeypatch):
    monkeypatch.setattr(flask_app, "_validate_url", lambda value: value)
    monkeypatch.setattr(flask_app, "_run_scan", lambda url, crawl: (_report(), object()))

    response = _post_json(
        authenticated_client, "/scan",
        {"url": "https://example.test", "crawl": False},
    )
    assert response.status_code == 200
    assert response.get_json()["results"] == []

    class FullSlots:
        def acquire(self, blocking=False):
            return False

        def release(self):
            raise AssertionError("an unacquired slot must not be released")

    monkeypatch.setattr(flask_app, "_scan_slots", FullSlots())
    response = _post_json(authenticated_client, "/scan", {"url": "https://example.test"})
    assert response.status_code == 429
    assert "busy" in response.get_json()["error"]


def test_scan_hides_unexpected_exception_details(authenticated_client, monkeypatch, caplog):
    monkeypatch.setattr(flask_app, "_validate_url", lambda value: value)
    caplog.set_level("ERROR", logger="app")

    def fail_scan(_url, _crawl):
        raise RuntimeError("sensitive internal details")

    monkeypatch.setattr(flask_app, "_run_scan", fail_scan)
    response = _post_json(
        authenticated_client, "/scan", {"url": "https://example.test"},
    )
    assert response.status_code == 500
    assert "sensitive internal details" not in response.get_data(as_text=True)
    assert "sensitive internal details" not in caplog.text


def test_json_export_uses_report_payload_without_rescanning(authenticated_client, monkeypatch):
    monkeypatch.setattr(
        flask_app, "_run_scan",
        lambda *_args: (_ for _ in ()).throw(AssertionError("unexpected rescan")),
    )

    response = _post_json(
        authenticated_client, "/export/json", {"report": _report()},
    )
    assert response.status_code == 200
    assert response.mimetype == "application/json"
    assert json.loads(response.get_data(as_text=True))["results"] == []


def test_export_rejects_invalid_report_shape(authenticated_client):
    response = _post_json(
        authenticated_client, "/export/json", {"report": {"results": []}},
    )
    assert response.status_code == 400
    assert "missing required" in response.get_json()["error"]


def test_json_export_rejects_non_finite_numbers(authenticated_client):
    report = _report()
    report["summary"]["risk_score"] = float("nan")

    response = _post_json(authenticated_client, "/export/json", {"report": report})

    assert response.status_code == 400
    assert "NaN" in response.get_json()["error"]


def test_pdf_export_supports_empty_results(authenticated_client):
    response = _post_json(
        authenticated_client, "/export/pdf", {"report": _report()},
    )
    assert response.status_code == 200
    assert response.mimetype == "application/pdf"
    assert response.data.startswith(b"%PDF")
