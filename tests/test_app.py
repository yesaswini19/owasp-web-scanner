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


def test_health_and_dashboard_routes():
    client = flask_app.app.test_client()

    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"
    assert client.get("/").status_code == 200


def test_scan_rejects_malformed_and_non_boolean_options():
    client = flask_app.app.test_client()

    assert client.post("/scan", json=[]).status_code == 400
    response = client.post("/scan", json={"url": "https://example.test", "crawl": "false"})
    assert response.status_code == 400
    assert "crawl" in response.get_json()["error"]


def test_authenticated_scan_requires_opt_in_lab_scope_and_credentials(monkeypatch):
    client = flask_app.app.test_client()
    monkeypatch.setattr(flask_app, "_validate_url", lambda value: value)
    monkeypatch.setattr(
        flask_app, "validate_local_lab_auth_target",
        lambda value: (_ for _ in ()).throw(flask_app.URLValidationError("lab only")),
    )

    outside_scope = client.post("/scan", json={
        "url": "https://example.test", "authenticated": True,
        "username": "user", "password": "secret",
    })
    credentials_without_opt_in = client.post("/scan", json={
        "url": "https://example.test", "username": "user", "password": "secret",
    })
    missing_password = client.post("/scan", json={
        "url": "https://example.test", "authenticated": True, "username": "user",
    })

    assert outside_scope.status_code == 400
    assert credentials_without_opt_in.status_code == 400
    assert missing_password.status_code == 400
    assert "secret" not in outside_scope.get_data(as_text=True)
    assert "secret" not in credentials_without_opt_in.get_data(as_text=True)


def test_authenticated_scan_does_not_log_or_report_credentials(monkeypatch, caplog):
    client = flask_app.app.test_client()
    monkeypatch.setattr(flask_app, "_validate_url", lambda value: value)
    monkeypatch.setattr(flask_app, "validate_local_lab_auth_target", lambda _value: None)
    caplog.set_level("INFO")
    received = {}

    def run_scan(url, crawl, credentials):
        received.update(credentials)
        return _report(), object()

    monkeypatch.setattr(flask_app, "_run_scan", run_scan)
    response = client.post("/scan", json={
        "url": "http://dvwa:80", "crawl": True, "authenticated": True,
        "username": "demo-user", "password": "secret-password",
    })

    assert response.status_code == 200
    assert received == {"username": "demo-user", "password": "secret-password"}
    assert "secret-password" not in caplog.text
    assert "secret-password" not in response.get_data(as_text=True)


def test_scan_returns_report_and_limits_concurrent_scans(monkeypatch):
    client = flask_app.app.test_client()
    monkeypatch.setattr(flask_app, "_validate_url", lambda value: value)
    monkeypatch.setattr(flask_app, "_run_scan", lambda url, crawl: (_report(), object()))

    response = client.post("/scan", json={"url": "https://example.test", "crawl": False})
    assert response.status_code == 200
    assert response.get_json()["results"] == []

    class FullSlots:
        def acquire(self, blocking=False):
            return False

        def release(self):
            raise AssertionError("an unacquired slot must not be released")

    monkeypatch.setattr(flask_app, "_scan_slots", FullSlots())
    response = client.post("/scan", json={"url": "https://example.test"})
    assert response.status_code == 429
    assert "busy" in response.get_json()["error"]


def test_scan_hides_unexpected_exception_details(monkeypatch, caplog):
    client = flask_app.app.test_client()
    monkeypatch.setattr(flask_app, "_validate_url", lambda value: value)
    caplog.set_level("ERROR", logger="app")

    def fail_scan(_url, _crawl):
        raise RuntimeError("sensitive internal details")

    monkeypatch.setattr(flask_app, "_run_scan", fail_scan)
    response = client.post("/scan", json={"url": "https://example.test"})
    assert response.status_code == 500
    assert "sensitive internal details" not in response.get_data(as_text=True)
    assert "sensitive internal details" not in caplog.text


def test_json_export_uses_report_payload_without_rescanning(monkeypatch):
    client = flask_app.app.test_client()
    monkeypatch.setattr(
        flask_app, "_run_scan",
        lambda *_args: (_ for _ in ()).throw(AssertionError("unexpected rescan")),
    )

    response = client.post("/export/json", json={"report": _report()})
    assert response.status_code == 200
    assert response.mimetype == "application/json"
    assert json.loads(response.get_data(as_text=True))["results"] == []


def test_export_rejects_invalid_report_shape():
    response = flask_app.app.test_client().post("/export/json", json={"report": {"results": []}})
    assert response.status_code == 400
    assert "missing required" in response.get_json()["error"]


def test_json_export_rejects_non_finite_numbers():
    report = _report()
    report["summary"]["risk_score"] = float("nan")

    response = flask_app.app.test_client().post("/export/json", json={"report": report})

    assert response.status_code == 400
    assert "NaN" in response.get_json()["error"]


def test_pdf_export_supports_empty_results():
    response = flask_app.app.test_client().post("/export/pdf", json={"report": _report()})
    assert response.status_code == 200
    assert response.mimetype == "application/pdf"
    assert response.data.startswith(b"%PDF")
