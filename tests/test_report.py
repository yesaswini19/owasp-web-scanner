import json

from report import ReportGenerator, build_pdf, build_text_report


def test_report_counts_only_detected_findings_by_severity():
    report = ReportGenerator(
        "https://example.test",
        [
            {
                "name": "Possible issue",
                "owasp": "A05",
                "detected": True,
                "severity": "Medium",
                "details": ["A response indicator was found."],
                "recommendation": "Review configuration.",
            },
            {
                "name": "No issue",
                "detected": False,
                "severity": "None",
                "details": [],
                "recommendation": "No action.",
            },
            {
                "name": "Unavailable check",
                "detected": False,
                "finding_type": "error",
                "severity": "Error",
                "details": ["internal exception text"],
            },
        ],
        {"checks_run": 3, "pages_crawled": 2, "pages": [{"url": "https://example.test"}]},
    ).generate()

    summary = report["summary"]
    assert summary["total_checks"] == 3
    assert summary["vulnerabilities_detected"] == 1
    assert summary["possible_findings"] == 1
    assert summary["confirmed_findings"] == 0
    assert summary["checks_with_errors"] == 1
    assert summary["severity_breakdown"]["Medium"] == 1
    assert "Error" not in summary["severity_breakdown"]
    assert report["results"][0]["affected_url"] == "https://example.test"
    assert report["results"][0]["evidence"][0]["description"] == "A response indicator was found."
    assert "internal exception text" not in json.dumps(report)


def test_empty_report_has_valid_json_and_readable_pdf():
    report = ReportGenerator("https://example.test", [], {}).generate()
    assert json.loads(json.dumps(report))["results"] == []
    assert report["summary"]["total_checks"] == 0
    assert report["scan_performance"]["total_pages_scanned"] == 1

    pdf = build_pdf(report)
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 500
    assert "No checks returned results." in build_text_report(report)


def test_pdf_escapes_dynamic_finding_content():
    report = ReportGenerator(
        "https://example.test",
        [{
            "name": "<script>finding</script>",
            "owasp": "A03",
            "detected": True,
            "severity": "Low",
            "details": ["<b>untrusted evidence</b>"],
            "affected_url": "https://example.test/?q=<tag>",
            "evidence": [{"description": "<img src=x>", "url": "https://example.test/"}],
            "recommendation": "Encode < and > characters.",
        }],
    ).generate()

    pdf = build_pdf(report)
    assert pdf.startswith(b"%PDF")


def test_unsupported_checks_are_not_counted_as_passed():
    report = ReportGenerator(
        "https://example.test",
        [{
            "name": "Authentication Strength (not assessed)",
            "detected": False,
            "finding_type": "unsupported",
            "severity": "None",
            "details": ["No authentication test was performed."],
        }],
    ).generate()

    assert report["summary"]["passed"] == 0
    assert report["summary"]["unsupported_checks"] == 1
    assert report["results"][0]["status"] == "UNSUPPORTED"


def test_report_preserves_not_tested_and_partial_assessment_statuses():
    report = ReportGenerator(
        "http://dvwa:80/",
        [
            {
                "name": "SQL Injection",
                "detected": False,
                "finding_type": "unsupported",
                "status": "NOT TESTED",
                "severity": "None",
                "details": ["POST form was discovered but not submitted."],
                "evidence": [{
                    "type": "form_candidate_not_tested",
                    "description": "POST inputs were not tested.",
                    "page_url": "http://dvwa:80/vulnerabilities/sqli/",
                    "form_action": "http://dvwa:80/vulnerabilities/sqli/",
                    "method": "POST",
                    "field_names": ["id"],
                }],
            },
            {
                "name": "SQL Injection",
                "detected": False,
                "finding_type": "partial",
                "status": "PARTIALLY TESTED",
                "severity": "None",
                "details": ["GET parameters tested; POST fields were not."],
            },
        ],
    ).generate()
    text_report = build_text_report(report)
    pdf = build_pdf(report)

    assert report["results"][0]["status"] == "NOT TESTED"
    assert report["results"][1]["status"] == "PARTIALLY TESTED"
    assert report["summary"]["unsupported_checks"] == 1
    assert report["summary"]["partially_tested_checks"] == 1
    assert "Form action: http://dvwa:80/vulnerabilities/sqli/" in text_report
    assert "Field names: id" in text_report
    assert pdf.startswith(b"%PDF")


def test_report_form_metadata_contains_no_field_values():
    from scanner import _extract_form_metadata
    from bs4 import BeautifulSoup

    html = (
        '<form method="post" action="/login">'
        '<input type="password" name="password" value="password-secret">'
        '<input type="hidden" name="user_token" value="token-secret">'
        '</form>'
    )
    forms = _extract_form_metadata(
        "http://dvwa:80/", BeautifulSoup(html, "html.parser"),
    )

    assert forms[0]["method"] == "POST"
    assert forms[0]["fields"] == [
        {"name": "password", "type": "password", "is_password": True},
        {"name": "user_token", "type": "hidden", "is_password": False},
    ]
    assert "password-secret" not in json.dumps(forms)
    assert "token-secret" not in json.dumps(forms)
    report = ReportGenerator(
        "http://dvwa:80/",
        [],
        {
            "pages_crawled": 1,
            "pages": [{
                "url": "http://dvwa:80/login.php",
                "form_count": 1,
                "forms": forms,
            }],
        },
    ).generate()
    text_report = build_text_report(report)
    pdf = build_pdf(report)

    assert "POST http://dvwa:80/login" in text_report
    assert "password (password field), user_token (hidden)" in text_report
    assert "password-secret" not in text_report
    assert "token-secret" not in text_report
    assert pdf.startswith(b"%PDF")


def test_report_distinguishes_authentication_and_protected_access():
    auth_status = {
        "authentication_mode": "authenticated",
        "authentication_mode_enabled": True,
        "login_session_establishment": "succeeded",
        "protected_access_verified": True,
        "protected_access_url": "http://dvwa:80/index.php",
    }
    report = ReportGenerator(
        "http://dvwa:80/",
        [],
        {"checks_run": 0, "pages_crawled": 0, **auth_status},
    ).generate()

    perf = report["scan_performance"]
    assert perf["authentication_mode_enabled"] is True
    assert perf["login_session_establishment"] == "succeeded"
    assert perf["protected_access_verified"] is True
    assert perf["protected_access_url"] == "http://dvwa:80/index.php"
    text_report = build_text_report(report)
    assert "Login/session establishment: succeeded" in text_report
    assert "Protected access verified: http://dvwa:80/index.php" in text_report
    assert build_pdf(report).startswith(b"%PDF")


def test_dashboard_uses_consistent_partial_sqli_status():
    from pathlib import Path

    template = (Path(__file__).parents[1] / "templates" / "index.html").read_text(
        encoding="utf-8"
    )

    assert "PARTIALLY TESTED — no indicator in tested GET inputs" in template
    assert "scanResultStatus(result)" in template
    assert "scanResultStatus(r)" in template
