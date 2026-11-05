import socket
import threading
import time

import pytest
import requests

import scanner

LAB_TEST_IP = "192.0.2.10"
LAB_REBOUND_IP = "192.0.2.11"


def _address_record(address, port):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]


def test_url_validation_rejects_unsafe_schemes_and_local_destinations():
    for url in (
        "file:///etc/passwd",
        "http://localhost/",
        "http://127.0.0.1/",
        "http://user:pass@example.test/",
        "http://example.test:invalid/",
    ):
        with pytest.raises(scanner.URLValidationError):
            scanner._validate_url(url)


def test_url_validation_rejects_dns_private_and_reserved_addresses(monkeypatch):
    monkeypatch.setattr(
        scanner.socket, "getaddrinfo",
        lambda host, port, type: _address_record("192.0.2.4", port),
    )
    with pytest.raises(scanner.URLValidationError, match="private"):
        scanner._validate_url("https://example.test/")


def test_local_lab_mode_allows_only_configured_host_port_and_pinned_ip(monkeypatch):
    monkeypatch.setenv("SCANNER_LOCAL_LAB_URL", "http://dvwa:80")
    monkeypatch.setenv("SCANNER_LOCAL_LAB_IP", LAB_TEST_IP)
    monkeypatch.setattr(
        scanner.socket, "getaddrinfo",
        lambda host, port, type: _address_record(LAB_TEST_IP, port),
    )

    assert scanner._validate_url("http://dvwa:80/") == "http://dvwa:80/"
    for url in (
        "http://dvwa:81/",
        "https://dvwa:80/",
        f"http://{LAB_TEST_IP}/",
        "http://other:80/",
    ):
        with pytest.raises(scanner.URLValidationError):
            scanner._validate_url(url)


def test_local_lab_mode_rejects_dns_rebinding_and_nonmatching_addresses(monkeypatch):
    monkeypatch.setenv("SCANNER_LOCAL_LAB_URL", "http://dvwa:80")
    monkeypatch.setenv("SCANNER_LOCAL_LAB_IP", LAB_TEST_IP)
    monkeypatch.setattr(
        scanner.socket, "getaddrinfo",
        lambda host, port, type: _address_record(LAB_REBOUND_IP, port),
    )

    with pytest.raises(scanner.URLValidationError, match="configured IP"):
        scanner._validate_url("http://dvwa:80/")


def test_local_lab_mode_rejects_redirects_to_other_ports(monkeypatch):
    monkeypatch.setenv("SCANNER_LOCAL_LAB_URL", "http://dvwa:80")
    monkeypatch.setenv("SCANNER_LOCAL_LAB_IP", LAB_TEST_IP)
    monkeypatch.setattr(
        scanner.socket, "getaddrinfo",
        lambda host, port, type: _address_record(LAB_TEST_IP, port),
    )
    calls = []

    class Redirect:
        status_code = 302
        headers = {"Location": "http://dvwa:81/other"}
        url = "http://dvwa:80/"
        cookies = requests.cookies.RequestsCookieJar()

    monkeypatch.setattr(
        scanner, "_one_request",
        lambda *args, **kwargs: calls.append(args) or Redirect(),
    )

    response, _elapsed = scanner._request("GET", "http://dvwa:80/")

    assert response is None
    assert len(calls) == 1


def test_local_lab_mode_requires_complete_valid_configuration(monkeypatch):
    monkeypatch.setenv("SCANNER_LOCAL_LAB_URL", "http://dvwa:80")
    monkeypatch.delenv("SCANNER_LOCAL_LAB_IP", raising=False)

    with pytest.raises(scanner.URLValidationError, match="requires both"):
        scanner._validate_url("http://dvwa:80/")


def test_url_validation_normalizes_and_accepts_public_dns(monkeypatch):
    monkeypatch.setattr(
        scanner.socket, "getaddrinfo",
        lambda host, port, type: _address_record("93.184.216.34", port),
    )
    assert scanner._validate_url("HTTPS://Example.Test") == "https://example.test/"


def test_request_rejects_redirect_outside_approved_host(monkeypatch):
    monkeypatch.setattr(
        scanner.socket, "getaddrinfo",
        lambda host, port, type: _address_record("93.184.216.34", port),
    )
    calls = []

    class Redirect:
        status_code = 302
        headers = {"Location": "http://169.254.169.254/latest/meta-data/"}
        url = "https://example.test/"
        cookies = requests.cookies.RequestsCookieJar()

    monkeypatch.setattr(scanner, "_one_request", lambda *args, **kwargs: calls.append(args) or Redirect())
    response, _elapsed = scanner._request("GET", "https://example.test/")

    assert response is None
    assert len(calls) == 1


def test_request_rejects_dns_rebinding_before_connecting(monkeypatch):
    resolutions = iter(("93.184.216.34", "192.0.2.2"))
    monkeypatch.setattr(
        scanner.socket, "getaddrinfo",
        lambda host, port, type: _address_record(next(resolutions), port),
    )
    monkeypatch.setattr(
        scanner, "_pinned_connection",
        lambda *args, **kwargs: pytest.fail("connection must not be opened"),
    )

    with pytest.raises(scanner.URLValidationError):
        scanner._one_request("GET", "https://example.test/")


def test_request_handles_timeout_without_raising(monkeypatch):
    monkeypatch.setattr(scanner, "_validate_url", lambda url, allowed_host=None: url)

    def timeout(*_args, **_kwargs):
        raise requests.exceptions.Timeout("mock timeout")

    monkeypatch.setattr(scanner, "_one_request", timeout)
    response, elapsed = scanner._request("GET", "https://example.test/")

    assert response is None
    assert elapsed >= 0


def test_http_response_preserves_cookie_security_attributes(monkeypatch):
    session = requests.Session()
    monkeypatch.setattr(scanner, "_session", lambda: session)
    monkeypatch.setattr(scanner, "_validate_url", lambda url, allowed_host=None: url)
    monkeypatch.setattr(
        scanner.socket, "getaddrinfo",
        lambda host, port, type: _address_record("93.184.216.34", port),
    )

    class RawResponse:
        status = 200
        reason = "OK"

        def read(self, _limit):
            return b"<html>safe</html>"

        def getheaders(self):
            return [
                ("Content-Type", "text/html; charset=utf-8"),
                ("Set-Cookie", "session=abc; Path=/; Secure; HttpOnly; SameSite=Strict"),
            ]

    class Connection:
        sock = None

        def request(self, *_args, **_kwargs):
            pass

        def getresponse(self):
            return RawResponse()

        def close(self):
            pass

    monkeypatch.setattr(scanner, "_pinned_connection", lambda *_args: Connection())

    response = scanner._one_request("GET", "https://example.test/")
    cookie = next(iter(response.cookies))

    assert cookie.secure is True
    assert cookie.get_nonstandard_attr("HttpOnly") is True
    assert cookie.get_nonstandard_attr("SameSite") == "Strict"
    assert len(session.cookies) == 0


def test_request_carries_redirect_cookies_only_within_the_same_request(monkeypatch):
    seen_headers = []
    responses = []
    for status, location, cookie_name, cookie_value in (
        (302, "/login.php", "PHPSESSID", "first"),
        (200, None, "security", "low"),
    ):
        response = requests.Response()
        response.status_code = status
        response.url = "http://example.test/"
        response.headers = {}
        if location:
            response.headers["Location"] = location
        response.cookies = requests.cookies.RequestsCookieJar()
        response.cookies.set(cookie_name, cookie_value, domain="example.test", path="/")
        responses.append(response)

    def fake_one_request(_method, _url, **kwargs):
        seen_headers.append(dict(kwargs.get("headers") or {}))
        return responses.pop(0)

    monkeypatch.setattr(scanner, "_validate_url", lambda url, **_kwargs: url)
    monkeypatch.setattr(scanner, "_one_request", fake_one_request)

    response, _elapsed = scanner._request("GET", "http://example.test/")

    assert response.status_code == 200
    assert seen_headers[0] == {}
    assert seen_headers[1]["Cookie"] == "PHPSESSID=first"
    assert {cookie.name for cookie in response.cookies} == {"PHPSESSID", "security"}


def test_dvwa_login_uses_only_login_fields_and_keeps_cookies_ephemeral(monkeypatch, caplog):
    monkeypatch.setenv("SCANNER_LOCAL_LAB_URL", "http://dvwa:80")
    monkeypatch.setenv("SCANNER_LOCAL_LAB_IP", LAB_TEST_IP)
    monkeypatch.setenv("SCANNER_LOCAL_LAB_AUTH_ENABLED", "1")
    monkeypatch.setattr(
        scanner.socket, "getaddrinfo",
        lambda host, port, type: _address_record(LAB_TEST_IP, port),
    )
    login_cookie = requests.cookies.RequestsCookieJar()
    login_cookie.set("PHPSESSID", "initial-session", domain="dvwa", path="/")
    rotated_cookie = requests.cookies.RequestsCookieJar()
    rotated_cookie.set("PHPSESSID", "authenticated-session", domain="dvwa", path="/")
    calls = []

    class Response:
        status_code = 200

        def __init__(self, url, text, cookies=None):
            self.url = url
            self.text = text
            self.cookies = cookies or requests.cookies.RequestsCookieJar()

    def fake_get(url, headers=None, **_kwargs):
        calls.append(("GET", url, headers))
        if url == "http://dvwa:80/":
            return Response(
                "http://dvwa:80/login.php",
                '<form method="post" action="login.php">'
                '<input name="username"><input type="password" name="password">'
                '<input type="submit" name="Login" value="Login">'
                '<input type="hidden" name="user_token" value="csrf-token">'
                '<input name="unrelated" value="must-not-submit"></form>',
                login_cookie,
            ), 0.01
        assert url == "http://dvwa:80/index.php"
        assert headers["Cookie"] == "PHPSESSID=authenticated-session"
        return Response(
            url, '<a href="logout.php">Logout</a>', rotated_cookie,
        ), 0.01

    def fake_post(url, data, headers=None, **_kwargs):
        calls.append(("POST", url, headers))
        assert url == "http://dvwa:80/login.php"
        assert headers["Cookie"] == "PHPSESSID=initial-session"
        assert data == {
            "user_token": "csrf-token",
            "username": "demo-user",
            "password": "do-not-log-this",
            "Login": "Login",
        }
        return Response(url, "redirected", rotated_cookie), 0.01

    monkeypatch.setattr(scanner, "_get", fake_get)
    monkeypatch.setattr(scanner, "_post", fake_post)
    caplog.set_level("INFO", logger="scanner")

    headers, status = scanner._authenticate_local_dvwa(
        "http://dvwa:80/", "demo-user", "do-not-log-this",
    )

    assert headers["Cookie"] == "PHPSESSID=authenticated-session"
    assert status == {
        "authentication_mode": "authenticated",
        "authentication_mode_enabled": True,
        "login_session_establishment": "succeeded",
        "protected_access_verified": True,
        "protected_access_url": "http://dvwa:80/index.php",
    }
    assert len(calls) == 3
    assert "do-not-log-this" not in caplog.text
    assert "authenticated-session" not in caplog.text


def test_dvwa_login_rejects_non_configured_target_before_requests(monkeypatch):
    monkeypatch.setenv("SCANNER_LOCAL_LAB_URL", "http://dvwa:80")
    monkeypatch.setenv("SCANNER_LOCAL_LAB_IP", LAB_TEST_IP)
    monkeypatch.setenv("SCANNER_LOCAL_LAB_AUTH_ENABLED", "1")
    monkeypatch.setattr(
        scanner, "_get",
        lambda *_args, **_kwargs: pytest.fail("out-of-scope login must not request"),
    )

    with pytest.raises(scanner.LabAuthenticationError):
        scanner._authenticate_local_dvwa("http://other:80/", "user", "password")


def test_scanner_passes_auth_cookie_to_checks_without_reporting_it(monkeypatch):
    monkeypatch.setattr(
        scanner, "_authenticate_local_dvwa",
        lambda *_args: (
            {"Cookie": "PHPSESSID=secret-session"},
            {
                "authentication_mode": "authenticated",
                "authentication_mode_enabled": True,
                "login_session_establishment": "succeeded",
                "protected_access_verified": True,
                "protected_access_url": "http://dvwa:80/index.php",
            },
        ),
    )
    observed = []

    def fake_check(url, headers=None):
        observed.append(headers)
        return scanner._result("test", "A03", False, ["tested"], "None", "review")

    monkeypatch.setattr(scanner.SecurityScanner, "CHECKS", [fake_check])
    instance = scanner.SecurityScanner(
        "http://dvwa:80/", lab_credentials={"username": "user", "password": "secret-password"},
    )
    results = instance.run_all_checks()

    assert results[0]["finding_type"] == "none"
    assert observed == [{"Cookie": "PHPSESSID=secret-session"}]
    assert instance.scan_meta["authentication_mode"] == "authenticated"
    assert instance.scan_meta["authentication_mode_enabled"] is True
    assert instance.scan_meta["login_session_establishment"] == "succeeded"
    assert instance.scan_meta["protected_access_verified"] is True
    assert instance.scan_meta["protected_access_url"] == "http://dvwa:80/index.php"
    assert "secret-session" not in str(results)
    assert "secret-password" not in str(instance.scan_meta)


def test_failed_local_authentication_is_reported_without_secrets(monkeypatch):
    def fail_auth(*_args):
        raise scanner.LabAuthenticationError(
            "safe error text",
            {
                "authentication_mode": "authenticated",
                "authentication_mode_enabled": True,
                "login_session_establishment": "failed",
                "protected_access_verified": False,
                "protected_access_url": None,
            },
        )

    monkeypatch.setattr(scanner, "_authenticate_local_dvwa", fail_auth)
    instance = scanner.SecurityScanner(
        "http://dvwa:80/",
        lab_credentials={"username": "private-user", "password": "private-password"},
    )

    results = instance.run_all_checks()

    assert instance.scan_meta["authentication_mode_enabled"] is True
    assert instance.scan_meta["login_session_establishment"] == "failed"
    assert instance.scan_meta["protected_access_verified"] is False
    assert "private-user" not in str(instance.scan_meta)
    assert "private-password" not in str(instance.scan_meta)
    assert all("private-password" not in str(result) for result in results)


def test_response_differences_are_not_sqli_findings_without_new_db_error():
    class Response:
        def __init__(self, text, status_code):
            self.text = text
            self.status_code = status_code

    baseline = Response("ordinary content", 200)
    changed = Response("a much longer unrelated server response " * 100, 500)

    assert scanner._response_length_anomaly(len(baseline.text), len(changed.text))
    assert scanner._analyze_sqli_response(baseline, changed, 12.0, "'") is None


def test_crawler_deduplicates_links_and_obeys_page_cap(monkeypatch):
    monkeypatch.setattr(scanner, "_validate_url", lambda url, allowed_host=None: url)
    crawler = scanner.Crawler("https://example.test/", max_pages=2)
    seen = []

    def fetch(url):
        seen.append(url)
        if url.endswith("/"):
            return {
                "url": url, "status": 200, "title": "root", "form_count": 0, "elapsed": 0,
                "_links": [
                    "https://example.test/a",
                    "https://example.test/a",
                    "https://example.test/b",
                ],
            }
        return {
            "url": url, "status": 200, "title": "page", "form_count": 0, "elapsed": 0,
            "_links": ["https://example.test/"],
        }

    monkeypatch.setattr(crawler, "_fetch_page", fetch)
    pages = crawler.crawl()

    assert len(pages) == 2
    assert len(seen) == 2
    assert len({crawler._normalize(url) for url in seen}) == 2


def test_crawler_discovers_same_host_links_once_and_excludes_other_hosts(monkeypatch):
    monkeypatch.setattr(
        scanner.socket, "getaddrinfo",
        lambda host, port, type: _address_record("93.184.216.34", port),
    )
    requested = []
    headers_seen = []

    class Response:
        status_code = 200
        headers = {"Content-Type": "text/html"}

        def __init__(self, url, text):
            self.url = url
            self.text = text

    def fake_get(url, headers=None, **_kwargs):
        requested.append(url)
        headers_seen.append(headers)
        if url.endswith("/"):
            body = (
                '<a href="/page">page</a><a href="/page#section">duplicate</a>'
                '<a href="https://other.example/private">out of scope</a>'
            )
        else:
            body = '<a href="/">home</a>'
        return Response(url, f"<html><body>{body}</body></html>"), 0.01

    monkeypatch.setattr(scanner, "_get", fake_get)
    auth_headers = {"Cookie": "PHPSESSID=ephemeral"}
    crawler = scanner.Crawler(
        "https://example.test/", max_pages=5, headers=auth_headers,
    )

    pages = crawler.crawl()

    assert {page["url"] for page in pages} == {
        "https://example.test/",
        "https://example.test/page",
    }
    assert requested.count("https://example.test/") == 1
    assert requested.count("https://example.test/page") == 1
    assert all("other.example" not in url for url in requested)
    assert headers_seen == [auth_headers, auth_headers]


def test_crawler_records_form_structure_without_field_values(monkeypatch):
    monkeypatch.setattr(scanner, "_validate_url", lambda value, **_kwargs: value)
    monkeypatch.setattr(scanner, "_get", lambda *_args, **_kwargs: (
        type("Response", (), {
            "headers": {"Content-Type": "text/html"},
            "text": (
                '<form action="/search" method="get">'
                '<input name="term" type="search" value="private-search">'
                '</form>'
                '<form action="/login.php" method="post">'
                '<input name="username" value="private-user">'
                '<input name="password" type="password" value="private-password">'
                '<input name="user_token" type="hidden" value="private-csrf-token">'
                '</form>'
            ),
            "status_code": 200,
        })(), 0.01,
    ))
    crawler = scanner.Crawler("https://example.test/")

    page = crawler._fetch_page("https://example.test/")
    serialized = str(page["forms"])

    assert page["form_count"] == 2
    assert [form["method"] for form in page["forms"]] == ["GET", "POST"]
    assert page["forms"][0]["action"] == "https://example.test/search"
    assert page["forms"][0]["fields"] == [
        {"name": "term", "type": "search", "is_password": False},
    ]
    assert page["forms"][1]["fields"] == [
        {"name": "username", "type": "text", "is_password": False},
        {"name": "password", "type": "password", "is_password": True},
        {"name": "user_token", "type": "hidden", "is_password": False},
    ]
    assert all(value not in serialized for value in (
        "private-search", "private-user", "private-password", "private-csrf-token",
    ))


def test_passive_checks_analyze_mocked_responses(monkeypatch):
    class Response:
        url = "https://example.test/"
        status_code = 200
        text = "<html><script src='/jquery/1.9.9.js'></script></html>"
        headers = {
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "no-referrer",
            "Strict-Transport-Security": "max-age=31536000",
        }

    monkeypatch.setattr(scanner, "_get", lambda *_args, **_kwargs: (Response(), 0.01))
    config = scanner.check_security_misconfiguration("https://example.test/")
    component = scanner.check_components_with_vulnerabilities("https://example.test/")

    assert config["detected"] is False
    assert component["detected"] is True
    assert component["finding_type"] == "possible"


def test_sql_injection_check_requires_new_database_error(monkeypatch):
    class Response:
        url = "https://example.test/?q=hello"
        status_code = 200
        headers = {"Content-Type": "text/html"}

        def __init__(self, text):
            self.text = text

    responses = iter((Response("<p>baseline</p>"), Response("SQL syntax error in MySQL query")))
    headers_seen = []

    def fake_get(*_args, headers=None, **_kwargs):
        headers_seen.append(headers)
        return next(responses), 0.01

    monkeypatch.setattr(scanner, "_get", fake_get)

    auth_headers = {"Cookie": "PHPSESSID=ephemeral"}
    result = scanner.check_sql_injection(
        "https://example.test/?q=hello", headers=auth_headers,
    )

    assert result["detected"] is True
    assert result["finding_type"] == "possible"
    assert result["evidence"][0]["type"] == "database_error"
    assert headers_seen == [auth_headers, auth_headers]
    assert "ephemeral" not in str(result)


def test_sql_injection_without_probeable_inputs_is_not_marked_passed(monkeypatch):
    class Response:
        url = "http://dvwa:80/login.php"
        status_code = 200
        text = '<form method="post" action="/login.php"><input name="user"></form>'

    monkeypatch.setattr(scanner, "_get", lambda *_args, **_kwargs: (Response(), 0.01))

    result = scanner.check_sql_injection("http://dvwa:80/")

    assert result["detected"] is False
    assert result["finding_type"] == "unsupported"
    assert result["status"] == "NOT TESTED"
    assert "not assessed" in result["details"][0]


def test_sql_injection_reports_post_fields_as_not_tested_without_posting(monkeypatch):
    class Response:
        url = "http://dvwa:80/vulnerabilities/sqli/"
        status_code = 200
        text = (
            '<form method="post" action="/vulnerabilities/sqli/">'
            '<input name="id" value="1"><input name="Submit" type="submit">'
            '</form>'
        )

    monkeypatch.setattr(scanner, "_get", lambda *_args, **_kwargs: (Response(), 0.01))
    monkeypatch.setattr(
        scanner, "_post",
        lambda *_args, **_kwargs: pytest.fail("POST forms must remain passive"),
    )

    result = scanner.check_sql_injection("http://dvwa:80/vulnerabilities/sqli/")
    candidate = result["evidence"][0]

    assert result["finding_type"] == "unsupported"
    assert result["status"] == "NOT TESTED"
    assert candidate["page_url"] == "http://dvwa:80/vulnerabilities/sqli/"
    assert candidate["form_action"] == "http://dvwa:80/vulnerabilities/sqli/"
    assert candidate["method"] == "POST"
    assert candidate["field_names"] == ["id", "Submit"]
    assert "not submitted" in candidate["description"]


def test_sql_injection_evidence_identifies_get_form_candidate(monkeypatch):
    class Response:
        url = "https://example.test/search"
        status_code = 200

        def __init__(self, text):
            self.text = text

    responses = iter((
        Response(
            '<form method="get" action="/search">'
            '<input name="term"><input type="hidden" name="user_token" value="csrf-secret">'
            '<input type="submit" name="Submit"></form>'
        ),
        Response("SQL syntax error in MySQL query"),
    ))
    monkeypatch.setattr(scanner, "_validate_url", lambda value, **_kwargs: value)
    monkeypatch.setattr(
        scanner, "_get",
        lambda *_args, **_kwargs: (next(responses), 0.01),
    )

    result = scanner.check_sql_injection("https://example.test/search")
    evidence = result["evidence"][0]

    assert result["finding_type"] == "possible"
    assert evidence["page_url"] == "https://example.test/search"
    assert evidence["form_action"] == "https://example.test/search"
    assert evidence["method"] == "GET"
    assert evidence["field_names"] == ["term"]


def test_scanner_supplies_crawled_form_metadata_to_sqli_and_a07(monkeypatch):
    forms = [{
        "page_url": "http://dvwa:80/vulnerabilities/sqli/",
        "action": "http://dvwa:80/vulnerabilities/sqli/",
        "method": "POST",
        "fields": [
            {"name": "id", "type": "text", "is_password": False},
            {"name": "password", "type": "password", "is_password": True},
        ],
        "index": 0,
    }]

    class FakeCrawler:
        def __init__(self, *_args, **_kwargs):
            pass

        def crawl(self):
            return [{
                "url": forms[0]["page_url"],
                "status": 200,
                "title": "DVWA",
                "form_count": 1,
                "forms": forms,
            }]

    class Response:
        url = forms[0]["page_url"]
        status_code = 200
        text = (
            '<form method="post" action="/vulnerabilities/sqli/">'
            '<input name="id"><input name="password" type="password"></form>'
        )

    monkeypatch.setattr(scanner, "Crawler", FakeCrawler)
    monkeypatch.setattr(scanner, "_get", lambda *_args, **_kwargs: (Response(), 0.01))
    scanner_instance = scanner.SecurityScanner("http://dvwa:80/", crawl=True)
    monkeypatch.setattr(
        scanner.SecurityScanner, "CHECKS",
        [scanner.check_sql_injection, scanner.check_authentication_weakness],
    )

    results = {
        result["name"]: result
        for result in scanner_instance.run_all_checks()
    }

    assert results["SQL Injection"]["status"] == "NOT TESTED"
    assert results["SQL Injection"]["evidence"][0]["field_names"] == ["id", "password"]
    assert results["Authentication Strength (not assessed)"]["status"] == "NOT ASSESSED"
    assert "Password-bearing form discovered" in results["Authentication Strength (not assessed)"]["details"][0]
    assert "password-secret" not in str(scanner_instance.scan_meta)


def test_xss_check_only_flags_raw_inert_marker_reflection(monkeypatch):
    class Response:
        url = "https://example.test/?q=hello"
        status_code = 200
        headers = {"Content-Type": "text/html"}

        def __init__(self, text):
            self.text = text

    responses = iter((
        Response("<p>baseline</p>"),
        Response("<p>&lt;owasp-probe-7f3a&gt;</p>"),
    ))
    monkeypatch.setattr(scanner, "_get", lambda *_args, **_kwargs: (next(responses), 0.01))

    result = scanner.check_xss("https://example.test/?q=hello")

    assert result["detected"] is False
    assert result["finding_type"] == "none"


def test_xss_check_reports_unescaped_inert_marker(monkeypatch):
    class Response:
        url = "https://example.test/?q=hello"
        status_code = 200
        headers = {"Content-Type": "text/html"}

        def __init__(self, text):
            self.text = text

    responses = iter((
        Response("<p>baseline</p>"),
        Response("<p><owasp-probe-7f3a></p>"),
    ))
    headers_seen = []

    def fake_get(*_args, headers=None, **_kwargs):
        headers_seen.append(headers)
        return next(responses), 0.01

    monkeypatch.setattr(scanner, "_get", fake_get)

    auth_headers = {"Cookie": "PHPSESSID=ephemeral"}
    result = scanner.check_xss("https://example.test/?q=hello", headers=auth_headers)

    assert result["detected"] is True
    assert result["finding_type"] == "possible"
    assert result["evidence"][0]["url"] == "https://example.test/?q=hello"
    assert headers_seen == [auth_headers, auth_headers]
    assert "ephemeral" not in str(result)
    evidence = result["evidence"][0]
    assert evidence["parameter"] == "q"
    assert evidence["field_names"] == ["q"]
    assert "JavaScript execution was not tested or confirmed" in evidence["description"]


def test_xss_form_evidence_names_fields_without_claiming_execution(monkeypatch):
    class Response:
        url = "https://example.test/search"
        status_code = 200

        def __init__(self, text):
            self.text = text

    responses = iter((
        Response(
            '<form method="get" action="/search">'
            '<input name="term"><input type="hidden" name="user_token" value="csrf-secret">'
            '<input type="submit" name="Submit"></form>'
        ),
        Response("<p><owasp-probe-7f3a></p>"),
    ))
    monkeypatch.setattr(scanner, "_validate_url", lambda value, **_kwargs: value)
    monkeypatch.setattr(
        scanner, "_get",
        lambda *_args, **_kwargs: (next(responses), 0.01),
    )

    result = scanner.check_xss("https://example.test/search")
    evidence = result["evidence"][0]

    assert result["status"] == "POSSIBLE FINDING"
    assert result["finding_type"] == "possible"
    assert evidence["page_url"] == "https://example.test/search"
    assert evidence["form_action"] == "https://example.test/search"
    assert evidence["method"] == "GET"
    assert evidence["field_names"] == ["term"]
    assert "JavaScript execution was not tested or confirmed" in evidence["description"]


def test_xss_crawl_summary_compacts_unaffected_pages_and_preserves_evidence():
    finding = {
        "name": "Cross-Site Scripting (XSS)",
        "owasp": "A03:2021 – Injection",
        "detected": True,
        "finding_type": "possible",
        "severity": "Medium",
        "affected_url": "https://example.test/search",
        "details": [
            "The inert HTML marker was reflected unescaped in query parameter 'q'; "
            "JavaScript execution was not tested or confirmed."
        ],
        "evidence": [{
            "type": "unescaped_reflection",
            "description": (
                "The inert HTML marker was reflected unescaped in query parameter 'q'; "
                "JavaScript execution was not tested or confirmed."
            ),
            "url": "https://example.test/search",
            "parameter": "q",
        }],
    }
    no_finding = {
        "name": "Cross-Site Scripting (XSS)",
        "owasp": "A03:2021 – Injection",
        "detected": False,
        "finding_type": "none",
        "severity": "None",
        "affected_url": "https://example.test/unaffected",
        "details": ["No unescaped marker reflection was observed."],
        "evidence": [],
    }

    merged = scanner._merge_page_check_results(
        "check_xss",
        [finding, no_finding, dict(no_finding, affected_url="https://example.test/other")],
        "https://example.test/",
    )

    assert merged["finding_type"] == "possible"
    assert len(merged["evidence"]) == 1
    assert merged["evidence"][0]["url"] == "https://example.test/search"
    assert merged["evidence"][0]["parameter"] == "q"
    assert merged["details"] == [
        "[https://example.test/search] "
        "The inert HTML marker was reflected unescaped in query parameter 'q'; "
        "JavaScript execution was not tested or confirmed.",
        "No unescaped inert-marker reflection was observed on 2 other crawled page(s).",
    ]


def test_access_control_check_reports_only_a_possible_route_indicator(monkeypatch):
    class Response:
        def __init__(self, status, text):
            self.status_code = status
            self.text = text

    def fake_get(url, **_kwargs):
        if url == "https://example.test/":
            return Response(200, "Public landing page"), 0.01
        if url.endswith("/admin"):
            return Response(200, "Distinct admin-like content"), 0.01
        return Response(404, "not found"), 0.01

    monkeypatch.setattr(scanner, "_get", fake_get)

    result = scanner.check_broken_access_control("https://example.test/")

    assert result["detected"] is True
    assert result["finding_type"] == "possible"
    assert any(
        evidence["url"] in {
            "https://example.test/admin",
            "https://example.test/dashboard",
            "https://example.test/api/admin",
        }
        for evidence in result["evidence"]
    )


def test_sensitive_data_check_accepts_properly_flagged_cookies(monkeypatch):
    jar = requests.cookies.RequestsCookieJar()
    jar.set(
        "session", "abc", domain="example.test", path="/", secure=True,
        rest={"HttpOnly": True, "SameSite": "Strict"},
    )

    class Response:
        url = "https://example.test/"
        status_code = 200
        text = "<html>ordinary page</html>"
        headers = {}
        cookies = jar

    monkeypatch.setattr(scanner, "_get", lambda *_args, **_kwargs: (Response(), 0.01))

    result = scanner.check_sensitive_data_exposure("https://example.test/")

    assert result["detected"] is False
    assert result["finding_type"] == "none"
    assert any("properly flagged" in detail for detail in result["details"])


def test_sensitive_data_check_flags_cookie_missing_security_attributes(monkeypatch):
    jar = requests.cookies.RequestsCookieJar()
    jar.set("session", "abc", domain="example.test", path="/")

    class Response:
        url = "https://example.test/"
        status_code = 200
        text = "<html>ordinary page</html>"
        headers = {}
        cookies = jar

    monkeypatch.setattr(scanner, "_get", lambda *_args, **_kwargs: (Response(), 0.01))

    result = scanner.check_sensitive_data_exposure("https://example.test/")

    assert result["detected"] is True
    assert any("missing Secure" in detail for detail in result["details"])
    assert any("missing HttpOnly" in detail for detail in result["details"])
    assert any("missing SameSite" in detail for detail in result["details"])


def test_sensitive_data_distinguishes_request_and_response_cookies(monkeypatch, caplog):
    class Response:
        url = "http://dvwa:80/page"
        status_code = 200
        text = "<html>ordinary page</html>"
        headers = {}
        cookies = requests.cookies.RequestsCookieJar()

    secret_cookie = "request-cookie-secret"
    secret_response_cookie = "response-cookie-secret"
    Response.cookies.set("new_cookie", secret_response_cookie, domain="dvwa", path="/")
    monkeypatch.setattr(
        scanner, "_get", lambda *_args, **_kwargs: (Response(), 0.01),
    )
    caplog.set_level("INFO", logger="scanner")

    result = scanner.check_sensitive_data_exposure(
        "http://dvwa:80/page",
        headers={"Cookie": f"PHPSESSID={secret_cookie}"},
    )
    serialized = str(result)

    assert any("Response-set cookie 'new_cookie'" in detail for detail in result["details"])
    assert "Request sent cookie name(s): PHPSESSID" in serialized
    assert secret_cookie not in serialized
    assert secret_response_cookie not in serialized
    assert secret_cookie not in caplog.text
    assert secret_response_cookie not in caplog.text


def test_authentication_discovery_does_not_claim_authentication_was_tested():
    forms = [{
        "page_url": "http://dvwa:80/login.php",
        "action": "http://dvwa:80/login.php",
        "method": "POST",
        "fields": [
            {"name": "username", "type": "text", "is_password": False},
            {"name": "password", "type": "password", "is_password": True},
        ],
    }]

    result = scanner.check_authentication_weakness(
        "http://dvwa:80/", form_metadata=forms,
    )

    assert result["finding_type"] == "unsupported"
    assert result["status"] == "NOT ASSESSED"
    assert "Password-bearing form discovered" in result["details"][0]
    assert "Authentication strength was not tested" in result["details"][1]


def test_generated_form_and_cookie_reports_exclude_secret_values(monkeypatch, caplog):
    from report import ReportGenerator, build_pdf, build_text_report

    class Response:
        url = "http://dvwa:80/"
        status_code = 200
        text = '<form method="post"><input name="password" value="form-password-secret"></form>'
        headers = {}
        cookies = requests.cookies.RequestsCookieJar()

    Response.cookies.set("PHPSESSID", "response-cookie-secret", domain="dvwa", path="/")
    request_cookie_secret = "request-cookie-secret"
    monkeypatch.setattr(scanner, "_get", lambda *_args, **_kwargs: (Response(), 0.01))
    caplog.set_level("INFO", logger="scanner")

    finding = scanner.check_sensitive_data_exposure(
        "http://dvwa:80/",
        headers={
            "Cookie": f"PHPSESSID={request_cookie_secret}",
            "X-Local-Credential": "credential-secret",
        },
    )
    report = ReportGenerator("http://dvwa:80/", [finding]).generate()
    json_text = __import__("json").dumps(report)
    text_report = build_text_report(report)
    pdf_report = build_pdf(report)

    for secret in (
        "form-password-secret", "response-cookie-secret",
        request_cookie_secret, "credential-secret",
    ):
        assert secret not in json_text
        assert secret not in text_report
        assert secret.encode("utf-8") not in pdf_report
        assert secret not in caplog.text


def test_scanner_runs_checks_concurrently_and_returns_all_results(monkeypatch):
    scanner_instance = scanner.SecurityScanner("https://example.test/")
    active = 0
    max_active = 0
    lock = threading.Lock()

    def check_factory(index):
        def check(_url):
            nonlocal active, max_active
            with lock:
                active += 1
                max_active = max(max_active, active)
            time.sleep(0.03)
            with lock:
                active -= 1
            return scanner._result(
                f"check-{index}", "A05", False, ["tested"], "None", "review"
            )
        return check

    monkeypatch.setattr(scanner.SecurityScanner, "CHECKS", [check_factory(i) for i in range(6)])
    results = scanner_instance.run_all_checks()

    assert len(results) == 6
    assert max_active > 1
    assert scanner_instance.scan_meta["checks_run"] == 6


def test_scanner_check_exceptions_do_not_expose_exception_messages(monkeypatch, caplog):
    scanner_instance = scanner.SecurityScanner("https://example.test/")
    caplog.set_level("ERROR", logger="scanner")

    def fail(_url):
        raise RuntimeError("sensitive response content")

    monkeypatch.setattr(scanner.SecurityScanner, "CHECKS", [fail])

    result = scanner_instance.run_all_checks()[0]

    assert result["finding_type"] == "error"
    assert "sensitive response content" not in result["description"]
    assert "sensitive response content" not in caplog.text


def test_scanner_logs_do_not_include_query_string_secrets(monkeypatch, caplog):
    monkeypatch.setattr(scanner, "_validate_url", lambda url, allowed_host=None: url)
    caplog.set_level("INFO", logger="scanner")

    def timeout(*_args, **_kwargs):
        raise requests.exceptions.Timeout("secret from an exception should not be logged")

    monkeypatch.setattr(scanner, "_one_request", timeout)
    scanner._get("https://example.test/path?access_token=secret-value")

    assert "secret-value" not in caplog.text
    assert "https://example.test" in caplog.text


def test_result_helper_accepts_evidence_and_classifies_check_errors():
    finding = scanner._result(
        "Check", "A05", True, ["indicator"], "Low", "review",
        affected_url="https://example.test/",
        evidence=[{"description": "indicator"}],
    )
    error = scanner._result("Check", "A05", False, ["internal detail"], "Error", "retry")

    assert finding["finding_type"] == "possible"
    assert finding["description"] == "indicator"
    assert finding["evidence"][0]["description"] == "indicator"
    assert error["finding_type"] == "error"
    assert error["status"] == "ERROR"


def test_authentication_check_never_submits_credentials(monkeypatch):
    class LoginResponse:
        status_code = 200
        url = "https://example.test/"
        text = '<form action="/login" method="post"><input type="password" name="password"></form>'

    monkeypatch.setattr(scanner, "_get", lambda *_args, **_kwargs: (LoginResponse(), 0.01))
    monkeypatch.setattr(
        scanner, "_post",
        lambda *_args, **_kwargs: pytest.fail("authentication checks must not submit credentials"),
    )

    result = scanner.check_authentication_weakness("https://example.test/")

    assert result["finding_type"] == "unsupported"
    assert result["status"] == "NOT ASSESSED"
    assert result["detected"] is False
