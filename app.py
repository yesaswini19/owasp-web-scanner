"""Flask application for the local OWASP scanner dashboard and API."""

import io
import hmac
import json
import logging
import math
import os
import secrets
import sqlite3
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone

from flask import (
    Flask, jsonify, make_response, redirect, render_template, request, send_file,
    session, url_for,
)
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge
from werkzeug.security import check_password_hash

from scanner import (
    SecurityScanner,
    URLValidationError,
    _validate_url as validate_target_url,
    validate_local_lab_auth_target,
)
from report import ReportGenerator, build_pdf, build_text_report


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
app.config.update(
    SESSION_COOKIE_NAME="owasp_scanner_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    LOGIN_RATE_LIMIT_DB=os.path.join(
        tempfile.gettempdir(), "owasp-scanner-login-rate-limit.sqlite3",
    ),
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger(__name__)

MAX_CONCURRENT_SCANS = 2
_scan_slots = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)


class ScanCapacityError(RuntimeError):
    """Raised when all local scan slots are in use."""


def _auth_settings() -> dict | None:
    username = os.environ.get("SCANNER_ADMIN_USERNAME", "")
    password_hash = os.environ.get("SCANNER_ADMIN_PASSWORD_HASH", "")
    secret_key = os.environ.get("SECRET_KEY", "")
    cookie_secure = os.environ.get("SCANNER_COOKIE_SECURE", "true").lower()
    hash_parts = password_hash.split("$")
    valid_hash = (
        len(hash_parts) == 3
        and hash_parts[0] == "scrypt:32768:8:1"
        and len(hash_parts[1]) == 16
        and hash_parts[1].isascii()
        and hash_parts[1].isalnum()
        and len(hash_parts[2]) == 128
        and all(char in "0123456789abcdef" for char in hash_parts[2].lower())
    )
    development_cookie_setting = (
        cookie_secure == "false"
        and os.environ.get("SCANNER_ENV") == "development"
    )
    if (
        not username
        or len(username) > 128
        or any(ord(char) < 32 for char in username)
        or not valid_hash
        or len(secret_key.encode("utf-8")) < 32
        or cookie_secure not in ("true", "false")
        or (cookie_secure == "false" and not development_cookie_setting)
    ):
        return None

    app.config["SESSION_COOKIE_SECURE"] = cookie_secure == "true"
    return {"username": username, "password_hash": password_hash}


def _ensure_csrf_token() -> str:
    token = session.get("csrf_token")
    if not isinstance(token, str):
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _csrf_is_valid() -> bool:
    expected = session.get("csrf_token")
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    return (
        isinstance(expected, str)
        and isinstance(supplied, str)
        and hmac.compare_digest(expected, supplied)
    )


def _login_rate_limit_keys() -> tuple[str, str]:
    secret = app.config["SECRET_KEY"].encode("utf-8")
    remote = request.remote_addr or "unknown"
    address_key = hmac.new(
        secret, f"login-ip:{remote}".encode("utf-8"), "sha256",
    ).hexdigest()
    return f"ip:{address_key}", "account:admin"


def _consume_login_attempt() -> int:
    now = time.time()
    window_seconds = 15 * 60
    limits = {key: limit for key, limit in zip(_login_rate_limit_keys(), (20, 5))}
    with sqlite3.connect(app.config["LOGIN_RATE_LIMIT_DB"], timeout=5) as database:
        database.execute(
            "CREATE TABLE IF NOT EXISTS login_attempts "
            "(bucket TEXT PRIMARY KEY, window_start REAL NOT NULL, attempts INTEGER NOT NULL)"
        )
        database.execute("BEGIN IMMEDIATE")
        rows = {
            key: (window_start, attempts)
            for key, window_start, attempts in database.execute(
                "SELECT bucket, window_start, attempts FROM login_attempts "
                "WHERE bucket IN (?, ?)",
                tuple(limits),
            )
        }
        retry_after = 0
        for key, limit in limits.items():
            row = rows.get(key)
            if row and now - row[0] < window_seconds and row[1] >= limit:
                retry_after = max(
                    retry_after, int(row[0] + window_seconds - now) + 1,
                )
        if retry_after:
            database.commit()
            return retry_after

        for key in limits:
            row = rows.get(key)
            if not row or now - row[0] >= window_seconds:
                database.execute(
                    "INSERT INTO login_attempts(bucket, window_start, attempts) "
                    "VALUES (?, ?, 1) ON CONFLICT(bucket) DO UPDATE SET "
                    "window_start=excluded.window_start, attempts=1",
                    (key, now),
                )
            else:
                database.execute(
                    "UPDATE login_attempts SET attempts=attempts+1 WHERE bucket=?",
                    (key,),
                )
        database.commit()
    return 0


def _clear_login_rate_limit() -> None:
    keys = _login_rate_limit_keys()
    with sqlite3.connect(app.config["LOGIN_RATE_LIMIT_DB"], timeout=5) as database:
        database.execute(
            "DELETE FROM login_attempts WHERE bucket IN (?, ?)", keys,
        )


@app.before_request
def enforce_application_authentication():
    settings = _auth_settings()
    if request.endpoint == "health":
        if settings is None:
            return _error_response("Authentication configuration is incomplete.", 503)
        return None
    if settings is None:
        return _error_response("Authentication configuration is incomplete.", 503)

    if request.endpoint in {"static", "login"}:
        if request.endpoint == "login" and request.method == "POST":
            if not _csrf_is_valid():
                return render_template(
                    "login.html", error="The form expired. Reload the page and try again.",
                    csrf_token=_ensure_csrf_token(),
                ), 400
        return None

    if not session.get("authenticated"):
        if request.endpoint == "index" and request.method in {"GET", "HEAD"}:
            return redirect(url_for("login"))
        return _error_response("Authentication is required.", 401)

    if request.method not in {"GET", "HEAD", "OPTIONS"} and not _csrf_is_valid():
        return _error_response("A valid CSRF token is required.", 400)
    return None


@app.after_request
def set_private_response_headers(response):
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


def _parse_json_object() -> dict:
    if not request.is_json:
        raise ValueError("Content-Type must be application/json.")
    try:
        data = request.get_json()
    except BadRequest as exc:
        raise ValueError("Request body must contain valid JSON.") from exc
    if not isinstance(data, dict):
        raise ValueError("Request body must be a JSON object.")
    return data


def _validate_url(url) -> str:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("A target URL is required.")
    try:
        return validate_target_url(url.strip())
    except URLValidationError as exc:
        raise ValueError(str(exc)) from exc


def _scan_options(data: dict) -> tuple[str, bool, dict | None]:
    crawl = data.get("crawl", False)
    if not isinstance(crawl, bool):
        raise ValueError("'crawl' must be true or false.")
    url = _validate_url(data.get("url"))
    authenticated = data.get("authenticated", False)
    if not isinstance(authenticated, bool):
        raise ValueError("'authenticated' must be true or false.")
    if not authenticated:
        if data.get("username") or data.get("password"):
            raise ValueError("Credentials are accepted only for an explicitly authenticated lab scan.")
        return url, crawl, None

    try:
        validate_local_lab_auth_target(url)
    except URLValidationError as exc:
        raise ValueError(str(exc)) from exc
    username = data.get("username")
    password = data.get("password")
    if (
        not isinstance(username, str)
        or not username
        or len(username) > 256
        or not isinstance(password, str)
        or not password
        or len(password) > 1024
        or any(ord(char) < 32 for char in username + password)
    ):
        raise ValueError("Enter valid local DVWA credentials.")
    return url, crawl, {"username": username, "password": password}


def _run_scan(url: str, crawl: bool, lab_credentials: dict = None) -> tuple[dict, SecurityScanner]:
    scanner = SecurityScanner(url, crawl=crawl, lab_credentials=lab_credentials)
    results = scanner.run_all_checks()
    report = ReportGenerator(url, results, scanner.scan_meta)
    return report.generate(), scanner


def _run_limited_scan(url: str, crawl: bool, lab_credentials: dict = None) -> dict:
    if not _scan_slots.acquire(blocking=False):
        raise ScanCapacityError("The scanner is busy. Please try again shortly.")
    try:
        if lab_credentials is None:
            report_data, _ = _run_scan(url, crawl)
        else:
            report_data, _ = _run_scan(url, crawl, lab_credentials)
        return report_data
    finally:
        _scan_slots.release()


def _validate_report(data):
    def reject_non_finite(value):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("'report' must not contain NaN or infinite numbers.")
        if isinstance(value, dict):
            for item in value.values():
                reject_non_finite(item)
        elif isinstance(value, list):
            for item in value:
                reject_non_finite(item)

    reject_non_finite(data)
    if not isinstance(data, dict):
        raise ValueError("'report' must be a report object returned by /scan.")
    if not all(key in data for key in ("meta", "summary", "scan_performance", "results")):
        raise ValueError("'report' is missing required report fields.")
    if not isinstance(data["meta"], dict) or not isinstance(data["summary"], dict):
        raise ValueError("'report' metadata and summary must be JSON objects.")
    if not isinstance(data["scan_performance"], dict) or not isinstance(data["results"], list):
        raise ValueError("'report' performance must be an object and results must be an array.")
    required = {
        "meta": ("tool", "version", "target", "generated_at", "disclaimer"),
        "summary": ("total_checks", "vulnerabilities_detected", "passed",
                    "overall_risk", "severity_breakdown"),
        "scan_performance": ("duration_seconds", "pages_crawled",
                             "total_checks_performed", "pages"),
    }
    for section, keys in required.items():
        if any(key not in data[section] for key in keys):
            raise ValueError(f"'report.{section}' is missing required fields.")
    if not isinstance(data["summary"]["severity_breakdown"], dict):
        raise ValueError("'report.summary.severity_breakdown' must be a JSON object.")
    if not isinstance(data["scan_performance"]["pages"], list):
        raise ValueError("'report.scan_performance.pages' must be an array.")
    result_keys = ("name", "owasp", "detected", "status", "severity", "description",
                   "details", "recommendation", "finding_type", "affected_url", "evidence")
    for result in data["results"]:
        if not isinstance(result, dict) or any(key not in result for key in result_keys):
            raise ValueError("Every report result must contain the required result fields.")
    return data


def _export_report(data: dict) -> dict:
    if "report" in data:
        return _validate_report(data["report"])
    url, crawl, lab_credentials = _scan_options(data)
    return _run_limited_scan(url, crawl, lab_credentials)


def _error_response(message: str, status: int):
    return jsonify({"error": message}), status


@app.errorhandler(RequestEntityTooLarge)
def request_too_large(_error):
    return _error_response("Request body exceeds the 2 MB limit.", 413)


@app.route("/")
def index():
    return render_template("index.html", csrf_token=_ensure_csrf_token())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("authenticated"):
            return redirect(url_for("index"))
        return render_template("login.html", error=None, csrf_token=_ensure_csrf_token())

    try:
        retry_after = _consume_login_attempt()
    except sqlite3.Error as exc:
        logger.error("Login rate limiter unavailable (%s).", type(exc).__name__)
        return _error_response("Login is temporarily unavailable.", 503)
    if retry_after:
        response = make_response(
            render_template(
                "login.html", error="Too many login attempts. Try again later.",
                csrf_token=_ensure_csrf_token(),
            ),
            429,
        )
        response.headers["Retry-After"] = str(retry_after)
        return response

    settings = _auth_settings()
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    username_valid = (
        isinstance(username, str)
        and len(username) <= 128
        and hmac.compare_digest(
            username.encode("utf-8"), settings["username"].encode("utf-8"),
        )
    )
    password_valid = (
        isinstance(password, str)
        and len(password) <= 1024
        and check_password_hash(
            settings["password_hash"], password,
        )
    )
    if not username_valid or not password_valid:
        return render_template(
            "login.html", error="Invalid username or password.",
            csrf_token=_ensure_csrf_token(),
        ), 401

    try:
        _clear_login_rate_limit()
    except sqlite3.Error as exc:
        logger.error("Login rate limiter unavailable (%s).", type(exc).__name__)
        return _error_response("Login is temporarily unavailable.", 503)

    session.clear()
    session["authenticated"] = True
    session["csrf_token"] = secrets.token_urlsafe(32)
    session.permanent = True
    return redirect(url_for("index"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "2.0.0"})


@app.route("/scan", methods=["POST"])
def scan():
    try:
        url, crawl, lab_credentials = _scan_options(_parse_json_object())
    except ValueError as exc:
        return _error_response(str(exc), 400)

    logger.info("Scan requested (crawl=%s)", crawl)
    try:
        return jsonify(_run_limited_scan(url, crawl, lab_credentials))
    except ScanCapacityError as exc:
        return _error_response(str(exc), 429)
    except URLValidationError:
        return _error_response("The target failed URL safety validation.", 400)
    except Exception as exc:
        logger.error("Scan request failed (%s).", type(exc).__name__)
        return _error_response("The scan could not be completed. Check the server logs.", 500)


@app.route("/export/json", methods=["POST"])
def export_json():
    try:
        report_data = _export_report(_parse_json_object())
    except ValueError as exc:
        return _error_response(str(exc), 400)
    except ScanCapacityError as exc:
        return _error_response(str(exc), 429)
    except URLValidationError:
        return _error_response("The target failed URL safety validation.", 400)
    except Exception as exc:
        logger.error("JSON report generation failed (%s).", type(exc).__name__)
        return _error_response("The report could not be generated. Check the server logs.", 500)

    filename = f"owasp_report_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.json"
    payload = json.dumps(
        report_data, indent=2, ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    response = make_response(payload)
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@app.route("/export/pdf", methods=["POST"])
def export_pdf():
    try:
        report_data = _export_report(_parse_json_object())
        pdf_bytes = build_pdf(report_data)
    except ValueError as exc:
        return _error_response(str(exc), 400)
    except ScanCapacityError as exc:
        return _error_response(str(exc), 429)
    except URLValidationError:
        return _error_response("The target failed URL safety validation.", 400)
    except ImportError:
        filename = f"owasp_report_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.txt"
        buf = io.BytesIO(build_text_report(report_data).encode("utf-8"))
        return send_file(buf, mimetype="text/plain; charset=utf-8",
                         as_attachment=True, download_name=filename)
    except Exception as exc:
        logger.error("PDF report generation failed (%s).", type(exc).__name__)
        return _error_response("The report could not be generated. Check the server logs.", 500)

    filename = f"owasp_report_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.pdf"
    return send_file(io.BytesIO(pdf_bytes), mimetype="application/pdf",
                     as_attachment=True, download_name=filename)


@app.route("/export", methods=["POST"])
def export_legacy():
    return export_json()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
