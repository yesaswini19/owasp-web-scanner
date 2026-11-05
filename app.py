"""Flask application for the local OWASP scanner dashboard and API."""

import io
import json
import logging
import math
import threading
from datetime import datetime, timezone

from flask import Flask, jsonify, make_response, render_template, request, send_file
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

from scanner import (
    SecurityScanner,
    URLValidationError,
    _validate_url as validate_target_url,
    validate_local_lab_auth_target,
)
from report import ReportGenerator, build_pdf, build_text_report


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger(__name__)

MAX_CONCURRENT_SCANS = 2
_scan_slots = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)


class ScanCapacityError(RuntimeError):
    """Raised when all local scan slots are in use."""


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
    return render_template("index.html")


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
