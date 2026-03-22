"""
app.py - Main Flask Application (v2.0)
======================================
Endpoints:
  GET  /            → Dashboard UI
  POST /scan        → Run scan, return JSON report
  POST /export/json → Downloadable JSON report
  POST /export/pdf  → Downloadable PDF report  (Upgrade 5)
  GET  /health      → Health check (for Docker/k8s)
"""

import logging
import json
import io
from datetime import datetime, timezone

from flask import Flask, render_template, request, jsonify, send_file
from scanner import SecurityScanner
from report import ReportGenerator

# ─────────────────────────────────────────────
# App
# ─────────────────────────────────────────────
app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("scanner.log", mode="a"),
    ],
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _validate_url(url: str) -> str | None:
    """Return an error string if the URL is invalid, else None."""
    if not url:
        return "No URL provided."
    if not url.startswith(("http://", "https://")):
        return "URL must start with http:// or https://"
    return None


def _run_scan(url: str, crawl: bool) -> tuple[dict, SecurityScanner]:
    """Run the scanner and return (report_data, scanner_instance)."""
    scanner = SecurityScanner(url, crawl=crawl)
    results = scanner.run_all_checks()
    report  = ReportGenerator(url, results, scanner.scan_meta)
    return report.generate(), scanner


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    """Health-check endpoint for Docker / load balancers."""
    return jsonify({"status": "ok", "version": "2.0.0"})


@app.route("/scan", methods=["POST"])
def scan():
    """
    POST /scan
    Body: { "url": "https://...", "crawl": true/false }
    Returns: structured JSON vulnerability report
    """
    data       = request.get_json(silent=True) or {}
    target_url = data.get("url", "").strip()
    crawl      = bool(data.get("crawl", False))

    err = _validate_url(target_url)
    if err:
        return jsonify({"error": err}), 400

    logger.info("Scan requested: %s (crawl=%s)", target_url, crawl)
    report_data, _ = _run_scan(target_url, crawl)
    return jsonify(report_data)


@app.route("/export/json", methods=["POST"])
def export_json():
    """POST /export/json — downloadable JSON report."""
    data       = request.get_json(silent=True) or {}
    target_url = data.get("url", "").strip()
    crawl      = bool(data.get("crawl", False))

    err = _validate_url(target_url)
    if err:
        return jsonify({"error": err}), 400

    report_data, _ = _run_scan(target_url, crawl)
    filename = f"owasp_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"

    buf = io.BytesIO(json.dumps(report_data, indent=2).encode())
    buf.seek(0)
    return send_file(
        buf, mimetype="application/json",
        as_attachment=True, download_name=filename,
    )


@app.route("/export/pdf", methods=["POST"])
def export_pdf():
    """
    POST /export/pdf — downloadable PDF report  (Upgrade 5)
    Generates a professional PDF using ReportLab if available,
    falls back to a well-formatted HTML→text report otherwise.
    """
    data       = request.get_json(silent=True) or {}
    target_url = data.get("url", "").strip()
    crawl      = bool(data.get("crawl", False))

    err = _validate_url(target_url)
    if err:
        return jsonify({"error": err}), 400

    report_data, _ = _run_scan(target_url, crawl)
    filename = f"owasp_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"

    try:
        from report import build_pdf
        pdf_bytes = build_pdf(report_data)
        buf = io.BytesIO(pdf_bytes)
        buf.seek(0)
        return send_file(buf, mimetype="application/pdf",
                         as_attachment=True, download_name=filename)
    except ImportError:
        # ReportLab not installed — send a plain-text fallback
        from report import build_text_report
        text = build_text_report(report_data)
        buf = io.BytesIO(text.encode())
        buf.seek(0)
        return send_file(buf, mimetype="text/plain",
                         as_attachment=True,
                         download_name=filename.replace(".pdf", ".txt"))


# Legacy alias kept for backward compat
@app.route("/export", methods=["POST"])
def export_legacy():
    return export_json()


# ─────────────────────────────────────────────
# Entry point (dev only — use gunicorn in prod)
# ─────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
