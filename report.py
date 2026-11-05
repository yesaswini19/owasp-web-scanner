"""
report.py - Report Generation Module (v2.0)
============================================
Upgrades over v1:
  ✦ Accepts scan_meta (timing, crawler pages, thread count)
  ✦ build_pdf()  — professional PDF via ReportLab  (Upgrade 5)
  ✦ build_text_report() — plain-text fallback
  ✦ Richer summary: duration, pages crawled, per-check timing
"""

import logging
import textwrap
from datetime import datetime, timezone
from xml.sax.saxutils import escape

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {
    "Critical": 0, "High": 1, "Medium": 2,
    "Low": 3, "None": 4, "Error": 5, "Unknown": 6,
}

SEVERITY_COLORS_PDF = {
    "Critical": (0.85, 0.11, 0.24),
    "High":     (0.95, 0.42, 0.14),
    "Medium":   (0.95, 0.78, 0.03),
    "Low":      (0.13, 0.55, 0.36),
    "None":     (0.40, 0.60, 0.65),
    "Error":    (0.50, 0.50, 0.50),
}

SUPPORTED_CATEGORIES = {
    "A01": "Broken Access Control (route-response heuristics)",
    "A02": "Cryptographic Failures (limited transport, cookie, and exposure indicators)",
    "A03": "Injection (SQL error signatures and inert marker reflection)",
    "A05": "Security Misconfiguration (selected headers and visible disclosures)",
    "A06": "Vulnerable and Outdated Components (visible fingerprints only)",
}
UNSUPPORTED_CATEGORIES = {
    "A04": "Insecure Design",
    "A07": "Identification and Authentication Failures (login-form discovery only; authentication strength is not assessed)",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}
REPORT_LIMITATIONS = [
    "Findings are heuristic indicators and require manual verification; response changes alone are not proof.",
    "A negative result does not establish that the target is secure. Coverage is limited to the checks listed in this report.",
    "Component fingerprints do not verify installed versions or map them to a confirmed vulnerability database.",
    "Authentication and access-control checks cannot verify authorization without suitable test accounts and application context.",
]


class ReportGenerator:
    """Builds a structured report dictionary from raw scanner results."""

    def __init__(self, target_url: str, results: list[dict], scan_meta: dict = None):
        self.target_url   = target_url
        self.results      = results if isinstance(results, list) else []
        self.scan_meta    = scan_meta or {}
        self.generated_at = datetime.now(timezone.utc).isoformat()

    def generate(self) -> dict:
        results = [self._normalize_result(result) for result in self.results]
        summary = self._build_summary(results)
        sorted_results = sorted(
            results,
            key=lambda r: SEVERITY_ORDER.get(r.get("severity", "Unknown"), 99),
        )
        pages = self.scan_meta.get("pages", [])
        pages = pages if isinstance(pages, list) else []
        pages_scanned = self.scan_meta.get("pages_crawled", len(pages) or 1)

        report = {
            "meta": {
                "tool":         "OWASP Top 10 Security Scanner",
                "version":      "2.0.0",
                "target":       self.target_url,
                "generated_at": self.generated_at,
                "disclaimer": (
                    "This tool is for educational and authorized testing only. "
                    "Do not scan systems without explicit written permission."
                ),
                "coverage": {
                    "supported_categories": SUPPORTED_CATEGORIES,
                    "unsupported_categories": UNSUPPORTED_CATEGORIES,
                },
                "limitations": REPORT_LIMITATIONS,
            },
            "scan_performance": {
                "duration_seconds": self.scan_meta.get("scan_duration_seconds", 0),
                "pages_crawled":    pages_scanned,
                "total_pages_scanned": pages_scanned,
                "threads_used":     self.scan_meta.get("threads_used", 1),
                "authentication_mode": self.scan_meta.get(
                    "authentication_mode", "unauthenticated"
                ),
                "authentication_mode_enabled": self.scan_meta.get(
                    "authentication_mode_enabled", False
                ),
                "login_session_establishment": self.scan_meta.get(
                    "login_session_establishment", "not_attempted"
                ),
                "protected_access_verified": self.scan_meta.get(
                    "protected_access_verified", False
                ),
                "protected_access_url": self.scan_meta.get(
                    "protected_access_url"
                ),
                "checks_run":       self.scan_meta.get("checks_run", len(results)),
                "total_checks_performed": self.scan_meta.get("checks_run", len(results)),
                "pages":            pages,
            },
            "summary": summary,
            "results": sorted_results,
        }

        logger.info(
            "Report generated — %d checks, %d detected, risk=%s, %.1fs",
            summary["total_checks"],
            summary["vulnerabilities_detected"],
            summary["overall_risk"],
            self.scan_meta.get("scan_duration_seconds", 0),
        )
        return report

    def _normalize_result(self, result: dict) -> dict:
        if not isinstance(result, dict):
            result = {}
        normalized = dict(result)
        detected = bool(normalized.get("detected", False))
        finding_type = normalized.get("finding_type")
        if finding_type not in ("confirmed", "possible", "error", "none", "unsupported", "partial"):
            finding_type = "possible" if detected else "none"
        severity = normalized.get("severity", "Unknown")
        details = normalized.get("details", [])
        evidence = normalized.get("evidence", [])
        affected_url = normalized.get("affected_url") or (self.target_url if detected else "")
        if not isinstance(details, list):
            details = [str(details)]
        if not isinstance(evidence, list):
            evidence = []
        description = normalized.get("description") or " ".join(str(item) for item in details)
        if detected and not evidence:
            evidence = [
                {"type": "check_detail", "description": str(detail), "url": affected_url}
                for detail in details
            ]
        normalized.update({
            "name": str(normalized.get("name", "Unknown check")),
            "owasp": str(normalized.get("owasp", "Unknown")),
            "detected": detected,
            "finding_type": finding_type,
            "status": normalized.get("status") if normalized.get("status") in (
                "NOT TESTED", "NOT ASSESSED", "PARTIALLY TESTED",
            ) else (
                "UNSUPPORTED" if finding_type == "unsupported" else
                "ERROR" if finding_type == "error" else
                "CONFIRMED FINDING" if finding_type == "confirmed" else
                "PARTIALLY TESTED" if finding_type == "partial" else
                "POSSIBLE FINDING" if detected else "NOT FOUND"
            ),
            "severity": str(severity),
            "description": str(description),
            "affected_url": str(affected_url),
            "details": details,
            "evidence": evidence,
            "recommendation": str(normalized.get("recommendation", "Review the application manually.")),
        })
        if finding_type == "error":
            normalized["details"] = ["This check could not be completed; consult server logs."]
            normalized["description"] = normalized["details"][0]
            normalized["evidence"] = []
            normalized["recommendation"] = "Verify the target is reachable and review server logs."
        return normalized

    def _build_summary(self, results: list[dict]) -> dict:
        total = len(results)
        detected = [r for r in results if r.get("detected")]
        confirmed = [r for r in detected if r.get("finding_type") == "confirmed"]
        possible = [r for r in detected if r.get("finding_type") == "possible"]
        errors = [r for r in results if r.get("finding_type") == "error"]
        unsupported = [r for r in results if r.get("finding_type") == "unsupported"]
        partially_tested = [r for r in results if r.get("finding_type") == "partial"]
        passed = [r for r in results if r.get("finding_type") == "none"]

        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
        for r in detected:
            sev = r.get("severity", "None")
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            "total_checks":              total,
            "vulnerabilities_detected":  len(detected),
            "passed":                    len(passed),
            "possible_findings":         len(possible),
            "confirmed_findings":        len(confirmed),
            "checks_with_errors":        len(errors),
            "unsupported_checks":       len(unsupported),
            "partially_tested_checks":  len(partially_tested),
            "overall_risk":              _calculate_risk(severity_counts),
            "severity_breakdown":        severity_counts,
            "detected_names":            [r["name"] for r in detected],
        }


# ─────────────────────────────────────────────────────────
# PDF Report (Upgrade 5)
# ─────────────────────────────────────────────────────────

def build_pdf(report_data: dict) -> bytes:
    """
    Generate a professional PDF report using ReportLab.
    Raises ImportError if reportlab is not installed (caller handles fallback).
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak,
    )
    from reportlab.lib.enums import TA_CENTER
    import io

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )

    styles = getSampleStyleSheet()
    dark_blue = colors.HexColor("#0b1a2e")
    accent    = colors.HexColor("#00d4ff")
    light_bg  = colors.HexColor("#f0f4f8")

    # Custom styles
    title_style = ParagraphStyle(
        "Title", parent=styles["Title"],
        fontSize=22, textColor=accent,
        spaceAfter=4, alignment=TA_CENTER,
        fontName="Helvetica-Bold",
    )
    h1_style = ParagraphStyle(
        "H1", parent=styles["Heading1"],
        fontSize=14, textColor=dark_blue,
        spaceBefore=14, spaceAfter=6,
        fontName="Helvetica-Bold",
        borderPad=4,
    )
    h2_style = ParagraphStyle(
        "H2", parent=styles["Heading2"],
        fontSize=11, textColor=dark_blue,
        spaceBefore=10, spaceAfter=4,
        fontName="Helvetica-Bold",
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontSize=9, leading=13, spaceAfter=2,
    )
    code_style = ParagraphStyle(
        "Code", parent=styles["Code"],
        fontSize=8, leading=11, leftIndent=10,
        fontName="Courier",
    )

    def pdf_text(value) -> str:
        return escape(str(value)).replace("\r\n", "\n").replace("\n", "<br/>")

    story = []
    meta    = report_data["meta"]
    summary = report_data["summary"]
    perf    = report_data["scan_performance"]

    # ── Cover ───────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("OWASP Security Scan Report", title_style))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width="100%", thickness=2, color=accent))
    story.append(Spacer(1, 0.5*cm))

    meta_rows = [
        ["Target URL", meta["target"]],
        ["Generated",  meta["generated_at"]],
        ["Tool",       f"{meta['tool']} v{meta['version']}"],
        ["Overall Risk", summary["overall_risk"]],
        ["Pages Crawled", str(perf["pages_crawled"])],
        ["Checks Performed", str(perf.get("total_checks_performed", perf.get("checks_run", 0)))],
        ["Scan Duration", f"{perf['duration_seconds']}s"],
        ["Authentication Mode", "Enabled" if perf.get("authentication_mode_enabled") else "Disabled"],
        ["Login / Session", str(perf.get("login_session_establishment", "not_attempted")).replace("_", " ").title()],
        ["Protected Access", (
            f"Verified: {perf.get('protected_access_url')}"
            if perf.get("protected_access_verified") else "Not verified"
        )],
    ]
    meta_table = Table(meta_rows, colWidths=[4*cm, 13*cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), light_bg),
        ("FONTNAME",   (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 9),
        ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#c8d8e8")),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.white, light_bg]),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("PADDING",    (0,0), (-1,-1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.8*cm))

    # ── Summary table ────────────────────────────────
    story.append(Paragraph("Executive Summary", h1_style))
    sev = summary["severity_breakdown"]
    sev_rows = [
        ["Checks", "Possible", "Confirmed", "Errors", "Not tested", "Partial", "Critical", "High", "Medium", "Low"],
        [
            str(summary["total_checks"]),
            str(summary.get("possible_findings", summary["vulnerabilities_detected"])),
            str(summary.get("confirmed_findings", 0)),
            str(summary.get("checks_with_errors", 0)),
            str(summary.get("unsupported_checks", 0)),
            str(summary.get("partially_tested_checks", 0)),
            str(sev.get("Critical", 0)),
            str(sev.get("High", 0)),
            str(sev.get("Medium", 0)),
            str(sev.get("Low", 0)),
        ],
    ]
    sev_table = Table(sev_rows, colWidths=[1.7*cm]*10)
    sev_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), dark_blue),
        ("TEXTCOLOR",   (0,0), (-1,0), colors.white),
        ("FONTNAME",    (0,0), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("ALIGN",       (0,0), (-1,-1), "CENTER"),
        ("GRID",        (0,0), (-1,-1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (1,0), (-1,-1), [colors.white, light_bg]),
        ("PADDING",     (0,0), (-1,-1), 7),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 0.8*cm))

    # ── Findings ─────────────────────────────────────
    story.append(Paragraph("Detailed Findings", h1_style))

    if not report_data["results"]:
        story.append(Paragraph("No checks returned results.", body_style))

    for r in report_data["results"]:
        sev_name  = r.get("severity", "None")
        sev_color = colors.HexColor(
            "#{:02x}{:02x}{:02x}".format(
                *[int(c * 255) for c in SEVERITY_COLORS_PDF.get(sev_name, (0.5,0.5,0.5))]
            )
        )

        # Finding header table
        header_data = [[
            Paragraph(f"<b>{pdf_text(r['name'])}</b>", body_style),
            Paragraph(pdf_text(r["owasp"]), body_style),
            Paragraph(f"<b>{pdf_text(sev_name)}</b>", body_style),
            Paragraph(f"<b>{pdf_text(r['status'])}</b>", body_style),
        ]]
        hdr_table = Table(header_data, colWidths=[6*cm, 6*cm, 2*cm, 3*cm])
        hdr_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), dark_blue if r["detected"] else light_bg),
            ("TEXTCOLOR",  (0,0), (-1,-1), colors.white if r["detected"] else dark_blue),
            ("FONTSIZE",   (0,0), (-1,-1), 9),
            ("GRID",       (0,0), (-1,-1), 0.5, colors.grey),
            ("PADDING",    (0,0), (-1,-1), 6),
            ("LEFTPADDING",(2,0),(3,0), 8),
        ]))
        story.append(hdr_table)

        # Details
        if r.get("affected_url"):
            story.append(Paragraph(
                f"<b>Affected URL:</b> {pdf_text(r['affected_url'])}", body_style
            ))
        if r.get("description"):
            story.append(Paragraph(
                f"<b>Description:</b> {pdf_text(r['description'])}", body_style
            ))
        if " ".join(str(item) for item in r["details"]) != r.get("description", ""):
            for detail in r["details"]:
                story.append(Paragraph(f"- {pdf_text(detail)}", code_style))
        for evidence in r.get("evidence", []):
            if not isinstance(evidence, dict):
                continue
            evidence_text = evidence.get("description", "")
            evidence_url = evidence.get("url", "")
            if evidence_text or evidence_url:
                story.append(Paragraph(
                    f"<b>Evidence:</b> {pdf_text(evidence_text)}"
                    + (f"<br/><b>Evidence URL:</b> {pdf_text(evidence_url)}" if evidence_url else ""),
                    body_style,
                ))
            for label, value in _evidence_metadata(evidence):
                story.append(Paragraph(
                    f"<b>{pdf_text(label)}:</b> {pdf_text(value)}", body_style,
                ))
        story.append(Spacer(1, 0.2*cm))

        # Recommendation
        rec_data = [[
            Paragraph("<b>Recommendation:</b>", body_style),
            Paragraph(pdf_text(r["recommendation"]), body_style),
        ]]
        rec_table = Table(rec_data, colWidths=[3.5*cm, 13.5*cm])
        rec_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#e8f4fd")),
            ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#c8d8e8")),
            ("PADDING",    (0,0), (-1,-1), 6),
            ("FONTSIZE",   (0,0), (-1,-1), 8),
            ("VALIGN",     (0,0), (-1,-1), "TOP"),
        ]))
        story.append(rec_table)
        story.append(Spacer(1, 0.5*cm))

    # ── Crawled pages ─────────────────────────────────
    pages = perf.get("pages", [])
    if pages:
        story.append(PageBreak())
        story.append(Paragraph("Crawled Pages", h1_style))
        page_rows = [["URL", "Status", "Forms", "Load Time"]]
        for p in pages:
            page_rows.append([
                p.get("url", "")[:60],
                str(p.get("status", "")),
                str(p.get("form_count", "")),
                f"{p.get('elapsed', '')}s",
            ])
        pg_table = Table(page_rows, colWidths=[11*cm, 1.8*cm, 1.8*cm, 2.4*cm])
        pg_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), dark_blue),
            ("TEXTCOLOR",     (0,0), (-1,0), colors.white),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 8),
            ("GRID",          (0,0), (-1,-1), 0.3, colors.grey),
            ("ROWBACKGROUNDS",(1,0), (-1,-1), [colors.white, light_bg]),
            ("PADDING",       (0,0), (-1,-1), 5),
        ]))
        story.append(pg_table)
        for page in pages:
            for form in page.get("forms", []):
                story.append(Paragraph(
                    f"<b>Form on {pdf_text(page.get('url', ''))}:</b> "
                    f"{pdf_text(form.get('method', ''))} "
                    f"{pdf_text(form.get('action', ''))}; "
                    f"<b>Fields:</b> {pdf_text(_form_fields_text(form) or 'none')}",
                    body_style,
                ))

    story.append(Paragraph("Coverage and Limitations", h1_style))
    coverage = meta.get("coverage", {})
    for code, description in coverage.get("supported_categories", {}).items():
        story.append(Paragraph(
            f"<b>{pdf_text(code)}</b> - {pdf_text(description)}", body_style
        ))
    for code, description in coverage.get("unsupported_categories", {}).items():
        story.append(Paragraph(
            f"<b>{pdf_text(code)}</b> - Unsupported: {pdf_text(description)}", body_style
        ))
    for limitation in meta.get("limitations", REPORT_LIMITATIONS):
        story.append(Paragraph(f"- {pdf_text(limitation)}", body_style))

    # ── Disclaimer ────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        f"<i>{pdf_text(meta['disclaimer'])}</i>",
        ParagraphStyle("Disc", parent=styles["Normal"], fontSize=7,
                       textColor=colors.grey, alignment=TA_CENTER)
    ))

    doc.build(story)
    return buf.getvalue()


# ─────────────────────────────────────────────────────────
# Plain-text report (PDF fallback)
# ─────────────────────────────────────────────────────────

def build_text_report(report_data: dict) -> str:
    """Generate a formatted plain-text report (fallback when ReportLab is absent)."""
    lines = []
    meta    = report_data["meta"]
    summary = report_data["summary"]
    perf    = report_data["scan_performance"]

    border = "=" * 70
    lines += [
        border,
        "  OWASP TOP 10 SECURITY SCAN REPORT",
        border,
        f"  Target  : {meta['target']}",
        f"  Date    : {meta['generated_at']}",
        f"  Risk    : {summary['overall_risk']}",
        f"  Duration: {perf['duration_seconds']}s | Pages: {perf['pages_crawled']} | Checks: {perf.get('total_checks_performed', perf.get('checks_run', 0))}",
        f"  Authentication mode enabled: {'yes' if perf.get('authentication_mode_enabled') else 'no'}",
        f"  Login/session establishment: {perf.get('login_session_establishment', 'not_attempted')}",
        (
            f"  Protected access verified: {perf.get('protected_access_url')}"
            if perf.get("protected_access_verified")
            else "  Protected access verified: no"
        ),
        border, "",
        "SUMMARY",
        "-" * 40,
        f"  Checks Run  : {summary['total_checks']}",
        f"  Detected    : {summary['vulnerabilities_detected']}",
        f"  Possible    : {summary.get('possible_findings', summary['vulnerabilities_detected'])}",
        f"  Confirmed   : {summary.get('confirmed_findings', 0)}",
        f"  Errors      : {summary.get('checks_with_errors', 0)}",
        f"  Not tested  : {summary.get('unsupported_checks', 0)}",
        f"  Partly tested: {summary.get('partially_tested_checks', 0)}",
        f"  Passed      : {summary['passed']}",
        f"  Critical    : {summary['severity_breakdown'].get('Critical', 0)}",
        f"  High        : {summary['severity_breakdown'].get('High', 0)}",
        f"  Medium      : {summary['severity_breakdown'].get('Medium', 0)}",
        "", "FINDINGS", "-" * 40,
    ]

    if not report_data["results"]:
        lines.append("  No checks returned results.")

    for page in perf.get("pages", []):
        for form in page.get("forms", []):
            lines.append(
                f"  Form on {page.get('url', '')}: {form.get('method', '')} "
                f"{form.get('action', '')}; fields: {_form_fields_text(form) or 'none'}"
            )

    for r in report_data["results"]:
        status_mark = r.get("status", "NOT FOUND")
        lines += [
            "",
            f"  [{r['severity'].upper():8}] {r['name']}  -  {status_mark}",
            f"  OWASP: {r['owasp']}",
            f"  Affected URL: {r.get('affected_url') or 'N/A'}",
            f"  Description: {r.get('description', '')}",
        ]
        if " ".join(str(item) for item in r["details"]) != r.get("description", ""):
            lines.extend(f"    - {item}" for item in r["details"])
        for item in r.get("evidence", []):
            if isinstance(item, dict):
                lines.append(f"    Evidence: {item.get('description', '')}")
                if item.get("url"):
                    lines.append(f"    Evidence URL: {item['url']}")
                lines.extend(
                    f"    {label}: {value}"
                    for label, value in _evidence_metadata(item)
                )
        lines += [
            "  Recommendation:",
            *textwrap.wrap(r["recommendation"], width=64, initial_indent="    ", subsequent_indent="    "),
        ]

    lines += ["", "COVERAGE AND LIMITATIONS", "-" * 40]
    coverage = meta.get("coverage", {})
    for code, description in coverage.get("supported_categories", {}).items():
        lines.append(f"  {code}: {description}")
    for code, description in coverage.get("unsupported_categories", {}).items():
        lines.append(f"  {code}: Unsupported - {description}")
    lines.extend(f"  - {item}" for item in meta.get("limitations", REPORT_LIMITATIONS))
    lines += ["", border, f"  {meta['disclaimer']}", border]
    return "\n".join(lines)


def _evidence_metadata(evidence: dict) -> list[tuple[str, str]]:
    """Render only known, non-secret evidence metadata fields."""
    rendered = []
    for key, label in (
        ("page_url", "Page URL"),
        ("form_action", "Form action"),
        ("method", "Method"),
        ("parameter", "Parameter"),
        ("field_names", "Field names"),
        ("cookie_name", "Cookie name"),
    ):
        value = evidence.get(key)
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value)
        if value not in (None, ""):
            rendered.append((label, str(value)))
    return rendered


def _form_fields_text(form: dict) -> str:
    """Format form field names and types without including field values."""
    formatted = []
    for field in form.get("fields", []):
        name = field.get("name")
        if not name:
            continue
        if field.get("is_password"):
            formatted.append(f"{name} (password field)")
        else:
            formatted.append(f"{name} ({field.get('type', 'unknown')})")
    return ", ".join(formatted)


# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────

def _calculate_risk(counts: dict) -> str:
    if counts.get("Critical", 0) > 0: return "CRITICAL"
    if counts.get("High", 0) > 0:     return "HIGH"
    if counts.get("Medium", 0) > 0:   return "MEDIUM"
    if counts.get("Low", 0) > 0:      return "LOW"
    return "LOW"
