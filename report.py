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


class ReportGenerator:
    """Builds a structured report dictionary from raw scanner results."""

    def __init__(self, target_url: str, results: list[dict], scan_meta: dict = None):
        self.target_url   = target_url
        self.results      = results
        self.scan_meta    = scan_meta or {}
        self.generated_at = datetime.now(timezone.utc).isoformat()

    def generate(self) -> dict:
        summary = self._build_summary()
        sorted_results = sorted(
            self.results,
            key=lambda r: SEVERITY_ORDER.get(r.get("severity", "Unknown"), 99),
        )

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
            },
            "scan_performance": {
                "duration_seconds": self.scan_meta.get("scan_duration_seconds", 0),
                "pages_crawled":    self.scan_meta.get("pages_crawled", 1),
                "threads_used":     self.scan_meta.get("threads_used", 1),
                "checks_run":       self.scan_meta.get("checks_run", len(self.results)),
                "pages":            self.scan_meta.get("pages", []),
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

    def _build_summary(self) -> dict:
        total    = len(self.results)
        detected = [r for r in self.results if r.get("detected")]
        passed   = [r for r in self.results if not r.get("detected")]

        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
        for r in self.results:
            sev = r.get("severity", "None")
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            "total_checks":              total,
            "vulnerabilities_detected":  len(detected),
            "passed":                    len(passed),
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
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
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

    story = []
    meta    = report_data["meta"]
    summary = report_data["summary"]
    perf    = report_data["scan_performance"]

    # ── Cover ───────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("🛡 OWASP Security Scan Report", title_style))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width="100%", thickness=2, color=accent))
    story.append(Spacer(1, 0.5*cm))

    meta_rows = [
        ["Target URL", meta["target"]],
        ["Generated",  meta["generated_at"]],
        ["Tool",       f"{meta['tool']} v{meta['version']}"],
        ["Overall Risk", summary["overall_risk"]],
        ["Pages Crawled", str(perf["pages_crawled"])],
        ["Scan Duration", f"{perf['duration_seconds']}s"],
        ["Threads Used", str(perf["threads_used"])],
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
        ["Checks Run", "Detected", "Passed", "Critical", "High", "Medium", "Low"],
        [
            str(summary["total_checks"]),
            str(summary["vulnerabilities_detected"]),
            str(summary["passed"]),
            str(sev.get("Critical", 0)),
            str(sev.get("High", 0)),
            str(sev.get("Medium", 0)),
            str(sev.get("Low", 0)),
        ],
    ]
    sev_table = Table(sev_rows, colWidths=[2.4*cm]*7)
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

    for r in report_data["results"]:
        sev_name  = r.get("severity", "None")
        sev_color = colors.HexColor(
            "#{:02x}{:02x}{:02x}".format(
                *[int(c * 255) for c in SEVERITY_COLORS_PDF.get(sev_name, (0.5,0.5,0.5))]
            )
        )

        # Finding header table
        header_data = [[
            Paragraph(f"<b>{r['name']}</b>", body_style),
            Paragraph(r["owasp"], body_style),
            Paragraph(f"<b>{sev_name}</b>", body_style),
            Paragraph(f"<b>{r['status']}</b>", body_style),
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
        for detail in r["details"]:
            story.append(Paragraph(f"  • {detail}", code_style))
        story.append(Spacer(1, 0.2*cm))

        # Recommendation
        rec_data = [[
            Paragraph("<b>Recommendation:</b>", body_style),
            Paragraph(r["recommendation"], body_style),
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

    # ── Disclaimer ────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        f"<i>{meta['disclaimer']}</i>",
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
        f"  Duration: {perf['duration_seconds']}s | Pages: {perf['pages_crawled']} | Threads: {perf['threads_used']}",
        border, "",
        "SUMMARY",
        "-" * 40,
        f"  Checks Run  : {summary['total_checks']}",
        f"  Detected    : {summary['vulnerabilities_detected']}",
        f"  Passed      : {summary['passed']}",
        f"  Critical    : {summary['severity_breakdown'].get('Critical', 0)}",
        f"  High        : {summary['severity_breakdown'].get('High', 0)}",
        f"  Medium      : {summary['severity_breakdown'].get('Medium', 0)}",
        "", "FINDINGS", "-" * 40,
    ]

    for r in report_data["results"]:
        status_mark = "⚠ DETECTED" if r["detected"] else "✔ NOT FOUND"
        lines += [
            "",
            f"  [{r['severity'].upper():8}] {r['name']}  —  {status_mark}",
            f"  OWASP: {r['owasp']}",
            "  Details:",
        ]
        for d in r["details"]:
            lines.append(f"    • {d}")
        lines += [
            "  Recommendation:",
            *textwrap.wrap(r["recommendation"], width=64, initial_indent="    ", subsequent_indent="    "),
        ]

    lines += ["", border, f"  {meta['disclaimer']}", border]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────

def _calculate_risk(counts: dict) -> str:
    if counts.get("Critical", 0) > 0: return "CRITICAL"
    if counts.get("High", 0) > 0:     return "HIGH"
    if counts.get("Medium", 0) > 0:   return "MEDIUM"
    if counts.get("Low", 0) > 0:      return "LOW"
    return "LOW"
