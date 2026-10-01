"""Render a Scan as a PDF report, using the same colors as the website.

Kept separate from views.py so the reportlab import only happens where it's needed --
nothing else in the project depends on this module.
"""
from __future__ import annotations

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Same palette as templates/base.html's :root custom properties, so the PDF matches the site.
INK = colors.HexColor("#1d2433")
MUTED = colors.HexColor("#5b6478")
BRAND = colors.HexColor("#2f5bea")
HIGH, HIGH_BG = colors.HexColor("#b42318"), colors.HexColor("#fee4e2")
MED, MED_BG = colors.HexColor("#b54708"), colors.HexColor("#fef0c7")
LOW, LOW_BG = colors.HexColor("#175cd3"), colors.HexColor("#d1e9ff")
SNIPPET_BG = colors.HexColor("#101828")
SNIPPET_INK = colors.HexColor("#e6edf7")

GRADE_COLORS = {
    "A": colors.HexColor("#12805c"), "B": colors.HexColor("#12805c"),
    "C": colors.HexColor("#c58a00"), "D": colors.HexColor("#d9691a"), "F": HIGH,
}
SEVERITY_COLORS = {"HIGH": (HIGH, HIGH_BG), "MEDIUM": (MED, MED_BG), "LOW": (LOW, LOW_BG)}

# A very large report can still take a while to lay out, so the PDF caps detailed
# per-issue entries here; the summary table above always covers every stored issue.
MAX_DETAILED_ISSUES = 500


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("ci_title", parent=base["Title"], textColor=INK, fontSize=20, spaceAfter=2),
        "meta": ParagraphStyle("ci_meta", parent=base["Normal"], textColor=MUTED, fontSize=10, spaceAfter=14),
        "h2": ParagraphStyle("ci_h2", parent=base["Heading2"], textColor=INK, spaceBefore=16, spaceAfter=8),
        "issue_title": ParagraphStyle("ci_issue_title", parent=base["Heading4"], textColor=INK,
                                       fontSize=11, spaceBefore=0, spaceAfter=2),
        "where": ParagraphStyle("ci_where", parent=base["Normal"], textColor=MUTED, fontSize=9, spaceAfter=4),
        "body": ParagraphStyle("ci_body", parent=base["Normal"], textColor=INK, fontSize=9.5, leading=13),
        "snippet": ParagraphStyle("ci_snippet", parent=base["Code"], textColor=SNIPPET_INK,
                                   backColor=SNIPPET_BG, fontSize=8.5, leading=11,
                                   leftIndent=6, rightIndent=6, spaceBefore=4, spaceAfter=4,
                                   borderPadding=6),
        "fix": ParagraphStyle("ci_fix", parent=base["Normal"], textColor=colors.HexColor("#0d5b3e"),
                               backColor=colors.HexColor("#eefaf3"), fontSize=9.5, leading=13,
                               leftIndent=6, rightIndent=6, borderPadding=6, spaceBefore=4),
        "note": ParagraphStyle("ci_note", parent=base["Normal"], textColor=MUTED, fontSize=9, spaceBefore=6),
    }


def _escape(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _summary_table(scan, styles):
    grade_color = GRADE_COLORS.get(scan.grade, INK)
    rows = [
        ["Score", "Grade", "High", "Medium", "Low", "Files scanned"],
        [
            f"{scan.score} / 100",
            scan.grade,
            str(scan.high_count),
            str(scan.medium_count),
            str(scan.low_count),
            str(scan.files_scanned),
        ],
    ]
    table = Table(rows, colWidths=[28 * mm, 20 * mm, 20 * mm, 24 * mm, 20 * mm, 32 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef0f6")),
        ("TEXTCOLOR", (0, 0), (-1, 0), MUTED),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 13),
        ("TEXTCOLOR", (1, 1), (1, 1), grade_color),
        ("TEXTCOLOR", (2, 1), (2, 1), HIGH),
        ("TEXTCOLOR", (3, 1), (3, 1), MED),
        ("TEXTCOLOR", (4, 1), (4, 1), LOW),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e3e7ef")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e3e7ef")),
    ]))
    return table


def _issue_block(issue, styles):
    sev_color, sev_bg = SEVERITY_COLORS.get(issue.severity, (INK, colors.whitesmoke))
    badge = Table(
        [[Paragraph(f"<b>{issue.get_severity_display().upper()}</b>", ParagraphStyle(
            "sev", fontSize=8, textColor=sev_color, alignment=1))]],
        colWidths=[22 * mm],
    )
    badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), sev_bg),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))

    flow = [
        badge,
        Spacer(1, 4),
        Paragraph(f"{_escape(issue.title)} <font color='#5b6478' size=8>[{_escape(issue.rule_id)}]</font>",
                   styles["issue_title"]),
        Paragraph(_escape(f"{issue.file_path}:{issue.line}  ·  {issue.category}"), styles["where"]),
    ]
    if issue.detail:
        flow.append(Paragraph(_escape(issue.detail), styles["body"]))
    if issue.snippet:
        flow.append(Paragraph(_escape(issue.snippet).replace("\n", "<br/>"), styles["snippet"]))
    if issue.fix:
        flow.append(Paragraph(f"<b>How to fix:</b> {_escape(issue.fix)}", styles["fix"]))
    flow.append(Spacer(1, 10))
    # KeepTogether stops a single finding being split across a page break where possible.
    return KeepTogether(flow)


def build_scan_pdf(scan) -> bytes:
    """Render `scan` (with its `issues` prefetched or not) as a PDF report and return the bytes."""
    styles = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=18 * mm, bottomMargin=16 * mm, leftMargin=18 * mm, rightMargin=18 * mm,
        title=f"Code Inspector report - {scan.name}",
    )

    story = [
        Paragraph(_escape(scan.name), styles["title"]),
        Paragraph(
            f"Code Inspector report  ·  generated {scan.created_at:%d %b %Y, %H:%M}  ·  "
            f"{scan.files_scanned} file{'s' if scan.files_scanned != 1 else ''} scanned",
            styles["meta"],
        ),
        _summary_table(scan, styles),
        Spacer(1, 4),
        HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e3e7ef"), spaceBefore=16, spaceAfter=0),
        Paragraph(f"Findings ({scan.total_issues})", styles["h2"]),
    ]

    issues = list(scan.issues.all())
    if not issues:
        story.append(Paragraph("No issues found. Nice work!", styles["body"]))
    else:
        for issue in issues[:MAX_DETAILED_ISSUES]:
            story.append(_issue_block(issue, styles))
        if len(issues) > MAX_DETAILED_ISSUES:
            story.append(Paragraph(
                f"...and {len(issues) - MAX_DETAILED_ISSUES} more findings. "
                "Download the JSON report from the scan page for the complete list.",
                styles["note"],
            ))
    if scan.issues_truncated:
        story.append(Paragraph(
            "This scan found a very large number of issues; only the first 2,000 were stored.",
            styles["note"],
        ))

    doc.build(story)
    return buf.getvalue()
