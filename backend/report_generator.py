"""
report_generator.py — PDF Incident Report generator for SOC Lab
Generates professional incident reports using ReportLab.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from ioc_extractor import enrich_iocs, ioc_summary_text
from mitre_mapper import map_alert_to_technique

BASE_DIR    = Path(__file__).parent
REPORTS_DIR = BASE_DIR.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# ─── Color Scheme ─────────────────────────────────────────────────────────────

SOC_DARK      = colors.HexColor("#0a0f1e")
SOC_BLUE      = colors.HexColor("#00d4ff")
SOC_ACCENT    = colors.HexColor("#1a2744")
SOC_WHITE     = colors.white
SOC_GRAY      = colors.HexColor("#8892a4")
SOC_RED       = colors.HexColor("#ff3366")
SOC_ORANGE    = colors.HexColor("#ff8c42")
SOC_YELLOW    = colors.HexColor("#ffd700")
SOC_GREEN     = colors.HexColor("#00ff88")

SEVERITY_COLORS = {
    "Critical": SOC_RED,
    "High":     SOC_ORANGE,
    "Medium":   SOC_YELLOW,
    "Low":      SOC_GREEN,
}


def _severity_color(severity: str):
    return SEVERITY_COLORS.get(severity, SOC_GRAY)


def generate_pdf_report(
    alert: Dict[str, Any],
    events: List[Dict[str, Any]],
    analyst_name: str = "SOC Analyst L1",
    report_title: str = ""
) -> str:
    """
    Generate a full PDF incident report for an alert.
    report_title: user-supplied name shown on cover page and used for the saved filename.
    Returns the path to the generated PDF file.
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError("ReportLab not installed. Run: pip install reportlab")

    # Extract IOCs and MITRE data
    ioc_report    = enrich_iocs(events)
    mitre_context = map_alert_to_technique(alert)
    iocs_parsed   = json.loads(alert.get("iocs", "{}")) if isinstance(alert.get("iocs"), str) else alert.get("iocs", {})

    # File naming — use report_title if provided, else derive from rule name
    import re as _re
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    severity = alert.get("severity", "Unknown")
    if report_title:
        safe_name = _re.sub(r"[^\w\-]", "_", report_title)
        safe_name = _re.sub(r"_+", "_", safe_name).strip("_")
        filename  = f"{safe_name}.pdf"
    else:
        safe_name = alert.get("rule_name", "Incident").replace(" ", "_").replace("/", "-")
        filename  = f"INC_{ts}_{severity}_{safe_name}.pdf"
    filepath = REPORTS_DIR / filename

    # Cover page display title
    cover_title = report_title or alert.get("rule_name", "Security Incident")


    # ─── Document setup ──────────────────────────────────────────────────────
    doc = SimpleDocTemplate(
        str(filepath),
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm,
    )

    styles  = getSampleStyleSheet()
    story   = []

    # Custom styles
    title_style = ParagraphStyle(
        "SOCTitle",
        parent=styles["Heading1"],
        fontSize=22,
        textColor=SOC_DARK,
        spaceAfter=6,
        fontName="Helvetica-Bold",
    )
    subtitle_style = ParagraphStyle(
        "SOCSubtitle",
        parent=styles["Normal"],
        fontSize=11,
        textColor=SOC_GRAY,
        spaceAfter=4,
        fontName="Helvetica",
    )
    section_style = ParagraphStyle(
        "SOCSection",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=SOC_DARK,
        spaceBefore=14,
        spaceAfter=6,
        fontName="Helvetica-Bold",
        borderPad=4,
    )
    body_style = ParagraphStyle(
        "SOCBody",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#2c3e50"),
        spaceAfter=4,
        fontName="Helvetica",
        leading=14,
    )
    code_style = ParagraphStyle(
        "SOCCode",
        parent=styles["Normal"],
        fontSize=7.5,
        textColor=colors.HexColor("#1a1a2e"),
        spaceAfter=2,
        fontName="Courier",
        backColor=colors.HexColor("#f0f2f5"),
        borderPad=6,
        leading=11,
    )
    bold_style = ParagraphStyle(
        "SOCBold",
        parent=body_style,
        fontName="Helvetica-Bold",
        fontSize=9,
    )

    # ─── COVER PAGE ──────────────────────────────────────────────────────────

    # Header bar
    header_data = [[
        Paragraph("<font color='white'><b>SOC INCIDENT REPORT</b></font>", ParagraphStyle(
            "H", fontSize=16, textColor=SOC_WHITE, fontName="Helvetica-Bold"
        )),
        Paragraph(f"<font color='#00d4ff'>SEVERITY: {severity.upper()}</font>", ParagraphStyle(
            "S", fontSize=14, textColor=SOC_BLUE, fontName="Helvetica-Bold", alignment=TA_RIGHT
        )),
    ]]
    header_table = Table(header_data, colWidths=[11*cm, 6*cm])
    header_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), SOC_DARK),
        ("TEXTCOLOR",    (0, 0), (-1, -1), SOC_WHITE),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [SOC_DARK]),
        ("TOPPADDING",   (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 14),
        ("LEFTPADDING",  (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("GRID",         (0, 0), (-1, -1), 0, SOC_DARK),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 0.4*cm))

    # Incident title — displays the user's chosen report name
    story.append(Paragraph(cover_title, title_style))
    story.append(Paragraph(
        f"Incident ID: <b>INC-{ts}</b>  |  "
        f"Generated: <b>{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</b>  |  "
        f"Analyst: <b>{analyst_name}</b>",
        subtitle_style
    ))
    story.append(HRFlowable(width="100%", thickness=2, color=SOC_BLUE, spaceAfter=10))

    # ─── EXECUTIVE SUMMARY ───────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", section_style))

    summary_data = [
        ["Incident ID",        f"INC-{ts}"],
        ["Alert Title",        alert.get("rule_name", "N/A")],
        ["Severity",           severity],
        ["Status",             alert.get("status", "Open")],
        ["Detection Time",     alert.get("created_at", "N/A")],
        ["Affected Host",      alert.get("hostname", "N/A")],
        ["Affected User",      alert.get("user", "N/A")],
        ["Source IP",          alert.get("source_ip", "N/A")],
        ["MITRE Technique",    f"{mitre_context['technique_id']} — {mitre_context['technique_name']}"],
        ["MITRE Tactic",       mitre_context.get("tactic", "N/A")],
        ["Detection Rule",     alert.get("rule_id", "N/A")],
        ["Analyst",            analyst_name],
    ]

    summary_table = Table(summary_data, colWidths=[5*cm, 12*cm])
    sev_color = _severity_color(severity)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (0, -1), colors.HexColor("#eef1f7")),
        ("BACKGROUND",   (0, 2), (1, 2),  colors.HexColor("#fff3cd") if severity == "Medium" else colors.HexColor("#fde8ec") if severity in ("Critical","High") else colors.HexColor("#d4edda")),
        ("FONTNAME",     (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",     (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",     (0, 0), (-1, -1), 9),
        ("TEXTCOLOR",    (0, 0), (-1, -1), colors.HexColor("#2c3e50")),
        ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
        ("ROWBACKGROUNDS",(0,0),(-1,-1), [colors.white, colors.HexColor("#f8f9fa")]),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.3*cm))

    # Outcome description
    story.append(Paragraph(
        f"<b>Incident Summary:</b> {alert.get('summary', 'No summary available.')}",
        body_style
    ))
    story.append(Spacer(1, 0.3*cm))

    # ─── MITRE ATT&CK CONTEXT ────────────────────────────────────────────────
    story.append(Paragraph("MITRE ATT&CK Framework Mapping", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dee2e6"), spaceAfter=8))

    mitre_info = [
        ["Technique ID",  mitre_context.get("technique_id", "N/A")],
        ["Technique Name",mitre_context.get("technique_name", "N/A")],
        ["Tactic",        mitre_context.get("tactic", "N/A")],
        ["Platforms",     ", ".join(mitre_context.get("platforms", []))],
        ["Data Sources",  ", ".join(mitre_context.get("data_sources", []))],
        ["Reference",     mitre_context.get("mitre_url", "")],
    ]
    mitre_table = Table(mitre_info, colWidths=[5*cm, 12*cm])
    mitre_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, -1), colors.HexColor("#e8f4f8")),
        ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",      (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("TEXTCOLOR",     (1, 5), (1, 5), colors.HexColor("#0066cc")),
        ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    story.append(mitre_table)
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(f"<b>Description:</b> {mitre_context.get('description', '')}", body_style))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(f"<b>Detection Guidance:</b> {mitre_context.get('detection', '')}", body_style))

    # ─── EVENT TIMELINE ──────────────────────────────────────────────────────
    story.append(Paragraph("Event Timeline", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dee2e6"), spaceAfter=8))

    timeline_headers = [["#", "Timestamp", "Source", "Event ID", "Type", "User / IP"]]
    timeline_rows = []
    for i, event in enumerate(events[:20], 1):
        timeline_rows.append([
            str(i),
            event.get("timestamp", "")[:19].replace("T", " "),
            event.get("log_source", ""),
            event.get("event_id", ""),
            event.get("event_type", ""),
            f"{event.get('user','?')} / {event.get('source_ip','?')}",
        ])

    if len(events) > 20:
        timeline_rows.append(["...", f"...and {len(events)-20} more events", "", "", "", ""])

    timeline_data = timeline_headers + timeline_rows
    timeline_table = Table(
        timeline_data,
        colWidths=[0.8*cm, 3.8*cm, 2.8*cm, 2*cm, 3.5*cm, 4.1*cm],
        repeatRows=1
    )
    timeline_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  SOC_DARK),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  SOC_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
        ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#dee2e6")),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("ALIGN",         (0, 0), (0, -1),  "CENTER"),
    ]))
    story.append(timeline_table)

    # ─── IOC INVENTORY ───────────────────────────────────────────────────────
    story.append(Paragraph("Indicators of Compromise (IOCs)", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dee2e6"), spaceAfter=8))

    ioc_rows = []
    for ip in ioc_report.get("external_ips", []):
        ioc_rows.append(["IP Address (External)", ip, "HIGH", "Block at firewall"])
    for ip in ioc_report.get("internal_ips", []):
        ioc_rows.append(["IP Address (Internal)", ip, "MEDIUM", "Investigate host"])
    for h in ioc_report.get("file_hashes", []):
        ioc_rows.append(["File Hash (MD5)", h, "HIGH", "Quarantine file"])
    for domain, info in ioc_report.get("domains", {}).items():
        ioc_rows.append(["Domain", domain, info["verdict"], "Block DNS / notify team"])
    for user in ioc_report.get("usernames", []):
        ioc_rows.append(["Username", user, "MEDIUM", "Reset credentials / review access"])
    for proc, reason in ioc_report.get("flagged_processes", {}).items():
        ioc_rows.append(["Process", proc, "HIGH", reason])
    for key in ioc_report.get("registry_keys", []):
        ioc_rows.append(["Registry Key", key, "HIGH", "Remove and investigate"])

    if not ioc_rows:
        ioc_rows = [["No IOCs", "No high-confidence IOCs extracted", "", ""]]

    ioc_headers = [["IOC Type", "Value", "Verdict", "Recommended Action"]]
    ioc_data    = ioc_headers + ioc_rows[:25]
    ioc_table   = Table(ioc_data, colWidths=[3.5*cm, 6.5*cm, 2.5*cm, 4.5*cm], repeatRows=1)
    ioc_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  SOC_DARK),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  SOC_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
        ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#dee2e6")),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("WORDWRAP",      (0, 0), (-1, -1), True),
    ]))
    story.append(ioc_table)

    # ─── RECOMMENDED REMEDIATION ─────────────────────────────────────────────
    story.append(Paragraph("Recommended Remediation Steps", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dee2e6"), spaceAfter=8))

    remediation = mitre_context.get("remediation", [])
    if remediation:
        for i, step in enumerate(remediation, 1):
            story.append(Paragraph(f"<b>{i}.</b> {step}", body_style))
    else:
        story.append(Paragraph("Review logs and escalate to senior analyst.", body_style))

    # ─── RAW LOG APPENDIX ────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Appendix A — Raw Log Evidence", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dee2e6"), spaceAfter=8))
    story.append(Paragraph(
        "The following raw log entries were collected during the incident and used for detection:",
        body_style
    ))
    story.append(Spacer(1, 0.2*cm))

    for i, event in enumerate(events[:15], 1):
        raw = event.get("raw_log", "No raw log available")
        story.append(Paragraph(f"<b>Event #{i} — {event.get('event_type','?')} ({event.get('log_source','?')} Event {event.get('event_id','?')})</b>", bold_style))
        # Wrap long lines
        chunks = [raw[j:j+120] for j in range(0, min(len(raw), 480), 120)]
        for chunk in chunks:
            story.append(Paragraph(chunk, code_style))
        story.append(Spacer(1, 0.15*cm))

    # ─── Footer note ─────────────────────────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dee2e6")))
    story.append(Paragraph(
        f"<i>This report was generated by the SOC Monitoring & Incident Detection Lab | "
        f"Classification: INTERNAL USE ONLY | Analyst: {analyst_name} | "
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</i>",
        ParagraphStyle("footer", fontSize=7, textColor=SOC_GRAY, fontName="Helvetica-Oblique")
    ))

    # Build PDF
    doc.build(story)
    return str(filepath)


if __name__ == "__main__":
    # Quick test with dummy data
    from log_simulator import simulate_brute_force
    from detection_engine import init_db, process_scenario

    init_db()
    events, summary = simulate_brute_force(10)
    alert = process_scenario(events, summary)
    if alert:
        if isinstance(alert.get("iocs"), str):
            pass
        pdf_path = generate_pdf_report(alert, events)
        print(f"Report generated: {pdf_path}")
    else:
        print("No alert generated")
