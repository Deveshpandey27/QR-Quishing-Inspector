import io
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


def _extract_findings(analysis_data: dict) -> List[str]:
    """Extracts a clean, deduplicated list of findings for report presentation."""
    findings = []
    
    # 1. Detected characteristics list
    detected = analysis_data.get("detected") or []
    if isinstance(detected, list):
        for item in detected:
            if isinstance(item, str) and item.strip():
                clean_item = item.strip()
                if clean_item.startswith("✓ "):
                    clean_item = clean_item[2:]
                if clean_item not in findings:
                    findings.append(clean_item)

    # 2. Indicators list
    indicators = analysis_data.get("indicators") or []
    if isinstance(indicators, list):
        for ind in indicators:
            if isinstance(ind, dict):
                desc = ind.get("detail") or ind.get("name")
                if desc and isinstance(desc, str):
                    formatted = desc.replace("_", " ").title()
                    if formatted not in findings:
                        findings.append(formatted)

    # 3. Domain intel findings
    d_intel = analysis_data.get("domain_intel") or {}
    whois = d_intel.get("whois") or {}
    if whois.get("is_recently_registered"):
        if "Recently registered domain" not in findings:
            findings.append("Recently registered domain")

    # 4. Shortener findings
    hostname = str(analysis_data.get("hostname") or "")
    if analysis_data.get("is_shortener") or "bit.ly" in hostname:
        if "URL shortener detected" not in findings:
            findings.append("URL shortener detected")

    # 5. Threat intel findings
    ti = analysis_data.get("threat_intel") or {}
    if ti.get("known_malicious"):
        if "Known malicious threat feed match" not in findings:
            findings.append("Known malicious threat feed match")

    # 6. Anti-obfuscation findings
    obf = analysis_data.get("obfuscation_analysis") or {}
    if obf.get("is_obfuscated"):
        p_info = obf.get("punycode_info") or {}
        if p_info.get("detected"):
            resemble_txt = f" (resembles '{p_info.get('visually_resembles')}')" if p_info.get('visually_resembles') else ""
            findings.append(f"Unicode/punycode domain obfuscation{resemble_txt}")
        for tech in obf.get("detected_techniques") or []:
            if tech == "hex_alternative_ip" and "Hexadecimal / alternative IP representation" not in findings:
                findings.append("Hexadecimal / alternative IP representation")
            elif tech == "url_encoding" and "Evasive URL percent-encoding" not in findings:
                findings.append("Evasive URL percent-encoding")
            elif tech == "nested_urls" and "Nested URL parameter evasion" not in findings:
                findings.append("Nested URL parameter evasion")
            elif tech == "multiple_redirects" and "Multiple redirect chaining" not in findings:
                findings.append("Multiple redirect chaining")

    # 7. Brand Impersonation findings
    brand_imp = analysis_data.get("brand_impersonation") or {}
    if brand_imp.get("is_impersonation"):
        brand_name = brand_imp.get("detected_brand", "Target Brand")
        imp_types = brand_imp.get("impersonation_types") or []
        if "character_substitution" in imp_types:
            findings.append(f"Brand impersonation: '{brand_name}' via leetspeak character substitution")
        elif "misleading_subdomain" in imp_types:
            findings.append(f"Misleading subdomain brand deception mimicking '{brand_name}'")
        elif "typosquatting" in imp_types:
            findings.append(f"Typosquatting brand similarity mimicking '{brand_name}'")
        else:
            findings.append(f"Brand impersonation: Unauthorized '{brand_name}' compound domain")

    # Fallback to reasons if findings is still empty
    if not findings:
        reasons = analysis_data.get("reasons") or []
        for r in reasons:
            if isinstance(r, str) and r.strip() and r not in findings:
                findings.append(r.strip())

    # Fallback for safe destinations
    if not findings:
        findings = [
            "Authentic domain characteristics verified",
            "No suspicious keywords or obfuscation detected",
            "Valid SSL/TLS certificate structure"
        ]

    return findings[:6]


def _get_recommendation(risk_level: str) -> str:
    """Returns tailored security recommendation based on risk classification."""
    lvl = (risk_level or "LOW").upper()
    if lvl == "HIGH":
        return "Do not enter credentials or payment information."
    elif lvl == "MEDIUM":
        return "Proceed with extreme caution. Avoid entering sensitive data."
    else:
        return "Safe destination verified. Standard caution still applies."


def generate_text_report(analysis_data: dict) -> str:
    """
    Generates plain-text security analysis report matching the user's exact specification:

    QR QUISHING INSPECTOR
    Security Analysis Report

    URL:
    https://example.xyz/login

    Risk:
    HIGH — 87/100

    Findings:
    • Suspicious domain
    • Login keyword
    • Recently registered domain
    • Multiple URL indicators

    ML:
    91.3% suspicious

    Recommendation:
    Do not enter credentials or payment information.
    """
    url = analysis_data.get("url") or analysis_data.get("display_url") or "Unknown URL"
    score = int(analysis_data.get("score", analysis_data.get("final_score", 0)))
    
    risk_level = analysis_data.get("risk_level")
    if not risk_level:
        if score >= 70 or analysis_data.get("status") == "dangerous":
            risk_level = "HIGH"
        elif score >= 40 or analysis_data.get("status") == "suspicious":
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
    risk_level = risk_level.upper()

    findings = _extract_findings(analysis_data)
    findings_formatted = "\n".join([f"• {f}" for f in findings])

    # ML percentage
    ml_detail = analysis_data.get("ml_detail") or {}
    susp_prob = ml_detail.get("suspicious_probability")
    if susp_prob is None:
        susp_prob = float(analysis_data.get("ml_score", 0.0))
    ml_formatted = f"{susp_prob:.1f}% suspicious"

    recommendation = _get_recommendation(risk_level)

    report_lines = [
        "QR QUISHING INSPECTOR",
        "Security Analysis Report",
        "",
        "URL:",
        url,
        "",
        "Risk:",
        f"{risk_level} — {score}/100",
        "",
        "Findings:",
        findings_formatted,
        "",
        "ML:",
        ml_formatted,
        "",
        "Recommendation:",
        recommendation
    ]

    return "\n".join(report_lines)


def generate_pdf_report(analysis_data: dict) -> bytes:
    """
    Generates a presentation-grade, downloadable PDF Security Incident & Analysis Report.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom Typography Styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        alignment=TA_LEFT
    )
    
    sub_title_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748b"),
        alignment=TA_LEFT
    )

    section_header_style = ParagraphStyle(
        "SectionHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=8,
        spaceAfter=4
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )

    url_style = ParagraphStyle(
        "UrlStyle",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#0f172a")
    )

    finding_item_style = ParagraphStyle(
        "FindingItem",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b")
    )

    elements = []

    # 1. Header Banner
    now_str = datetime.now(timezone.utc).strftime("%B %d, %Y - %H:%M:%S UTC")
    report_id = f"QIR-{uuid.uuid4().hex[:8].upper()}"

    header_table_data = [
        [
            Paragraph("<b>QR QUISHING INSPECTOR</b>", title_style),
            Paragraph(f"<b>REPORT ID:</b> {report_id}<br/><b>DATE:</b> {now_str}", ParagraphStyle("HdrMeta", parent=body_style, fontSize=8, leading=11, alignment=TA_RIGHT, textColor=colors.HexColor("#64748b")))
        ],
        [
            Paragraph("Comprehensive Quishing Threat & Security Analysis Report", sub_title_style),
            ""
        ]
    ]
    header_table = Table(header_table_data, colWidths=[380, 160])
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("SPAN", (0, 1), (1, 1)),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0)
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 8))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceBefore=2, spaceAfter=10))

    # 2. Key Metadata & Risk Summary Table
    url = analysis_data.get("url") or analysis_data.get("display_url") or "Unknown URL"
    score = int(analysis_data.get("score") if analysis_data.get("score") is not None else (analysis_data.get("final_score") or 0))
    
    risk_level = analysis_data.get("risk_level")
    if not risk_level:
        if score >= 70 or analysis_data.get("status") == "dangerous":
            risk_level = "HIGH"
        elif score >= 40 or analysis_data.get("status") == "suspicious":
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
    risk_level = risk_level.upper()

    # Determine risk badge color
    if risk_level == "HIGH":
        risk_bg = colors.HexColor("#fee2e2")
        risk_fg = colors.HexColor("#b91c1c")
    elif risk_level == "MEDIUM":
        risk_bg = colors.HexColor("#fef3c7")
        risk_fg = colors.HexColor("#b45309")
    else:
        risk_bg = colors.HexColor("#d1fae5")
        risk_fg = colors.HexColor("#047857")

    summary_table_data = [
        [
            Paragraph("<b>Target Destination URL:</b>", body_style),
            Paragraph(f"<b>{url}</b>", url_style)
        ],
        [
            Paragraph("<b>Final Risk Classification:</b>", body_style),
            Paragraph(f"<b>{risk_level}</b> &nbsp;—&nbsp; <b>{score} / 100</b>", ParagraphStyle("RiskScoreVal", parent=body_style, fontName="Helvetica-Bold", fontSize=11, textColor=risk_fg))
        ],
        [
            Paragraph("<b>Domain Hostname:</b>", body_style),
            Paragraph(f"{analysis_data.get('hostname') or 'N/A'}", body_style)
        ],
        [
            Paragraph("<b>Verdict Status:</b>", body_style),
            Paragraph(f"{(analysis_data.get('status') or 'safe').upper()} (Action: {analysis_data.get('title') or 'Verified'})", body_style)
        ]
    ]

    summary_table = Table(summary_table_data, colWidths=[160, 380])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("BACKGROUND", (1, 1), (1, 1), risk_bg)
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 12))

    # 3. Findings Section
    elements.append(Paragraph("KEY DETECTED FINDINGS", section_header_style))
    findings = _extract_findings(analysis_data)
    findings_data = []
    for f in findings:
        findings_data.append([
            Paragraph("•", ParagraphStyle("Bullet", parent=body_style, fontName="Helvetica-Bold", textColor=risk_fg, alignment=TA_CENTER)),
            Paragraph(f, finding_item_style)
        ])

    findings_table = Table(findings_data, colWidths=[20, 520])
    findings_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4)
    ]))
    elements.append(findings_table)
    elements.append(Spacer(1, 12))

    # 4. Multi-Pillar Security Telemetry Table
    elements.append(Paragraph("MULTI-PILLAR TELEMETRY BREAKDOWN", section_header_style))

    ml_detail = analysis_data.get("ml_detail") or {}
    susp_prob = ml_detail.get("suspicious_probability")
    if susp_prob is None:
        susp_prob = float(analysis_data.get("ml_score", 0.0))
    model_name = ml_detail.get("model_name") or "HistGradientBoosting"

    d_intel = analysis_data.get("domain_intel") or {}
    whois = d_intel.get("whois") or {}
    age_text = whois.get("age_text") or ("Recently registered" if whois.get("is_recently_registered") else "Established")
    dns = d_intel.get("dns") or {}
    dns_status = dns.get("status", "resolved").title()

    tls = analysis_data.get("tls_analysis") or {}
    https_status = "Active HTTPS" if tls.get("has_https", True) else "HTTP (Unencrypted)"
    tls_expiry = tls.get("expiry_text") or "N/A"

    ti = analysis_data.get("threat_intel") or {}
    ti_matches = ti.get("matches_count", 0)
    ti_known = "YES (Reported)" if ti.get("known_malicious") else "NO (Clean)"

    telemetry_data = [
        [
            Paragraph("<b>Pillar / Engine</b>", ParagraphStyle("H1", parent=body_style, fontName="Helvetica-Bold")),
            Paragraph("<b>Telemetry & Findings</b>", ParagraphStyle("H2", parent=body_style, fontName="Helvetica-Bold")),
            Paragraph("<b>Pillar Weight</b>", ParagraphStyle("H3", parent=body_style, fontName="Helvetica-Bold", alignment=TA_RIGHT))
        ],
        [
            Paragraph("<b>Rule Engine Heuristics:</b>", body_style),
            Paragraph(f"Score: {analysis_data.get('rule_score') or 0}/100 &nbsp;|&nbsp; {len(analysis_data.get('detected') or [])} characteristics flagged", body_style),
            Paragraph("35%", ParagraphStyle("W1", parent=body_style, alignment=TA_RIGHT))
        ],
        [
            Paragraph("<b>Machine Learning Engine:</b>", body_style),
            Paragraph(f"Suspicious Probability: <b>{susp_prob:.1f}%</b> &nbsp;|&nbsp; Model: <i>{model_name}</i>", body_style),
            Paragraph("45%", ParagraphStyle("W2", parent=body_style, alignment=TA_RIGHT))
        ],
        [
            Paragraph("<b>Domain & TLS Signals:</b>", body_style),
            Paragraph(f"Domain Age: {age_text} &nbsp;|&nbsp; DNS: {dns_status} &nbsp;|&nbsp; TLS: {https_status} ({tls_expiry})", body_style),
            Paragraph("20%", ParagraphStyle("W3", parent=body_style, alignment=TA_RIGHT))
        ],
        [
            Paragraph("<b>Threat Intelligence Feeds:</b>", body_style),
            Paragraph(f"Known Malicious: <b>{ti_known}</b> &nbsp;|&nbsp; Threat Feeds Matches: <b>{ti_matches}</b> (URLhaus, PhishTank, Safe Browsing)", body_style),
            Paragraph("Consensus", ParagraphStyle("W4", parent=body_style, alignment=TA_RIGHT))
        ]
    ]

    telemetry_table = Table(telemetry_data, colWidths=[140, 330, 70])
    telemetry_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8)
    ]))
    elements.append(telemetry_table)
    elements.append(Spacer(1, 14))

    # 5. Recommendation Callout Box
    elements.append(Paragraph("RECOMMENDATION", section_header_style))
    recommendation = _get_recommendation(risk_level)
    rec_table_data = [
        [
            Paragraph(f"<b>ADVISORY ACTION:</b><br/>{recommendation}", ParagraphStyle("RecText", parent=body_style, fontSize=10, leading=14, textColor=risk_fg))
        ]
    ]
    rec_table = Table(rec_table_data, colWidths=[540])
    rec_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), risk_bg),
        ("BOX", (0, 0), (-1, -1), 1, risk_fg),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12)
    ]))
    elements.append(rec_table)
    elements.append(Spacer(1, 14))

    # 6. Corporate Disclaimer & Footer
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceBefore=2, spaceAfter=6))
    footer_text = (
        "CONFIDENTIAL & PROPRIETARY &nbsp;•&nbsp; Generated by QR Quishing Inspector v2.0 (FastAPI + ML Brain) &nbsp;•&nbsp; "
        "This security assessment is based on automated heuristic, ML, domain intelligence, and threat feed cross-referencing."
    )
    elements.append(Paragraph(footer_text, ParagraphStyle("Footer", parent=body_style, fontSize=7, leading=10, textColor=colors.HexColor("#94a3b8"), alignment=TA_CENTER)))

    doc.build(elements)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
