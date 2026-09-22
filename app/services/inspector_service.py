from typing import Dict, Any, Optional
from app.detection.risk_engine import calculate_composite_risk
from app.detection.payload_classifier import (
    classify_qr_payload,
    sanitize_payload_for_storage,
    extract_embedded_urls
)
from app.detection.guidance import get_what_should_i_do, get_user_education_advisory
from app.services.qr_service import decode_qr_image


def inspect_payload(raw_payload: str) -> Dict[str, Any]:
    """
    Classifies and inspects any QR code payload across all 6 content types:
    - URL
    - Plain text
    - Email
    - Phone number
    - Wi-Fi configuration
    - vCard/contact
    """
    raw_payload_clean = (raw_payload or "").strip()
    classification = classify_qr_payload(raw_payload_clean)
    content_type = classification["content_type"]

    # 1. URL Payloads -> proceed through full Quishing Composite Risk Engine
    if content_type == "url":
        target_url = classification.get("url") or raw_payload_clean
        analysis = calculate_composite_risk(target_url)
        analysis["payload_info"] = {
            "content_type": "url",
            "type_label": "URL",
            "security_warning": "QR code contains web destination URL.",
            "raw_preview": raw_payload_clean[:120],
            "sanitized_text": raw_payload_clean,
            "details": {"url": target_url},
            "embedded_urls": [target_url]
        }
        return analysis

    # 2. Non-URL Payloads -> specialized payload analysis
    score = classification.get("score", 10)
    risk_level = classification.get("risk_level", "LOW")
    status = classification.get("status", "safe")
    reasons = list(classification.get("reasons", []))
    warning = classification.get("security_warning", "QR payload inspected.")
    embedded_urls = classification.get("embedded_urls", [])

    # If payload contains an embedded URL, inspect that URL for quishing threats
    embedded_analysis = None
    if embedded_urls:
        try:
            embedded_analysis = calculate_composite_risk(embedded_urls[0])
            if embedded_analysis.get("success"):
                emb_score = embedded_analysis.get("score", 0)
                reasons.append(f"Embedded URL inspected: {embedded_urls[0]} (Risk: {embedded_analysis.get('risk_level', 'LOW')} - {emb_score}/100)")
                if emb_score > score:
                    score = emb_score
                    risk_level = embedded_analysis.get("risk_level", "LOW")
                    status = embedded_analysis.get("status", "safe")
                    warning = f"⚠ Embedded Quishing URL: {embedded_analysis.get('title', 'Suspicious Link')}"
        except Exception:
            pass

    # Build clean display hostname & titles based on type
    type_label = classification.get("type_label", "QR Payload")
    sanitized_text = sanitize_payload_for_storage(raw_payload_clean)

    if content_type == "wifi":
        hostname = f"Wi-Fi SSID: {classification.get('ssid') or '(Hidden)'}"
        title = "Wi-Fi Configuration"
        detected = ["Network credentials payload", f"Security: {classification.get('auth_type', 'WPA')}"]
        if classification.get("is_open"):
            detected.append("Unencrypted (Open) Wi-Fi")
        if classification.get("is_weak"):
            detected.append("Weak WEP Encryption")
    elif content_type == "email":
        hostname = f"Email: {classification.get('recipient') or 'Draft'}"
        title = "Email Draft Payload"
        detected = ["Email composition target"]
        if classification.get("is_phishing_lure"):
            detected.append("Urgent Phishing Lure Keywords")
        if embedded_urls:
            detected.append("Embedded URL in email body")
    elif content_type == "phone":
        hostname = f"Phone: {classification.get('phone_number') or 'Dialer'}"
        title = "Telephone Number Payload"
        detected = ["Phone dialer target"]
        if classification.get("is_premium"):
            detected.append("Premium-rate / Toll fraud number")
    elif content_type == "vcard":
        hostname = f"vCard: {classification.get('name') or 'Contact'}"
        title = "vCard Contact Card"
        detected = ["Contact card import"]
        if embedded_urls:
            detected.append("Website link inside contact card (Quishing vector)")
    else: # plain text
        hostname = "Plain Text Payload"
        title = "Plain Text Message"
        detected = []
        if classification.get("has_injection"):
            detected.append("Command / script injection syntax")
        if classification.get("has_credentials"):
            detected.append("Authentication credentials exposed in text")
        if embedded_urls:
            detected.append("Embedded URL inside text")

    # Construct unified AnalyzeResponse schema
    return {
        "success": True,
        "url": sanitized_text,
        "hostname": hostname,
        "score": score,
        "risk_level": risk_level,
        "ml_score": embedded_analysis.get("ml_score", 0) if embedded_analysis else 0,
        "rule_score": score,
        "domain_score": embedded_analysis.get("domain_score", 0) if embedded_analysis else 0,
        "risk_weights": {"rule": 0.35, "ml": 0.45, "domain": 0.20},
        "status": status,
        "title": title,
        "message": warning,
        "reasons": reasons,
        "indicators": [
            {"name": "qr_payload_type", "weight": score, "severity": "high" if score >= 70 else ("medium" if score >= 40 else "low"), "detail": f"Content Type: {type_label}"}
        ] if score > 20 else [],
        "detected": detected,
        "is_trusted": risk_level == "LOW",
        "is_shortener": False,
        "is_ip": False,
        "domain_intel": embedded_analysis.get("domain_intel") if embedded_analysis else None,
        "tls_analysis": embedded_analysis.get("tls_analysis") if embedded_analysis else None,
        "shortener_info": embedded_analysis.get("shortener_info") if embedded_analysis else None,
        "ml_detail": embedded_analysis.get("ml_detail") if embedded_analysis else {
            "model_name": "HistGradientBoosting",
            "suspicious_probability": float(embedded_analysis.get("ml_score", 0)) if embedded_analysis else 0.0,
            "legitimate_probability": 100.0 if not embedded_analysis else float(100.0 - embedded_analysis.get("ml_score", 0)),
            "label": "suspicious" if (embedded_analysis and embedded_analysis.get("ml_score", 0) >= 50) else "legitimate",
            "is_suspicious": bool(embedded_analysis and embedded_analysis.get("ml_score", 0) >= 50),
            "features": {},
            "explanation": None
        },
        "threat_intel": embedded_analysis.get("threat_intel") if embedded_analysis else {
            "known_malicious": False,
            "matches_count": 0,
            "sources_checked": 5,
            "providers": [],
            "warning_message": None,
            "summary_text": "Threat Intelligence: Non-URL payload (no external domain threat record)."
        },
        "payload_info": {
            "content_type": content_type,
            "type_label": type_label,
            "security_warning": warning,
            "raw_preview": raw_payload_clean[:120],
            "sanitized_text": sanitized_text,
            "details": classification,
            "embedded_urls": embedded_urls
        },
        "obfuscation_analysis": embedded_analysis.get("obfuscation_analysis") if embedded_analysis else None,
        "brand_impersonation": embedded_analysis.get("brand_impersonation") if embedded_analysis else None,
        "what_should_i_do": embedded_analysis.get("what_should_i_do") if embedded_analysis else get_what_should_i_do(score, risk_level),
        "user_education": embedded_analysis.get("user_education") if embedded_analysis else get_user_education_advisory()
    }


def inspect_url(raw_url: str) -> dict:
    """Wrapper routing URL or any payload through the unified inspector."""
    return inspect_payload(raw_url)


def inspect_qr_bytes(image_bytes: bytes) -> dict:
    """Decodes QR code from image bytes and analyzes its payload appropriately."""
    decode_result = decode_qr_image(image_bytes)
    if not decode_result["success"]:
        return {
            "success": False,
            "error": decode_result.get("error", "No QR code detected.")
        }

    extracted_payload = decode_result["data"]
    analysis = inspect_payload(extracted_payload)

    if not analysis.get("success"):
        return {
            "success": False,
            "extracted_text": sanitize_payload_for_storage(extracted_payload),
            "error": analysis.get("error", "Failed to inspect extracted destination.")
        }

    return {
        "success": True,
        "extracted_text": sanitize_payload_for_storage(extracted_payload),
        "raw_extracted_text": extracted_payload,
        "method": decode_result.get("method"),
        "analysis": analysis,
    }
