r"""
Actionable Security Guidance & User Education Module for QR-Quishing-Inspector.

Implements:
1. Feature 15: User Education ("WHY IS THIS DANGEROUS?")
   Explains QR quishing attack vectors and itemizes sensitive data categories
   that must never be entered without destination verification.

2. Feature 17: "What should I do?" Actionable Security Recommendations
   Tailored recommendations for LOW, MEDIUM, and HIGH risk tiers.
"""

from typing import Dict, Any, List


def get_what_should_i_do(score: int, risk_level: str = None, is_trusted: bool = False) -> Dict[str, Any]:
    """
    Returns exact actionable guidance for the user based on risk classification:
    - Low:
        ✓ LOW RISK
        No significant indicators were detected.
        Still verify the destination before entering credentials or payment information.
    - Medium:
        ⚠ SUSPICIOUS
        The URL contains characteristics commonly associated with phishing.
        Recommendation:
        Avoid entering sensitive information.
    - High:
        🚨 HIGH RISK
        Multiple phishing indicators were detected.
        Recommendation:
        Do not open the destination.
        Do not enter passwords, OTPs, card details, or banking information.
    """
    lvl = (risk_level or "").upper()
    if not lvl:
        if score >= 70:
            lvl = "HIGH"
        elif score >= 35:
            lvl = "MEDIUM"
        else:
            lvl = "LOW"

    if lvl == "HIGH":
        return {
            "tier": "HIGH",
            "risk_level": "HIGH",
            "badge_text": "🚨 HIGH RISK",
            "summary": "Multiple phishing indicators were detected.",
            "lead_text": "Multiple phishing indicators were detected.",
            "recommendation": "Do not open the destination. Do not enter passwords, OTPs, card details, or banking information.",
            "action_text": "Do not open the destination. Do not enter passwords, OTPs, card details, or banking information.",
            "action_items": [
                "Do not open the destination.",
                "Do not enter passwords, OTPs, card details, or banking information."
            ],
            "full_text": "🚨 HIGH RISK\nMultiple phishing indicators were detected.\n\nRecommendation:\nDo not open the destination. Do not enter passwords, OTPs, card details, or banking information.",
            "severity_color": "danger"
        }
    elif lvl == "MEDIUM":
        return {
            "tier": "MEDIUM",
            "risk_level": "MEDIUM",
            "badge_text": "⚠ SUSPICIOUS",
            "summary": "The URL contains characteristics commonly associated with phishing.",
            "lead_text": "The URL contains characteristics commonly associated with phishing.",
            "recommendation": "Avoid entering sensitive information.",
            "action_text": "Avoid entering sensitive information.",
            "action_items": [
                "Avoid entering sensitive information.",
                "Verify the destination domain before proceeding."
            ],
            "full_text": "⚠ SUSPICIOUS\nThe URL contains characteristics commonly associated with phishing.\n\nRecommendation:\nAvoid entering sensitive information.",
            "severity_color": "warning"
        }
    else:  # LOW
        return {
            "tier": "LOW",
            "risk_level": "LOW",
            "badge_text": "✓ LOW RISK",
            "summary": "No significant indicators were detected.",
            "lead_text": "No significant indicators were detected.",
            "recommendation": "Still verify the destination before entering credentials or payment information.",
            "action_text": "Still verify the destination before entering credentials or payment information.",
            "action_items": [
                "Still verify the destination before entering credentials or payment information."
            ],
            "full_text": "✓ LOW RISK\nNo significant indicators were detected.\nStill verify the destination before entering credentials or payment information.",
            "severity_color": "success"
        }


def get_user_education_advisory() -> Dict[str, Any]:
    """
    Returns standard educational advisory explaining why QR phishing is dangerous
    and explicitly itemizing sensitive data that should never be entered.
    """
    return {
        "title": "WHY IS THIS DANGEROUS?",
        "heading": "WHY IS THIS DANGEROUS?",
        "context": "QR phishing attacks can hide the destination URL from the user until the QR code is scanned.",
        "text": "QR phishing attacks can hide the destination URL from the user until the QR code is scanned.",
        "prohibited_lead": "Never enter:",
        "prohibited_items": [
            "passwords",
            "OTPs",
            "banking credentials",
            "card information"
        ],
        "condition_note": "unless you have verified the destination.",
        "closing_note": "unless you have verified the destination.",
        "formatted_text": (
            "WHY IS THIS DANGEROUS?\n\n"
            "QR phishing attacks can hide the destination URL from the user until the QR code is scanned.\n\n"
            "Never enter:\n"
            "• passwords\n"
            "• OTPs\n"
            "• banking credentials\n"
            "• card information\n\n"
            "unless you have verified the destination."
        )
    }
