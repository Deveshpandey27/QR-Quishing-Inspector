"""
Unit and integration tests for Features 15, 16, and 17:
- Feature 15: User Education ("WHY IS THIS DANGEROUS?")
- Feature 16: Professional "How It Works" 7-Stage Architecture Pipeline
- Feature 17: Actionable Security Recommendations ("What should I do?")

Validates:
1. get_what_should_i_do():
   - Exact text for LOW risk
   - Exact text for MEDIUM risk
   - Exact text for HIGH risk
2. get_user_education_advisory():
   - Exact heading: "WHY IS THIS DANGEROUS?"
   - Contextual lead on QR phishing hiding destination
   - Prohibited items: passwords, OTPs, banking credentials, card information
   - Closing condition: "unless you have verified the destination."
3. Composite Risk Engine integration:
   - what_should_i_do and user_education returned in risk synthesis
4. API endpoint (/api/v1/analyze):
   - Response includes valid what_should_i_do and user_education objects
5. Report Service integration:
   - Formatted report contains exact recommendations for each tier
6. HTML Template integrity:
   - Index template contains 7-stage architecture steps (01 to 07)
   - Index template contains whatShouldIDoCard and userEducationCard
"""

import unittest
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
from app.detection.guidance import get_what_should_i_do, get_user_education_advisory
from app.detection.risk_engine import calculate_composite_risk
from app.services.report_service import _get_recommendation


class TestEducationAndGuidance(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_what_should_i_do_low_risk(self):
        """Verify exact guidance text for Low risk."""
        guidance = get_what_should_i_do(score=10, risk_level="LOW", is_trusted=False)
        self.assertEqual(guidance["risk_level"], "LOW")
        self.assertEqual(guidance["badge_text"], "✓ LOW RISK")
        self.assertEqual(guidance["lead_text"], "No significant indicators were detected.")
        self.assertEqual(
            guidance["action_text"],
            "Still verify the destination before entering credentials or payment information.",
        )
        self.assertIn("verify", guidance["full_text"].lower())

    def test_what_should_i_do_medium_risk(self):
        """Verify exact guidance text for Medium risk (SUSPICIOUS)."""
        guidance = get_what_should_i_do(score=50, risk_level="MEDIUM", is_trusted=False)
        self.assertEqual(guidance["risk_level"], "MEDIUM")
        self.assertEqual(guidance["badge_text"], "⚠ SUSPICIOUS")
        self.assertEqual(
            guidance["lead_text"],
            "The URL contains characteristics commonly associated with phishing.",
        )
        self.assertEqual(
            guidance["action_text"],
            "Avoid entering sensitive information.",
        )
        self.assertIn("Avoid entering sensitive information", guidance["full_text"])

    def test_what_should_i_do_high_risk(self):
        """Verify exact guidance text for High risk."""
        guidance = get_what_should_i_do(score=85, risk_level="HIGH", is_trusted=False)
        self.assertEqual(guidance["risk_level"], "HIGH")
        self.assertEqual(guidance["badge_text"], "🚨 HIGH RISK")
        self.assertEqual(
            guidance["lead_text"],
            "Multiple phishing indicators were detected.",
        )
        self.assertEqual(
            guidance["action_text"],
            "Do not open the destination. Do not enter passwords, OTPs, card details, or banking information.",
        )
        self.assertIn("Do not open the destination", guidance["full_text"])

    def test_user_education_advisory_exact_text(self):
        """Verify exact user education headings, prohibited list, and conditions."""
        edu = get_user_education_advisory()
        self.assertEqual(edu["heading"], "WHY IS THIS DANGEROUS?")
        self.assertIn("QR phishing attacks can hide the destination", edu["text"])
        self.assertEqual(len(edu["prohibited_items"]), 4)
        self.assertIn("passwords", edu["prohibited_items"])
        self.assertIn("OTPs", edu["prohibited_items"])
        self.assertIn("banking credentials", edu["prohibited_items"])
        self.assertIn("card information", edu["prohibited_items"])
        self.assertEqual(edu["closing_note"], "unless you have verified the destination.")

    def test_composite_risk_engine_attaches_guidance_and_education(self):
        """Verify calculate_composite_risk attaches what_should_i_do and user_education."""
        # High-risk synthesis via brand impersonation target
        risk_high = calculate_composite_risk("https://google-security-example.com")
        self.assertIn("what_should_i_do", risk_high)
        self.assertIn("user_education", risk_high)
        self.assertEqual(risk_high["what_should_i_do"]["risk_level"], "HIGH")
        self.assertEqual(risk_high["user_education"]["heading"], "WHY IS THIS DANGEROUS?")

        # Low-risk synthesis via authoritative whitelist target
        risk_low = calculate_composite_risk("https://google.com")
        self.assertEqual(risk_low["what_should_i_do"]["risk_level"], "LOW")
        self.assertEqual(risk_low["what_should_i_do"]["badge_text"], "✓ LOW RISK")

    def test_analyze_api_returns_guidance_and_education(self):
        """Verify /api/v1/analyze returns guidance models conforming to Pydantic schema."""
        res = self.client.post("/api/v1/analyze", json={"url": "https://google-security-example.com"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertIn("what_should_i_do", data)
        self.assertIn("user_education", data)

        wsd = data["what_should_i_do"]
        self.assertIsNotNone(wsd)
        self.assertIn("badge_text", wsd)
        self.assertIn("action_text", wsd)

        edu = data["user_education"]
        self.assertIsNotNone(edu)
        self.assertEqual(edu["heading"], "WHY IS THIS DANGEROUS?")
        self.assertEqual(len(edu["prohibited_items"]), 4)

    def test_report_service_recommendation_alignment(self):
        """Verify _get_recommendation uses exact recommendations across all tiers."""
        high_rec = _get_recommendation("HIGH")
        self.assertEqual(high_rec, "Do not enter credentials or payment information.")

        med_rec = _get_recommendation("MEDIUM")
        self.assertEqual(med_rec, "Proceed with extreme caution. Avoid entering sensitive data.")

        low_rec = _get_recommendation("LOW")
        self.assertEqual(low_rec, "Safe destination verified. Standard caution still applies.")

    def test_html_template_7steps_and_cards_present(self):
        """Verify index.html contains the 7 steps and the two new card components."""
        template_path = Path(__file__).resolve().parent.parent / "templates" / "index.html"
        self.assertTrue(template_path.exists())
        html = template_path.read_text(encoding="utf-8")

        # Feature 16: 7 steps
        self.assertIn("HOW QR QUISHING INSPECTOR WORKS", html)
        self.assertIn("01", html)
        self.assertIn("QR Detection", html)
        self.assertIn("02", html)
        self.assertIn("URL Extraction", html)
        self.assertIn("03", html)
        self.assertIn("Security Analysis", html)
        self.assertIn("04", html)
        self.assertIn("ML Classification", html)
        self.assertIn("05", html)
        self.assertIn("Threat Intelligence", html)
        self.assertIn("06", html)
        self.assertIn("Risk Engine", html)
        self.assertIn("07", html)
        self.assertIn("Security Recommendation", html)

        # Feature 17 & Feature 15 cards
        self.assertIn('id="whatShouldIDoCard"', html)
        self.assertIn('id="userEducationCard"', html)
        self.assertIn("WHY IS THIS DANGEROUS?", html)
        self.assertIn("Never enter:", html)
        self.assertIn("passwords", html)
        self.assertIn("OTPs", html)
        self.assertIn("banking credentials", html)
        self.assertIn("card information", html)


if __name__ == "__main__":
    unittest.main()
