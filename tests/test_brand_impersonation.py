"""
Unit tests for Section 14: Brand Impersonation Detection Engine.

Validates:
1. Exact user prompt examples:
   - paypa1-login.com
   - micr0soft-security.com
   - g00gle-verification.com
   - google-security-example.com
2. Exact prompt warning output formatting:
   ⚠ POSSIBLE BRAND IMPERSONATION
   Detected brand-like term: Google
   Actual domain: google-security-example.com
   The domain is not an official Google domain.
3. Strict false-positive prevention:
   - Official domains: google.com, accounts.google.com, microsoft.com, paypal.com
   - Benign dictionary words: pineapple.com, metadata.org
4. Misleading subdomains (e.g. google.com.phishing-site.xyz)
5. Typosquatting & similarity (e.g. gogle.com, paypaal.com)
6. REST API endpoint (/api/v1/detect-brand-impersonation)
7. Composite Risk Engine escalation
"""

import unittest
from fastapi.testclient import TestClient
from app.main import app
from app.detection.brand_impersonation import detect_brand_impersonation
from app.detection.risk_engine import calculate_composite_risk


class TestBrandImpersonationDetection(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_user_example_google_security_example_exact_output(self):
        """Verify exact user prompt example and exact warning format."""
        url = "https://google-security-example.com"
        res = detect_brand_impersonation(url)

        self.assertTrue(res["is_impersonation"])
        self.assertEqual(res["warning_title"], "⚠ POSSIBLE BRAND IMPERSONATION")
        self.assertEqual(res["detected_brand"], "Google")
        self.assertEqual(res["actual_domain"], "google-security-example.com")
        self.assertEqual(res["warning_message"], "The domain is not an official Google domain.")
        self.assertIn("compound_keyword", res["impersonation_types"])
        self.assertFalse(res["is_official_domain"])

    def test_user_example_paypa1_login(self):
        """Verify paypa1-login.com character substitution ('1' for 'l')."""
        url = "https://paypa1-login.com"
        res = detect_brand_impersonation(url)

        self.assertTrue(res["is_impersonation"])
        self.assertEqual(res["detected_brand"], "PayPal")
        self.assertEqual(res["actual_domain"], "paypa1-login.com")
        self.assertEqual(res["warning_message"], "The domain is not an official PayPal domain.")
        self.assertIn("character_substitution", res["impersonation_types"])

        # Check leetspeak substitutions recorded
        subs = res.get("substitutions", [])
        self.assertTrue(any(s.get("original") == "1" and s.get("normalized") == "l" for s in subs))

    def test_user_example_micr0soft_security(self):
        """Verify micr0soft-security.com character substitution ('0' for 'o')."""
        url = "https://micr0soft-security.com"
        res = detect_brand_impersonation(url)

        self.assertTrue(res["is_impersonation"])
        self.assertEqual(res["detected_brand"], "Microsoft")
        self.assertEqual(res["actual_domain"], "micr0soft-security.com")
        self.assertEqual(res["warning_message"], "The domain is not an official Microsoft domain.")
        self.assertIn("character_substitution", res["impersonation_types"])

        subs = res.get("substitutions", [])
        self.assertTrue(any(s.get("original") == "0" and s.get("normalized") == "o" for s in subs))

    def test_user_example_g00gle_verification(self):
        """Verify g00gle-verification.com character substitution ('00' for 'oo')."""
        url = "https://g00gle-verification.com"
        res = detect_brand_impersonation(url)

        self.assertTrue(res["is_impersonation"])
        self.assertEqual(res["detected_brand"], "Google")
        self.assertEqual(res["actual_domain"], "g00gle-verification.com")
        self.assertEqual(res["warning_message"], "The domain is not an official Google domain.")
        self.assertIn("character_substitution", res["impersonation_types"])

    def test_false_positive_suppression_official_google(self):
        """Ensure official Google domains and subdomains are never falsely flagged."""
        official_urls = [
            "https://google.com",
            "https://accounts.google.com/login",
            "https://drive.google.com/drive/folders",
            "https://google.co.uk/search?q=cybersecurity",
            "https://mail.google.com",
        ]
        for url in official_urls:
            res = detect_brand_impersonation(url)
            self.assertFalse(res["is_impersonation"], f"Official URL flagged as impersonation: {url}")
            self.assertTrue(res["is_official_domain"], f"Official URL not recognized as official: {url}")

    def test_false_positive_suppression_other_brands(self):
        """Ensure other official brand domains are never falsely flagged."""
        official_urls = [
            "https://microsoft.com",
            "https://login.microsoftonline.com",
            "https://paypal.com",
            "https://apple.com",
            "https://amazon.com",
        ]
        for url in official_urls:
            res = detect_brand_impersonation(url)
            self.assertFalse(res["is_impersonation"], f"Official URL flagged as impersonation: {url}")
            self.assertTrue(res["is_official_domain"], f"Official URL not recognized as official: {url}")

    def test_false_positive_suppression_benign_dictionary_words(self):
        """Ensure dictionary words containing brand substrings are NOT flagged."""
        benign_urls = [
            "https://pineapple.com",
            "https://metadata.org",
        ]
        for url in benign_urls:
            res = detect_brand_impersonation(url)
            self.assertFalse(res["is_impersonation"], f"Benign dictionary URL flagged: {url}")

    def test_misleading_subdomain_deception(self):
        """Verify misleading subdomains disguised on unrelated registered domains."""
        url = "https://google.com.phishing-site.xyz/login"
        res = detect_brand_impersonation(url)

        self.assertTrue(res["is_impersonation"])
        self.assertEqual(res["detected_brand"], "Google")
        self.assertEqual(res["actual_domain"], "phishing-site.xyz")
        self.assertIn("misleading_subdomain", res["impersonation_types"])
        self.assertEqual(res["warning_message"], "The domain is not an official Google domain.")

    def test_typosquatting_similarity(self):
        """Verify typosquatting edit distance similarity matching."""
        # gogle.com (edit distance 1 from google)
        res_google = detect_brand_impersonation("https://gogle.com/signin")
        self.assertTrue(res_google["is_impersonation"])
        self.assertEqual(res_google["detected_brand"], "Google")
        self.assertIn("typosquatting", res_google["impersonation_types"])
        self.assertGreaterEqual(res_google["similarity_score"], 0.8)

        # paypaal.com (edit distance 1 from paypal)
        res_paypal = detect_brand_impersonation("https://paypaal.com/verify")
        self.assertTrue(res_paypal["is_impersonation"])
        self.assertEqual(res_paypal["detected_brand"], "PayPal")
        self.assertIn("typosquatting", res_paypal["impersonation_types"])
        self.assertGreaterEqual(res_paypal["similarity_score"], 0.8)

    def test_api_endpoint_detect_brand_impersonation(self):
        """Verify POST /api/v1/detect-brand-impersonation returns valid schema."""
        response = self.client.post(
            "/api/v1/detect-brand-impersonation",
            json={"url": "https://google-security-example.com"}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        imp = data["impersonation"]
        self.assertTrue(imp["is_impersonation"])
        self.assertEqual(imp["detected_brand"], "Google")
        self.assertEqual(imp["actual_domain"], "google-security-example.com")
        self.assertEqual(imp["warning_message"], "The domain is not an official Google domain.")

    def test_composite_risk_engine_brand_escalation(self):
        """Verify Composite Risk Engine escalates risk level and score on brand impersonation."""
        url = "https://google-security-example.com"
        result = calculate_composite_risk(url)

        self.assertTrue(result["success"])
        self.assertGreaterEqual(result["score"], 75)
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertIn("brand_impersonation", result)
        self.assertTrue(result["brand_impersonation"]["is_impersonation"])
        self.assertEqual(result["brand_impersonation"]["detected_brand"], "Google")
        self.assertTrue(any("brand_impersonation_detected" in ind["name"] for ind in result["indicators"]))


if __name__ == "__main__":
    unittest.main()
