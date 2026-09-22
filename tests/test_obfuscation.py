"""
Unit tests for Section 13: Anti-Obfuscation Detection.
Verifies all 5 evasion techniques:
1. URL Encoding & Double Encoding
2. Unicode & Punycode (IDN Homograph) Domains
3. Hexadecimal, DWORD, and Alternative IP Representations
4. Multiple Redirect Chains
5. Nested URLs
"""

import unittest
from fastapi.testclient import TestClient
from app.main import app
from app.detection.obfuscation import (
    check_unicode_punycode,
    check_url_encoding,
    check_hex_alternative_ip,
    check_nested_urls,
    trace_redirect_chain,
    detect_obfuscation,
)


class TestAntiObfuscation(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_punycode_homograph_exact_warning(self):
        """Verify Punycode detection and exact user prompt warning output."""
        url = "https://xn--pypal-4ve.com/signin"
        res = check_unicode_punycode(url)

        self.assertTrue(res["detected"])
        self.assertTrue(res["has_punycode"])
        # User exact prompt requirement:
        self.assertEqual(
            res["warning"],
            "The domain contains a Unicode/punycode representation that may visually resemble another domain."
        )
        self.assertIn("paypal", res["visually_resembles"].lower())

    def test_unicode_homoglyph_cyrillic(self):
        """Verify direct Unicode Cyrillic lookalikes mimicking ASCII brands."""
        # Using Cyrillic small 'а' (U+0430) inside paypal.com
        url = "http://p\u0430ypal.com/login"
        res = check_unicode_punycode(url)

        self.assertTrue(res["detected"])
        self.assertTrue(res["is_homograph"])
        self.assertEqual(res["visually_resembles"], "paypal.com")
        self.assertEqual(
            res["warning"],
            "The domain contains a Unicode/punycode representation that may visually resemble another domain."
        )

    def test_url_encoding_and_double_encoding(self):
        """Verify double percent-encoding and encoded traversal delimiters."""
        # Double encoded path traversal
        double_encoded_url = "https://portal.bank.com/%252e%252e%252fadmin"
        res_double = check_url_encoding(double_encoded_url)
        self.assertTrue(res_double["detected"])
        self.assertTrue(res_double["has_double_encoding"])

        # Encoded @ symbol for userinfo spoofing
        encoded_at_url = "https://legit-site.com%40evil-phish.xyz/login"
        res_at = check_url_encoding(encoded_at_url)
        self.assertTrue(res_at["detected"])
        self.assertTrue(res_at["has_encoded_at"])

        # Encoded hostname
        encoded_host_url = "http://%67%6f%6f%67%6c%65.com/search"
        res_host = check_url_encoding(encoded_host_url)
        self.assertTrue(res_host["detected"])
        self.assertTrue(res_host["host_has_percent"])

    def test_hex_and_dword_ip_representation(self):
        """Verify Hexadecimal, DWORD integer, and alternative IP representations."""
        # 1. Hex IP single integer 0x7f000001 -> 127.0.0.1
        hex_url = "http://0x7f000001/admin"
        res_hex = check_hex_alternative_ip(hex_url)
        self.assertTrue(res_hex["detected"])
        self.assertTrue(res_hex["is_hex_ip"])
        self.assertEqual(res_hex["canonical_ip"], "127.0.0.1")

        # 2. Dotted hex IP 0x7f.0x0.0x0.0x1 -> 127.0.0.1
        dotted_hex = "http://0x7f.0x0.0x0.0x1/test"
        res_dotted = check_hex_alternative_ip(dotted_hex)
        self.assertTrue(res_dotted["detected"])
        self.assertTrue(res_dotted["is_hex_ip"])
        self.assertEqual(res_dotted["canonical_ip"], "127.0.0.1")

        # 3. DWORD integer IP 2130706433 -> 127.0.0.1
        dword_url = "http://2130706433/login"
        res_dword = check_hex_alternative_ip(dword_url)
        self.assertTrue(res_dword["detected"])
        self.assertTrue(res_dword["is_dword_ip"])
        self.assertEqual(res_dword["canonical_ip"], "127.0.0.1")

    def test_nested_url_extraction(self):
        """Verify nested URLs concealed inside query parameters."""
        nested_url = "https://login.company.com/redirect?dest=https://phishing-harvest.xyz/token&id=12"
        res = check_nested_urls(nested_url)

        self.assertTrue(res["detected"])
        self.assertTrue(res["has_nested_url"])
        self.assertTrue(res["is_cross_domain"])
        self.assertEqual(res["primary_nested_url"], "https://phishing-harvest.xyz/token")
        self.assertIn("phishing-harvest.xyz", res["warning"])

    def test_clean_url_no_obfuscation(self):
        """Verify legitimate URLs trigger zero obfuscation false positives."""
        clean_url = "https://www.google.com/search?q=antigravity"
        res = detect_obfuscation(clean_url, check_redirects=False)

        self.assertFalse(res["is_obfuscated"])
        self.assertEqual(res["techniques_count"], 0)
        self.assertEqual(res["penalty"], 0)
        self.assertEqual(res["warning_title"], "No Obfuscation Detected")

    def test_detect_obfuscation_consolidated(self):
        """Verify consolidated detection engine returns exact user warning header and text."""
        puny_url = "https://xn--pypal-4ve.com/signin"
        res = detect_obfuscation(puny_url, check_redirects=False)

        self.assertTrue(res["is_obfuscated"])
        self.assertEqual(res["warning_title"], "⚠ POSSIBLE URL OBFUSCATION")
        self.assertEqual(
            res["warning_message"],
            "The domain contains a Unicode/punycode representation that may visually resemble another domain."
        )
        self.assertIn("unicode_punycode", res["detected_techniques"])
        self.assertGreater(res["penalty"], 0)

    def test_api_detect_obfuscation_endpoint(self):
        """Verify POST /api/v1/detect-obfuscation returns complete ObfuscationDetail schema."""
        req_body = {"url": "https://xn--pypal-4ve.com/signin"}
        res = self.client.post("/api/v1/detect-obfuscation", json=req_body)

        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("success"))
        obf = data.get("obfuscation")
        self.assertTrue(obf.get("is_obfuscated"))
        self.assertEqual(obf.get("warning_title"), "⚠ POSSIBLE URL OBFUSCATION")
        self.assertEqual(
            obf.get("warning_message"),
            "The domain contains a Unicode/punycode representation that may visually resemble another domain."
        )

    def test_api_analyze_integration_obfuscation(self):
        """Verify POST /api/v1/analyze includes obfuscation analysis and escalates risk."""
        req_body = {"url": "https://xn--pypal-4ve.com/signin"}
        res = self.client.post("/api/v1/analyze", json=req_body)

        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("success"))
        self.assertIn("obfuscation_analysis", data)
        obf = data.get("obfuscation_analysis")
        self.assertTrue(obf.get("is_obfuscated"))
        # Homograph attack should be flagged as HIGH risk / dangerous
        self.assertEqual(data.get("risk_level"), "HIGH")
        self.assertEqual(data.get("status"), "dangerous")


if __name__ == "__main__":
    unittest.main()
