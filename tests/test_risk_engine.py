import unittest
from app.detection.risk_engine import calculate_composite_risk


class TestRiskEngine(unittest.TestCase):

    def test_invalid_empty_url(self):
        result = calculate_composite_risk("")
        self.assertFalse(result["success"])
        self.assertEqual(result.get("status_code"), 400)

    def test_trusted_domain_score_zero(self):
        result = calculate_composite_risk("https://google.com")
        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "safe")
        self.assertEqual(result["rule_score"], 0)
        self.assertLess(result["score"], 20)

    def test_trusted_domain_login_whitelist_protection(self):
        # Whitelist suppression ensures login path doesn't produce false dangerous status
        result = calculate_composite_risk("https://accounts.google.com/login")
        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "safe")
        self.assertTrue(result["is_trusted"])
        self.assertLess(result["score"], 25)

    def test_ip_phishing_dangerous(self):
        result = calculate_composite_risk("http://192.168.1.50/login/verify")
        self.assertTrue(result["success"])
        self.assertIn(result["status"], ["suspicious", "dangerous"])
        self.assertGreaterEqual(result["score"], 50)
        self.assertTrue(result["is_ip"])

    def test_brand_impersonation_detection(self):
        result = calculate_composite_risk("https://paypal.com.attacker.xyz/login")
        self.assertTrue(result["success"])
        self.assertIn(result["status"], ["suspicious", "dangerous"])
        self.assertGreaterEqual(result["score"], 50)

    def test_url_shortener_flag(self):
        result = calculate_composite_risk("https://bit.ly/secure-token")
        self.assertTrue(result["success"])
        self.assertTrue(result["is_shortener"])
        self.assertGreaterEqual(result["score"], 35)

    def test_user_example_composite_risk_86(self):
        result = calculate_composite_risk("http://192.168.1.20/login/verify/account")
        self.assertTrue(result["success"])
        self.assertEqual(result["rule_score"], 86)
        self.assertGreaterEqual(result["score"], 85)
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertEqual(result["status"], "dangerous")
        self.assertIn("HTTP instead of HTTPS", result["detected"])
        self.assertIn("IP address detected", result["detected"])
        self.assertIn("Login keyword", result["detected"])
        self.assertIn("Verify keyword", result["detected"])
        self.assertIn("Account keyword", result["detected"])


if __name__ == "__main__":
    unittest.main()
