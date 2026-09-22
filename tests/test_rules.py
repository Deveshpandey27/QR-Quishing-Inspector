import unittest
from app.detection.normalizer import normalize_url
from app.detection.rules import analyze_url_security, _matches_keyword


class TestURLNormalizer(unittest.TestCase):

    def test_default_scheme(self):
        res = normalize_url("example.com/path")
        self.assertTrue(res["valid"])
        self.assertEqual(res["scheme"], "https")
        self.assertEqual(res["url"], "https://example.com/path")

    def test_whitespace_trimming(self):
        res = normalize_url("   https://google.com   ")
        self.assertTrue(res["valid"])
        self.assertEqual(res["hostname"], "google.com")

    def test_ip_address_detection(self):
        res = normalize_url("http://192.168.1.1:8080/admin")
        self.assertTrue(res["valid"])
        self.assertTrue(res["is_ip"])
        self.assertEqual(res["hostname"], "192.168.1.1")

    def test_shortener_detection(self):
        res = normalize_url("https://bit.ly/3XYZ")
        self.assertTrue(res["valid"])
        self.assertTrue(res["is_shortener"])

    def test_punycode_detection(self):
        res = normalize_url("https://xn--pple-43d.com")
        self.assertTrue(res["valid"])
        self.assertTrue(res["is_punycode"])

    def test_subdomain_extraction(self):
        res = normalize_url("https://accounts.google.com/login")
        self.assertEqual(res["registered_domain"], "google.com")
        self.assertEqual(res["subdomains"], ["accounts"])

    def test_empty_url(self):
        res = normalize_url("")
        self.assertFalse(res["valid"])


class TestSecurityRules(unittest.TestCase):

    def test_keyword_word_boundary(self):
        # "bank" should match in "/bank/login" but NOT inside "southbank" or "riverbank"
        self.assertTrue(_matches_keyword("/bank/login", "bank"))
        self.assertTrue(_matches_keyword("bank.com", "bank"))
        self.assertFalse(_matches_keyword("https://www.southbankmosaics.com", "bank"))
        self.assertFalse(_matches_keyword("riverbank.org", "bank"))

    def test_safe_trusted_domains(self):
        # Top reputable domains should have score 0 and LOW RISK
        safe_urls = [
            "https://google.com",
            "https://www.google.com",
            "https://github.com",
            "https://amazon.com",
            "https://paypal.com",
        ]
        for url in safe_urls:
            res = analyze_url_security(url)
            self.assertEqual(res["risk_level"], "LOW RISK", f"Failed for {url}")
            self.assertEqual(res["score"], 0, f"Expected 0 score for {url}, got {res['score']}")

    def test_trusted_domain_login_not_penalized(self):
        # Legitimate login pages on trusted domains must not be flagged
        res = analyze_url_security("https://accounts.google.com/login")
        self.assertEqual(res["risk_level"], "LOW RISK")
        self.assertEqual(res["score"], 0)
        self.assertTrue(res["is_trusted"])

    def test_southbank_false_positive_eliminated(self):
        # southbankmosaics.com must have score 0 (no false positive from 'bank')
        res = analyze_url_security("https://www.southbankmosaics.com")
        self.assertEqual(res["risk_level"], "LOW RISK")
        self.assertEqual(res["score"], 0)

    def test_ip_address_host(self):
        res = analyze_url_security("http://192.168.1.50/login/verify")
        self.assertGreaterEqual(res["score"], 50)
        self.assertIn("risk_level", res)
        self.assertIn(res["risk_level"], ["SUSPICIOUS", "HIGH RISK"])
        indicators = [ind["name"] for ind in res["indicators"]]
        self.assertIn("ip_host", indicators)
        self.assertIn("missing_https", indicators)

    def test_brand_impersonation(self):
        res = analyze_url_security("https://paypal.com.account-verify.xyz/login")
        indicators = [ind["name"] for ind in res["indicators"]]
        self.assertIn("brand_impersonation", indicators)
        self.assertGreaterEqual(res["score"], 35)

    def test_url_shortener_quishing(self):
        res = analyze_url_security("https://bit.ly/secure-account")
        indicators = [ind["name"] for ind in res["indicators"]]
        self.assertIn("url_shortener", indicators)
        self.assertGreaterEqual(res["score"], 25)

    def test_punycode_homograph(self):
        res = analyze_url_security("https://xn--pple-43d.com")
        indicators = [ind["name"] for ind in res["indicators"]]
        self.assertIn("punycode_homograph", indicators)
        self.assertGreaterEqual(res["score"], 30)

    def test_at_symbol_credential_evasion(self):
        res = analyze_url_security("http://google.com@attacker-site.com/path")
        indicators = [ind["name"] for ind in res["indicators"]]
        self.assertIn("embedded_credentials_at_symbol", indicators)
        self.assertGreaterEqual(res["score"], 30)

    def test_double_slash_evasion(self):
        res = analyze_url_security("https://attacker-site.com//redirect")
        indicators = [ind["name"] for ind in res["indicators"]]
        self.assertIn("double_slash_evasion", indicators)

    def test_user_example_86_risk_score(self):
        # Specific user requirement: http://192.168.1.20/login/verify/account
        res = analyze_url_security("http://192.168.1.20/login/verify/account")
        self.assertEqual(res["score"], 86)
        self.assertEqual(res["risk_level"], "HIGH RISK")
        expected_detected = [
            "HTTP instead of HTTPS",
            "IP address detected",
            "Account keyword",
            "Login keyword",
            "Verify keyword",
        ]
        for item in expected_detected:
            self.assertIn(item, res["detected"])

    def test_all_13_characteristics_coverage(self):
        # 1. HTTPS missing
        res = analyze_url_security("http://unknown-domain.com")
        self.assertIn("HTTP instead of HTTPS", res["detected"])

        # 2. IP address
        res = analyze_url_security("http://10.0.0.1/test")
        self.assertIn("IP address detected", res["detected"])

        # 3. Unusually long URL
        res = analyze_url_security("https://unknown-domain.com/" + "a" * 120)
        self.assertIn("Unusually long URL", res["detected"])

        # 4. Excessive subdomains
        res = analyze_url_security("https://sub1.sub2.sub3.unknown-domain.com")
        self.assertIn("Excessive subdomains", res["detected"])

        # 5. Suspicious keywords
        res = analyze_url_security("https://unknown-domain.com/login")
        self.assertIn("Login keyword", res["detected"])

        # 6. Excessive hyphens
        res = analyze_url_security("https://my-secure-phish-domain.com")
        self.assertIn("Excessive hyphens", res["detected"])

        # 7. @ symbol
        res = analyze_url_security("https://brand.com@attacker-site.com/path")
        self.assertIn("@ symbol in URL", res["detected"])

        # 8. Percent encoding
        res = analyze_url_security("https://unknown-domain.com/%20%2f%3d")
        self.assertIn("Percent encoding", res["detected"])

        # 9. Suspicious TLD
        res = analyze_url_security("https://phishing-campaign.xyz")
        self.assertIn("Suspicious TLD (.xyz)", res["detected"])

        # 10. URL shortener
        res = analyze_url_security("https://bit.ly/test-quishing")
        self.assertIn("URL shortener", res["detected"])

        # 11. Unusual port
        res = analyze_url_security("https://unknown-domain.com:8443/app")
        self.assertIn("Unusual port (:8443)", res["detected"])

        # 12. Suspicious path
        res = analyze_url_security("https://unknown-domain.com/download/malware.apk")
        self.assertIn("Suspicious path", res["detected"])

        # 13. Suspicious query parameters
        res = analyze_url_security("https://unknown-domain.com/auth?redirect=http://evil.com&token=123")
        self.assertIn("Suspicious query parameters", res["detected"])

    def test_clean_detected_list_on_trusted_domains(self):
        res = analyze_url_security("https://google.com")
        self.assertEqual(res["detected"], [])
        res2 = analyze_url_security("https://accounts.google.com/login")
        self.assertEqual(res2["detected"], [])


if __name__ == "__main__":
    unittest.main()
