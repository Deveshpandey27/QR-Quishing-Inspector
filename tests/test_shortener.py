import unittest
from app.detection.normalizer import normalize_url
from app.detection.rules import analyze_url_security
from app.detection.risk_engine import calculate_composite_risk
from app.detection.redirect_inspector import inspect_shortener_redirect, _REDIRECT_CACHE


class TestURLShortenerDetection(unittest.TestCase):

    def test_all_five_target_shorteners_detected(self):
        """
        User Requirement:
        Detect:
        - bit.ly
        - tinyurl.com
        - t.co
        - is.gd
        - cutt.ly
        """
        targets = [
            "https://bit.ly/secure-token",
            "https://tinyurl.com/invoice-doc",
            "https://t.co/promo-link",
            "https://is.gd/account-update",
            "https://cutt.ly/verify-pin",
        ]
        for url in targets:
            norm = normalize_url(url)
            self.assertTrue(norm["is_shortener"], f"Failed to detect shortener: {url}")
            res = analyze_url_security(url)
            self.assertTrue(res["is_shortener"], f"Failed rule check for shortener: {url}")
            self.assertIn("URL shortener", res["detected"])

    def test_exact_shortener_warning_message(self):
        """
        User Requirement:
        Then report:
        ⚠ URL SHORTENER DETECTED
        The QR code points to a shortened URL.
        Destination cannot be trusted based only on the visible short URL.
        """
        res = analyze_url_security("https://bit.ly/test-target")
        reasons_text = " ".join(res["reasons"])
        self.assertIn("⚠ URL SHORTENER DETECTED", reasons_text)
        self.assertIn("The QR code points to a shortened URL", reasons_text)
        self.assertIn("Destination cannot be trusted based only on the visible short URL", reasons_text)

    def test_composite_risk_engine_shortener_info(self):
        res = calculate_composite_risk("https://tinyurl.com/verify-qr")
        self.assertTrue(res["is_shortener"])
        self.assertIsNotNone(res.get("shortener_info"))
        s_info = res["shortener_info"]
        self.assertTrue(s_info["is_shortener"])
        self.assertEqual(s_info["service_name"], "tinyurl.com")
        self.assertIn("Destination cannot be trusted", s_info["warning"])

    def test_benign_non_shortener_domains(self):
        for url in ["https://google.com", "https://github.com", "https://southbankmosaics.com"]:
            norm = normalize_url(url)
            self.assertFalse(norm["is_shortener"], f"False positive shortener: {url}")
            res = analyze_url_security(url)
            self.assertFalse(res["is_shortener"])

    def test_redirect_inspector_cache(self):
        test_url = "https://bit.ly/cached-unit-test"
        import time
        _REDIRECT_CACHE[test_url.lower()] = (time.time(), {
            "has_redirect": True,
            "redirect_target": "https://example.com/dest",
            "status_code": 301,
            "cached": True,
        })
        res = inspect_shortener_redirect(test_url)
        self.assertTrue(res.get("cached"))
        self.assertEqual(res.get("redirect_target"), "https://example.com/dest")


if __name__ == "__main__":
    unittest.main()
