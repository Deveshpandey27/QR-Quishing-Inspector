import unittest
from app.detection.tls_analyzer import inspect_tls, evaluate_tls_risk_signal, _TLS_CACHE


class TestTLSAnalyzer(unittest.TestCase):

    def test_plain_http_url(self):
        result = inspect_tls("http://192.168.1.20/login/verify/account")
        self.assertFalse(result["has_https"])
        self.assertFalse(result["certificate_valid"])
        self.assertEqual(result["certificate_status"], "missing_https")
        self.assertFalse(result["hostname_match"])
        self.assertIsNone(result["expiry_days"])
        self.assertIn("N/A", result["expiry_text"])

    def test_live_https_google(self):
        result = inspect_tls("https://google.com")
        self.assertTrue(result["has_https"])
        self.assertTrue(result["certificate_valid"])
        self.assertEqual(result["certificate_status"], "valid")
        self.assertTrue(result["hostname_match"])
        self.assertIsNotNone(result["expiry_days"])
        self.assertGreater(result["expiry_days"], 0)
        self.assertIn("days", result["expiry_text"])
        self.assertIsNotNone(result["issuer"])
        self.assertIsNotNone(result["subject_cn"])

    def test_valid_https_non_immunity_principle(self):
        """
        Cybersecurity principle:
        Valid HTTPS does NOT mean the site is trustworthy. Phishing sites
        can have perfectly valid certificates.
        """
        valid_mock = {
            "has_https": True,
            "certificate_valid": True,
            "certificate_status": "valid",
            "hostname_match": True,
            "expiry_days": 42,
            "expiry_text": "42 days",
        }
        sig = evaluate_tls_risk_signal(valid_mock)
        # Valid cert adds 0 penalty, but does not wipe other indicators
        self.assertEqual(sig["penalty"], 0)
        self.assertEqual(len(sig["indicators"]), 0)

    def test_invalid_expired_tls_signal(self):
        expired_mock = {
            "has_https": True,
            "certificate_valid": False,
            "certificate_status": "expired",
            "hostname_match": True,
            "warning": "TLS certificate has expired."
        }
        sig = evaluate_tls_risk_signal(expired_mock)
        self.assertEqual(sig["penalty"], 25)
        self.assertIn("Invalid TLS certificate (Expired)", sig["detected"])
        reasons_text = " ".join(sig["reasons"])
        self.assertIn("Expired", reasons_text)

    def test_self_signed_tls_signal(self):
        self_signed_mock = {
            "has_https": True,
            "certificate_valid": False,
            "certificate_status": "self_signed",
            "hostname_match": True,
            "warning": "Self-signed certificate."
        }
        sig = evaluate_tls_risk_signal(self_signed_mock)
        self.assertEqual(sig["penalty"], 25)
        self.assertIn("Invalid TLS certificate (Self Signed)", sig["detected"])

    def test_tls_caching(self):
        test_key = "tls-cache-test.org:443"
        import time
        _TLS_CACHE[test_key] = (time.time(), {
            "has_https": True,
            "certificate_valid": True,
            "certificate_status": "valid",
            "hostname_match": True,
            "expiry_days": 42,
            "expiry_text": "42 days",
            "cached": True,
        })
        res = inspect_tls("https://tls-cache-test.org")
        self.assertTrue(res.get("cached"))


if __name__ == "__main__":
    unittest.main()
