import unittest
from datetime import datetime, timezone, timedelta
from app.detection.domain_intel import (
    _format_age,
    _normalize_datetime,
    get_domain_intelligence,
    evaluate_domain_risk_signal,
    _DOMAIN_INTEL_CACHE,
)


class TestDomainIntelligence(unittest.TestCase):

    def test_format_age(self):
        self.assertEqual(_format_age(0), "0 days")
        self.assertEqual(_format_age(1), "1 day")
        self.assertEqual(_format_age(11), "11 days")  # User example
        self.assertEqual(_format_age(29), "29 days")
        self.assertEqual(_format_age(60), "2 months")
        self.assertIn("year", _format_age(400))

    def test_normalize_datetime(self):
        now = datetime.now(timezone.utc)
        self.assertIsNotNone(_normalize_datetime(now))
        self.assertIsNotNone(_normalize_datetime("2026-09-01"))
        self.assertIsNotNone(_normalize_datetime("2026-09-01T12:00:00Z"))
        self.assertIsNotNone(_normalize_datetime([now]))
        self.assertIsNone(_normalize_datetime(None))

    def test_raw_ip_host_handling(self):
        intel = get_domain_intelligence("http://192.168.1.20/login/verify/account")
        self.assertTrue(intel["is_ip"])
        self.assertEqual(intel["domain"], "192.168.1.20")
        self.assertEqual(intel["whois"]["status"], "na_ip_host")
        self.assertFalse(intel["whois"]["is_recently_registered"])
        self.assertEqual(intel["dns"]["status"], "direct_ip")
        self.assertEqual(intel["dns"]["a_records"], ["192.168.1.20"])

    def test_recently_registered_domain_signal(self):
        """
        User Test Case:
        Domain: example.xyz
        Domain age: 11 days
        Signal: Recently registered domain (one signal, not an automatic verdict)
        """
        mock_intel = {
            "domain": "example.xyz",
            "is_ip": False,
            "whois": {
                "domain": "example.xyz",
                "creation_date": "2026-09-04",
                "age_days": 11,
                "age_text": "11 days",
                "is_recently_registered": True,
                "warning": "⚠ Recently registered domain",
                "status": "active",
            },
            "dns": {
                "a_records": ["93.184.216.34"],
                "mx_records": [],
                "nameservers": ["ns1.example.xyz"],
                "status": "resolved",
            }
        }
        sig = evaluate_domain_risk_signal(mock_intel)
        # Moderate penalty (+20) - NOT an automatic 100/100 verdict
        self.assertEqual(sig["penalty"], 20)
        self.assertIn("Recently registered domain (11 days old)", sig["detected"])
        reasons_str = " ".join(sig["reasons"])
        self.assertIn("11 days", reasons_str)
        self.assertIn("disposable phishing", reasons_str)

    def test_nxdomain_signal(self):
        mock_intel = {
            "domain": "nonexistent-quishing-domain-test.xyz",
            "is_ip": False,
            "whois": {"is_recently_registered": False},
            "dns": {"status": "nxdomain", "a_records": []}
        }
        sig = evaluate_domain_risk_signal(mock_intel)
        self.assertEqual(sig["penalty"], 25)
        self.assertIn("Unresolved domain (NXDOMAIN)", sig["detected"])

    def test_caching_behavior(self):
        # Pre-seed cache
        test_domain = "cache-test-domain.com"
        _DOMAIN_INTEL_CACHE[test_domain] = (
            datetime.now(timezone.utc).timestamp(),
            {"domain": test_domain, "cached": True, "whois": {}, "dns": {}}
        )
        cached = get_domain_intelligence(test_domain)
        self.assertTrue(cached.get("cached"))


if __name__ == "__main__":
    unittest.main()
