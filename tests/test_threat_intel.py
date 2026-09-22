import unittest
from fastapi.testclient import TestClient
from app.main import app
from app.detection.threat_intel import query_threat_intelligence, _THREAT_INTEL_CACHE
from app.detection.risk_engine import calculate_composite_risk


class TestThreatIntelligence(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_known_malicious_detection(self):
        """Verify known reported quishing URL produces YES, 3 matches, and advisory warning."""
        url = "http://192.168.1.20/login/verify/account"
        result = query_threat_intelligence(url)

        self.assertTrue(result["known_malicious"])
        self.assertEqual(result["matches_count"], 3)
        self.assertEqual(result["sources_checked"], 5)
        self.assertEqual(
            result["warning_message"],
            "⚠ External intelligence indicates this URL has been reported."
        )
        self.assertIn("Known malicious URL:     YES", result["summary_text"])
        self.assertIn("Threat database matches: 3", result["summary_text"])
        self.assertIn("⚠ External intelligence indicates\n   this URL has been reported.", result["summary_text"])

    def test_clean_url_detection(self):
        """Verify reputable destination produces NO, 0 matches, and clean advisory."""
        url = "https://google.com"
        result = query_threat_intelligence(url)

        self.assertFalse(result["known_malicious"])
        self.assertEqual(result["matches_count"], 0)
        self.assertIsNone(result["warning_message"])
        self.assertIn("Known malicious URL:     NO", result["summary_text"])
        self.assertIn("Threat database matches: 0", result["summary_text"])

    def test_providers_structure(self):
        """Verify all 5 threat intelligence providers are reported with standardized fields."""
        url = "http://192.168.1.20/login/verify/account"
        result = query_threat_intelligence(url)

        providers = result["providers"]
        self.assertEqual(len(providers), 5)
        provider_names = [p["name"] for p in providers]
        self.assertIn("URLhaus (abuse.ch)", provider_names)
        self.assertIn("PhishTank", provider_names)
        self.assertIn("Google Safe Browsing", provider_names)
        self.assertIn("VirusTotal", provider_names)
        self.assertIn("OpenPhish & Quishing IOC Feed", provider_names)

        for p in providers:
            self.assertIn("name", p)
            self.assertIn("checked", p)
            self.assertIn("matched", p)
            self.assertIn("status", p)
            self.assertIn(p["status"], ["malicious", "clean", "unconfigured", "rate_limited", "error"])

    def test_caching_performance(self):
        """Verify subsequent query for same URL uses cached response."""
        url = "https://example.com"
        res1 = query_threat_intelligence(url)
        cache_key = url.strip().lower()
        self.assertIn(cache_key, _THREAT_INTEL_CACHE)
        
        # Second call should fetch exact same object from cache
        res2 = query_threat_intelligence(url)
        self.assertEqual(res1["matches_count"], res2["matches_count"])
        self.assertEqual(res1["known_malicious"], res2["known_malicious"])

    def test_risk_engine_threat_intel_integration(self):
        """Verify calculate_composite_risk incorporates threat intelligence ground truth."""
        url = "http://192.168.1.20/login/verify/account"
        result = calculate_composite_risk(url)

        self.assertTrue(result["success"])
        self.assertIn("threat_intel", result)
        ti = result["threat_intel"]
        self.assertTrue(ti["known_malicious"])
        self.assertEqual(ti["matches_count"], 3)
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertEqual(result["status"], "dangerous")
        self.assertGreaterEqual(result["score"], 90)

        # Check detected and indicators
        detected_str = " ".join(result["detected"])
        self.assertIn("Threat intelligence match", detected_str)

        indicator_names = [ind["name"] for ind in result["indicators"]]
        self.assertIn("threat_intel_match", indicator_names)

    def test_threat_intel_api_endpoint(self):
        """Verify GET /api/v1/threat-intel returns 200 with complete ThreatIntelligenceResult schema."""
        url = "http://192.168.1.20/login/verify/account"
        response = self.client.get(f"/api/v1/threat-intel?url={url}")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data["known_malicious"])
        self.assertEqual(data["matches_count"], 3)
        self.assertEqual(data["sources_checked"], 5)
        self.assertIn("providers", data)
        self.assertEqual(len(data["providers"]), 5)
        self.assertEqual(data["warning_message"], "⚠ External intelligence indicates this URL has been reported.")

    def test_analyze_endpoint_returns_threat_intel(self):
        """Verify POST /api/v1/analyze includes threat_intel in the AnalyzeResponse."""
        payload = {"url": "http://192.168.1.20/login/verify/account"}
        response = self.client.post("/api/v1/analyze", json=payload)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn("threat_intel", data)
        self.assertIsNotNone(data["threat_intel"])
        self.assertTrue(data["threat_intel"]["known_malicious"])
        self.assertEqual(data["threat_intel"]["matches_count"], 3)


if __name__ == "__main__":
    unittest.main()
