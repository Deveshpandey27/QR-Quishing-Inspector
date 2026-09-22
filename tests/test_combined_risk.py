import unittest
import os
import json
from fastapi.testclient import TestClient
from app.main import app
from app.detection.domain_intel import calculate_domain_signals_score
from app.detection.risk_engine import (
    calculate_composite_risk,
    WEIGHT_RULE,
    WEIGHT_ML,
    WEIGHT_DOMAIN,
    CONSENSUS_BONUS,
)


class TestCombinedRiskEngine(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_calibrated_weights_constants(self):
        """Verify empirical weights sum to 1.0 and match calibration experiment (35/45/20)."""
        self.assertAlmostEqual(WEIGHT_RULE + WEIGHT_ML + WEIGHT_DOMAIN, 1.0, places=5)
        self.assertEqual(WEIGHT_RULE, 0.35)
        self.assertEqual(WEIGHT_ML, 0.45)
        self.assertEqual(WEIGHT_DOMAIN, 0.20)
        self.assertGreater(CONSENSUS_BONUS, 0)

    def test_weights_calibration_json_persisted(self):
        """Verify ml/models/weights_calibration.json exists and contains optimal weights config."""
        calib_file = os.path.join(os.path.dirname(__file__), "..", "ml", "models", "weights_calibration.json")
        self.assertTrue(os.path.exists(calib_file), f"Missing calibration file: {calib_file}")
        with open(calib_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("selected_weights", data)
        opt = data["selected_weights"]
        self.assertEqual(opt["rule"], 0.35)
        self.assertEqual(opt["ml"], 0.45)
        self.assertEqual(opt["domain"], 0.20)
        self.assertIn("configurations", data)
        self.assertGreaterEqual(len(data["configurations"]), 3)

    def test_domain_signals_score_calculation(self):
        """Verify calculate_domain_signals_score penalizes missing TLS, new domains, and IP hosts."""
        # Case 1: Trusted reputable domain with valid TLS
        mock_intel_trusted = {"is_ip": False, "whois": {"is_recently_registered": False}, "dns": {"status": "resolved"}}
        mock_tls_valid = {"has_https": True, "certificate_valid": True, "hostname_match": True, "expiry_days": 180}
        score_trusted = calculate_domain_signals_score(mock_intel_trusted, mock_tls_valid, is_trusted=True)
        self.assertEqual(score_trusted["score"], 0)

        # Case 2: Insecure IP host with HTTP
        mock_intel_ip = {"is_ip": True, "whois": {}, "dns": {"status": "direct_ip"}}
        mock_tls_http = {"has_https": False, "certificate_valid": False, "hostname_match": False}
        score_ip = calculate_domain_signals_score(mock_intel_ip, mock_tls_http, is_trusted=False)
        self.assertGreaterEqual(score_ip["score"], 65)

        # Case 3: Untrusted domain with expired TLS & recently registered
        mock_intel_recent = {"is_ip": False, "whois": {"is_recently_registered": True}, "dns": {"status": "resolved"}}
        mock_tls_expired = {"has_https": True, "certificate_valid": False, "certificate_status": "expired", "hostname_match": True}
        score_recent = calculate_domain_signals_score(mock_intel_recent, mock_tls_expired, is_trusted=False)
        self.assertGreaterEqual(score_recent["score"], 60)

    def test_composite_risk_synthesis_high_attack(self):
        """Verify composite risk synthesis for known attack target produces HIGH risk level and required triad."""
        url = "http://192.168.1.20/login/verify/account"
        result = calculate_composite_risk(url)
        self.assertTrue(result["success"])
        
        # Check that the 3 pillars are present
        self.assertIn("rule_score", result)
        self.assertIn("ml_score", result)
        self.assertIn("domain_score", result)
        self.assertIn("score", result)
        self.assertIn("risk_level", result)
        self.assertIn("risk_weights", result)

        # Specific values check
        self.assertEqual(result["rule_score"], 86)
        self.assertGreaterEqual(result["ml_score"], 80)
        self.assertGreaterEqual(result["domain_score"], 60)
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertGreaterEqual(result["score"], 70)
        self.assertEqual(result["status"], "dangerous")

        # Check weights dictionary
        weights = result["risk_weights"]
        self.assertEqual(weights["rule"], 0.35)
        self.assertEqual(weights["ml"], 0.45)
        self.assertEqual(weights["domain"], 0.20)

    def test_composite_risk_synthesis_safe_destination(self):
        """Verify composite risk synthesis for reputable safe target produces LOW risk level and 0 scores."""
        url = "https://google.com"
        result = calculate_composite_risk(url)
        self.assertTrue(result["success"])
        self.assertEqual(result["rule_score"], 0)
        self.assertEqual(result["domain_score"], 0)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["status"], "safe")

    def test_risk_calibration_api_endpoint(self):
        """Test GET /api/v1/risk-calibration endpoint returns 200 with calibration config."""
        response = self.client.get("/api/v1/risk-calibration")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["selected_weights"]["rule"], 0.35)
        self.assertEqual(data["selected_weights"]["ml"], 0.45)
        self.assertEqual(data["selected_weights"]["domain"], 0.20)
        self.assertIn("configurations", data)
        self.assertIn("rationale", data)

    def test_analyze_api_response_contains_section8_fields(self):
        """Test POST /api/v1/analyze returns domain_score, risk_level, and risk_weights."""
        payload = {"url": "https://google.com"}
        response = self.client.post("/api/v1/analyze", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn("domain_score", data)
        self.assertIn("risk_level", data)
        self.assertIn("risk_weights", data)
        self.assertEqual(data["risk_level"], "LOW")


if __name__ == "__main__":
    unittest.main()
