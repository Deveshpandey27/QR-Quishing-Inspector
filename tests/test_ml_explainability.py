import unittest
from app.detection.features import extract_url_features
from app.detection.explainability import explain_prediction
from app.detection.risk_engine import calculate_composite_risk
from app.schemas.analysis import FeatureContribution, MlExplanation
from app.main import app
from starlette.testclient import TestClient


class TestMlExplainability(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_explain_prediction_malicious_ip_url(self):
        url = "http://192.168.1.20/login/verify/account"
        feats = extract_url_features(url)
        exp = explain_prediction(feats, url)

        self.assertIn("signals", exp)
        self.assertIn("top_suspicious", exp)
        self.assertIn("top_legitimate", exp)
        self.assertIn("summary_text", exp)

        susp_features = [s["feature"] for s in exp["top_suspicious"]]
        susp_symbols = [s["symbol"] for s in exp["top_suspicious"]]
        susp_directions = [s["direction"] for s in exp["top_suspicious"]]

        # Verify key phishing indicators are flagged as risk escalators (↑)
        self.assertIn("has_ip_address", susp_features)
        self.assertIn("url_length", susp_features)
        self.assertIn("suspicious_keyword_count", susp_features)
        self.assertIn("has_https", susp_features)

        # All suspicious items must have ↑ and direction 'up'
        for s in exp["top_suspicious"]:
            self.assertEqual(s["direction"], "up")
            self.assertEqual(s["symbol"], "↑")
            self.assertGreater(s["impact_score"], 0)

        # Check prompt-matching summary text contains the key signals
        summary = exp["summary_text"]
        self.assertIn("ML Explanation", summary)
        self.assertIn("Strong contributing signals:", summary)
        self.assertIn("↑ IP address", summary)
        self.assertIn("↑ URL length", summary)

    def test_explain_prediction_legitimate_url(self):
        url = "https://google.com"
        feats = extract_url_features(url)
        exp = explain_prediction(feats, url)

        legit_features = [s["feature"] for s in exp["top_legitimate"]]
        legit_symbols = [s["symbol"] for s in exp["top_legitimate"]]
        legit_directions = [s["direction"] for s in exp["top_legitimate"]]

        # Verify HTTPS and compact URL length are flagged as safety mitigators (↓)
        self.assertIn("has_https", legit_features)
        self.assertIn("url_length", legit_features)

        for s in exp["top_legitimate"]:
            self.assertEqual(s["direction"], "down")
            self.assertEqual(s["symbol"], "↓")

        summary = exp["summary_text"]
        self.assertIn("↓ HTTPS", summary)

    def test_subdomain_and_special_char_attribution(self):
        url = "http://paypal.com.verify-billing.update.attacker.xyz/login?session=123&user=456"
        feats = extract_url_features(url)
        exp = explain_prediction(feats, url)

        susp_features = [s["feature"] for s in exp["top_suspicious"]]
        self.assertIn("subdomain_count", susp_features)
        self.assertIn("url_length", susp_features)
        self.assertIn("suspicious_keyword_count", susp_features)

    def test_schema_serialization(self):
        url = "http://192.168.1.20/login/verify/account"
        feats = extract_url_features(url)
        exp_dict = explain_prediction(feats, url)

        # Validate with Pydantic schema
        explanation_model = MlExplanation(**exp_dict)
        self.assertIsInstance(explanation_model, MlExplanation)
        self.assertGreater(len(explanation_model.top_suspicious), 0)

        for item in explanation_model.top_suspicious:
            self.assertIsInstance(item, FeatureContribution)
            self.assertEqual(item.direction, "up")
            self.assertEqual(item.symbol, "↑")

    def test_risk_engine_integrates_explanation(self):
        url = "http://192.168.1.20/login/verify/account"
        composite = calculate_composite_risk(url)

        self.assertTrue(composite["success"])
        self.assertIn("ml_detail", composite)
        ml = composite["ml_detail"]
        self.assertIn("explanation", ml)
        self.assertIsNotNone(ml["explanation"])
        self.assertIn("top_suspicious", ml["explanation"])

    def test_api_analyze_endpoint_returns_explanation(self):
        response = self.client.post("/api/v1/analyze", json={"url": "http://192.168.1.20/login/verify/account"})
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertIn("ml_detail", data)
        ml = data["ml_detail"]
        self.assertIn("explanation", ml)
        self.assertIsNotNone(ml["explanation"])
        self.assertIn("top_suspicious", ml["explanation"])
        self.assertGreater(len(ml["explanation"]["top_suspicious"]), 0)


if __name__ == "__main__":
    unittest.main()
