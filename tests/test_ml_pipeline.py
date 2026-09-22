import unittest
from app.detection.ml import predict_url, get_model_benchmarks
from app.detection.risk_engine import calculate_composite_risk
from app.main import app
from starlette.testclient import TestClient


class TestMlPipeline(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_predict_url_returns_dual_probabilities(self):
        url = "http://192.168.1.20/login/verify/account"
        result = predict_url(url)

        self.assertIn("suspicious_probability", result)
        self.assertIn("legitimate_probability", result)
        self.assertIn("model_name", result)
        self.assertIn("features", result)

        susp = result["suspicious_probability"]
        legit = result["legitimate_probability"]

        self.assertIsInstance(susp, float)
        self.assertIsInstance(legit, float)
        self.assertGreaterEqual(susp, 0.0)
        self.assertLessEqual(susp, 100.0)
        self.assertGreaterEqual(legit, 0.0)
        self.assertLessEqual(legit, 100.0)
        self.assertAlmostEqual(round(susp + legit, 1), 100.0, places=1)

    def test_predict_url_returns_24_features(self):
        url = "https://paypal.com-security-alert.attacker.xyz/update-billing?session=892348"
        result = predict_url(url)
        features = result["features"]

        self.assertIsInstance(features, dict)
        self.assertEqual(len(features), 24)
        expected_keys = [
            "url_length", "hostname_length", "path_length", "query_length",
            "has_https", "has_ip_address", "dot_count_host", "dot_count_path",
            "hyphen_count_host", "hyphen_count_path", "underscore_count",
            "slash_count", "question_mark_count", "equals_count", "at_symbol",
            "percent_encoded", "has_double_slash_path", "subdomain_count",
            "num_digits_host", "num_digits_url", "entropy_hostname",
            "is_shortener", "is_punycode", "suspicious_keyword_count"
        ]
        for key in expected_keys:
            self.assertIn(key, features)

    def test_get_model_benchmarks_returns_5_algorithms(self):
        benchmarks = get_model_benchmarks()

        self.assertIn("dataset", benchmarks)
        self.assertIn("models", benchmarks)
        self.assertIn("active_model", benchmarks)

        models = benchmarks["models"]
        model_names = [m["model"] for m in models]

        expected_models = [
            "Logistic Regression",
            "Random Forest",
            "Decision Tree",
            "SVM (Linear)",
            "Gradient Boosting"
        ]
        for expected in expected_models:
            self.assertIn(expected, model_names)

        # Check metrics are formatted as percentages
        for m in models:
            self.assertGreater(m["accuracy"], 90.0)
            self.assertGreater(m["precision"], 90.0)
            self.assertGreater(m["recall"], 90.0)
            self.assertGreater(m["f1"], 90.0)

    def test_risk_engine_populates_ml_detail(self):
        url = "http://192.168.1.20/login/verify/account"
        composite = calculate_composite_risk(url)

        self.assertTrue(composite["success"])
        self.assertIn("ml_detail", composite)
        ml = composite["ml_detail"]
        self.assertIsNotNone(ml)
        self.assertIn("suspicious_probability", ml)
        self.assertIn("legitimate_probability", ml)
        self.assertIn("model_name", ml)
        self.assertIn("features", ml)
        self.assertGreater(ml["suspicious_probability"], 50.0)

    def test_api_ml_benchmarks_endpoint(self):
        response = self.client.get("/api/v1/ml/benchmarks")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("dataset", data)
        self.assertIn("models", data)
        self.assertEqual(len(data["models"]), 5)

    def test_api_analyze_endpoint_includes_ml_detail(self):
        response = self.client.post("/api/v1/analyze", json={"url": "https://google.com"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("ml_detail", data)
        ml = data["ml_detail"]
        self.assertIsNotNone(ml)
        self.assertIn("suspicious_probability", ml)
        self.assertIn("legitimate_probability", ml)
        self.assertIn("features", ml)


if __name__ == "__main__":
    unittest.main()
