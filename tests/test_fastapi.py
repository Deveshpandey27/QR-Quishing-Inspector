import unittest
from starlette.testclient import TestClient
from app.main import app


class TestFastAPIApplication(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_home_page_rendering(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("QR Quishing Inspector", response.text)
        self.assertIn("FastAPI", response.text)
        self.assertIn("Live Camera", response.text)
        self.assertIn("Upload Image", response.text)

    def test_openapi_docs_available(self):
        response = self.client.get("/docs")
        self.assertEqual(response.status_code, 200)
        self.assertIn("swagger", response.text.lower())

    def test_health_check_endpoint(self):
        response = self.client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["framework"], "FastAPI")
        self.assertTrue(data["ml_model_loaded"])

    def test_analyze_empty_payload(self):
        response = self.client.post("/api/v1/analyze", json={})
        self.assertEqual(response.status_code, 422)  # Pydantic validation error

    def test_analyze_empty_url(self):
        response = self.client.post("/api/v1/analyze", json={"url": "   "})
        self.assertEqual(response.status_code, 400)

    def test_analyze_safe_google(self):
        response = self.client.post("/api/v1/analyze", json={"url": "https://google.com"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "safe")
        self.assertEqual(data["rule_score"], 0)
        self.assertLess(data["score"], 25)

    def test_analyze_safe_google_login(self):
        response = self.client.post("/api/v1/analyze", json={"url": "https://accounts.google.com/login"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "safe")
        self.assertTrue(data["is_trusted"])

    def test_analyze_safe_github(self):
        response = self.client.post("/api/v1/analyze", json={"url": "https://github.com"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "safe")

    def test_analyze_southbank_mosaics_benign(self):
        response = self.client.post("/api/v1/analyze", json={"url": "https://www.southbankmosaics.com"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "safe")
        self.assertEqual(data["rule_score"], 0)

    def test_analyze_ip_phishing(self):
        response = self.client.post("/api/v1/analyze", json={"url": "http://192.168.1.50/login/verify"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn(data["status"], ["suspicious", "dangerous"])
        self.assertGreaterEqual(data["rule_score"], 40)
        reasons_text = " ".join(data["reasons"])
        self.assertIn("IP address", reasons_text)

    def test_analyze_user_example_endpoint(self):
        response = self.client.post("/api/v1/analyze", json={"url": "http://192.168.1.20/login/verify/account"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["rule_score"], 86)
        self.assertGreaterEqual(data["score"], 85)
        self.assertEqual(data["risk_level"], "HIGH")
        self.assertEqual(data["status"], "dangerous")
        self.assertIn("HTTP instead of HTTPS", data["detected"])
        self.assertIn("IP address detected", data["detected"])
        self.assertIn("Login keyword", data["detected"])
        self.assertIn("Verify keyword", data["detected"])
        self.assertIn("Account keyword", data["detected"])
        self.assertIsNotNone(data.get("domain_intel"))
        self.assertTrue(data["domain_intel"]["is_ip"])
        self.assertEqual(data["domain_intel"]["dns"]["status"], "direct_ip")
        self.assertIsNotNone(data.get("tls_analysis"))
        self.assertFalse(data["tls_analysis"]["has_https"])
        self.assertEqual(data["tls_analysis"]["certificate_status"], "missing_https")

    def test_domain_intel_endpoint_ip(self):
        response = self.client.get("/api/v1/domain-intel?domain=192.168.1.20")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["domain"], "192.168.1.20")
        self.assertTrue(data["is_ip"])
        self.assertEqual(data["whois"]["status"], "na_ip_host")
        self.assertEqual(data["dns"]["status"], "direct_ip")

    def test_domain_intel_endpoint_empty(self):
        response = self.client.get("/api/v1/domain-intel?domain=  ")
        self.assertEqual(response.status_code, 400)

    def test_tls_analysis_endpoint_http_ip(self):
        response = self.client.get("/api/v1/tls-analysis?url=http://192.168.1.20/login")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertFalse(data["has_https"])
        self.assertFalse(data["certificate_valid"])
        self.assertEqual(data["certificate_status"], "missing_https")

    def test_tls_analysis_endpoint_empty(self):
        response = self.client.get("/api/v1/tls-analysis?url=  ")
        self.assertEqual(response.status_code, 400)

    def test_analyze_brand_impersonation(self):
        response = self.client.post("/api/v1/analyze", json={"url": "https://paypal.com.attacker.xyz/login"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn(data["status"], ["suspicious", "dangerous"])

    def test_analyze_url_shortener(self):
        response = self.client.post("/api/v1/analyze", json={"url": "https://bit.ly/secure-token"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertTrue(data["is_shortener"])
        self.assertIsNotNone(data.get("shortener_info"))
        self.assertTrue(data["shortener_info"]["is_shortener"])
        self.assertEqual(data["shortener_info"]["service_name"], "bit.ly")
        reasons_text = " ".join(data["reasons"])
        self.assertIn("⚠ URL SHORTENER DETECTED", reasons_text)
        self.assertIn("Destination cannot be trusted", reasons_text)

    def test_legacy_analyze_compatibility(self):
        response = self.client.post("/analyze", json={"url": "https://google.com"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "safe")

    def test_scan_image_empty_file(self):
        response = self.client.post(
            "/api/v1/scan-image",
            files={"file": ("empty.png", b"", "image/png")}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertFalse(data["success"])
        self.assertIn("empty", data["error"].lower())

    def test_scan_image_no_qr_detected(self):
        import cv2
        import numpy as np
        blank = np.full((100, 100, 3), 255, dtype=np.uint8)
        _, encoded = cv2.imencode(".png", blank)
        response = self.client.post(
            "/api/v1/scan-image",
            files={"file": ("blank.png", encoded.tobytes(), "image/png")}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertFalse(data["success"])
        self.assertIn("no qr code", data["error"].lower())


if __name__ == "__main__":
    unittest.main()
