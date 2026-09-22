import unittest
from fastapi.testclient import TestClient
from app.main import app
from app.services.report_service import generate_text_report, generate_pdf_report
from app.services.history_service import reset_seed_history


class TestSecurityReport(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)
        reset_seed_history()

    def test_text_report_format_exact_match(self):
        """Verify generated text report matches the user's exact specification."""
        analysis_data = {
            "url": "https://example.xyz/login",
            "hostname": "example.xyz",
            "score": 87,
            "risk_level": "HIGH",
            "status": "dangerous",
            "detected": [
                "Suspicious domain",
                "Login keyword",
                "Recently registered domain",
                "Multiple URL indicators"
            ],
            "ml_detail": {
                "suspicious_probability": 91.3,
                "model_name": "HistGradientBoosting"
            }
        }

        report = generate_text_report(analysis_data)

        # 1. Header
        self.assertIn("QR QUISHING INSPECTOR", report)
        self.assertIn("Security Analysis Report", report)

        # 2. URL section
        self.assertIn("URL:\nhttps://example.xyz/login", report)

        # 3. Risk section
        self.assertIn("Risk:\nHIGH — 87/100", report)

        # 4. Findings section
        self.assertIn("Findings:", report)
        self.assertIn("• Suspicious domain", report)
        self.assertIn("• Login keyword", report)
        self.assertIn("• Recently registered domain", report)
        self.assertIn("• Multiple URL indicators", report)

        # 5. ML section
        self.assertIn("ML:\n91.3% suspicious", report)

        # 6. Recommendation section
        self.assertIn("Recommendation:\nDo not enter credentials or payment information.", report)

    def test_text_report_low_risk(self):
        """Verify safe destination text report produces clean recommendations."""
        safe_data = {
            "url": "https://google.com",
            "hostname": "google.com",
            "score": 0,
            "risk_level": "LOW",
            "status": "safe",
            "detected": [],
            "ml_detail": {
                "suspicious_probability": 0.0
            }
        }
        report = generate_text_report(safe_data)
        self.assertIn("Risk:\nLOW — 0/100", report)
        self.assertIn("0.0% suspicious", report)
        self.assertIn("Safe destination verified.", report)

    def test_pdf_report_generation(self):
        """Verify PDF generator produces a valid non-empty PDF binary."""
        test_data = {
            "url": "https://example.xyz/login",
            "hostname": "example.xyz",
            "score": 87,
            "risk_level": "HIGH",
            "status": "dangerous",
            "detected": [
                "Suspicious domain",
                "Login keyword"
            ],
            "ml_detail": {
                "suspicious_probability": 91.3,
                "model_name": "HistGradientBoosting"
            }
        }
        pdf_bytes = generate_pdf_report(test_data)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
        self.assertGreater(len(pdf_bytes), 1500)

    def test_api_post_report_text(self):
        """Verify POST /api/v1/report/text returns 200 with formatted report_text."""
        payload = {
            "url": "https://example.xyz/login",
            "score": 87,
            "risk_level": "HIGH",
            "detected": ["Suspicious domain", "Login keyword"],
            "ml_detail": {"suspicious_probability": 91.3}
        }
        res = self.client.post("/api/v1/report/text", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertIn("QR QUISHING INSPECTOR", data["report_text"])
        self.assertIn("HIGH — 87/100", data["report_text"])

    def test_api_post_report_pdf(self):
        """Verify POST /api/v1/report/pdf streams downloadable PDF binary."""
        payload = {
            "url": "https://example.xyz/login",
            "hostname": "example.xyz",
            "score": 87,
            "risk_level": "HIGH"
        }
        res = self.client.post("/api/v1/report/pdf", json=payload)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers["content-type"], "application/pdf")
        self.assertIn("attachment; filename=", res.headers.get("content-disposition", ""))
        self.assertTrue(res.content.startswith(b"%PDF-"))

    def test_api_get_history_report_pdf(self):
        """Verify GET /api/v1/report/{scan_id}/pdf generates PDF for historical scan."""
        res = self.client.get("/api/v1/report/scan_seed_2/pdf")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers["content-type"], "application/pdf")
        self.assertTrue(res.content.startswith(b"%PDF-"))

    def test_api_get_history_report_text(self):
        """Verify GET /api/v1/report/{scan_id}/text returns text report for historical scan."""
        res = self.client.get("/api/v1/report/scan_seed_2/text")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertIn("example.xyz", data["report_text"])
        self.assertIn("HIGH — 85/100", data["report_text"])

    def test_api_get_history_report_not_found(self):
        """Verify 404 response for nonexistent historical scan."""
        res = self.client.get("/api/v1/report/invalid-scan-id-xyz/pdf")
        self.assertEqual(res.status_code, 404)


if __name__ == "__main__":
    unittest.main()
