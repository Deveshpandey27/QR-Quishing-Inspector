"""
Unit tests for Section 12: QR Code Payload Detection & Credential Protection.
Verifies all 6 content types, exact warnings, password sanitization, and REST endpoints.
"""

import unittest
from fastapi.testclient import TestClient
from app.main import app
from app.detection.payload_classifier import (
    classify_payload,
    classify_qr_payload,
    sanitize_payload_for_storage,
    extract_embedded_urls,
)
from app.services.inspector_service import inspect_payload


class TestPayloadDetection(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_classify_wifi_exact_spec(self):
        """Verify Wi-Fi payload detection and exact security warning from user prompt."""
        wifi_raw = "WIFI:T:WPA;S=HomeNetwork;P=password;;"
        info = classify_payload(wifi_raw)

        self.assertEqual(info["content_type"], "wifi")
        self.assertEqual(info["type_label"], "Wi-Fi configuration")
        # User exact prompt requirement: "This QR code contains network credentials."
        self.assertEqual(info["security_warning"], "This QR code contains network credentials.")
        self.assertTrue(info.get("is_sensitive", True))
        self.assertEqual(info.get("ssid"), "HomeNetwork")
        self.assertEqual(info.get("auth_type"), "WPA")
        self.assertEqual(info.get("password"), "password")
        self.assertEqual(info.get("masked_password"), "••••••••")

    def test_classify_all_six_content_types(self):
        """Verify scanner identifies all 6 required content types:
        1. URL
        2. Plain text
        3. Email
        4. Phone number
        5. Wi-Fi configuration
        6. vCard/contact
        """
        samples = [
            ("https://github.com/google/antigravity", "url", "URL"),
            ("Just plain human text notes", "text", "Plain text"),
            ("mailto:security@example.com?subject=Quishing", "email", "Email"),
            ("tel:+18005550199", "phone", "Phone number"),
            ("WIFI:T:WPA;S=TestOffice;P=Secret123;;", "wifi", "Wi-Fi configuration"),
            ("BEGIN:VCARD\nVERSION:3.0\nFN:Alice Smith\nTEL:+15551234\nEND:VCARD", "vcard", "vCard/contact"),
        ]

        for raw_payload, expected_type, expected_label in samples:
            with self.subTest(payload=raw_payload):
                info = classify_payload(raw_payload)
                self.assertEqual(info["content_type"], expected_type)
                self.assertEqual(info["type_label"], expected_label)

    def test_email_matmsg_and_embedded_urls(self):
        """Verify MATMSG email format and extraction of embedded malicious URLs."""
        raw = "MATMSG:TO:target@victim.com;SUB:Urgent Invoice;BODY:Please verify your payment at https://evil-phish.xyz/pay ;;"
        info = classify_payload(raw)

        self.assertEqual(info["content_type"], "email")
        self.assertEqual(info.get("recipient"), "target@victim.com")
        self.assertEqual(info.get("subject"), "Urgent Invoice")
        self.assertIn("https://evil-phish.xyz/pay", info.get("embedded_urls", []))

    def test_vcard_embedded_quishing_link(self):
        """Verify vCard contact payload extracts embedded links to prevent covert quishing."""
        vcard_raw = (
            "BEGIN:VCARD\n"
            "VERSION:3.0\n"
            "FN:Dr. John Doe\n"
            "ORG:Acme Healthcare\n"
            "TEL:+1-555-867-5309\n"
            "EMAIL:john.doe@acme.org\n"
            "URL:http://192.168.1.100:8080/portal\n"
            "END:VCARD"
        )
        info = classify_payload(vcard_raw)

        self.assertEqual(info["content_type"], "vcard")
        self.assertEqual(info.get("name"), "Dr. John Doe")
        self.assertEqual(info.get("org"), "Acme Healthcare")
        self.assertEqual(info.get("phone"), "+1-555-867-5309")
        self.assertEqual(info.get("email"), "john.doe@acme.org")
        self.assertEqual(info.get("url"), "http://192.168.1.100:8080/portal")
        self.assertIn("http://192.168.1.100:8080/portal", info.get("embedded_urls", []))

    def test_sanitize_payload_for_storage(self):
        """Verify sensitive Wi-Fi passwords are redacted before saving to disk or audit logs."""
        raw_wifi = "WIFI:T:WPA;S=MyCorpOffice;P=SuperSecretPassword123;;;H=false;"
        sanitized = sanitize_payload_for_storage(raw_wifi)

        self.assertNotIn("SuperSecretPassword123", sanitized)
        self.assertIn("P=********;", sanitized)
        self.assertIn("S=MyCorpOffice;", sanitized)

        # Non-wifi payloads should remain unchanged
        raw_url = "https://safe-domain.org/landing"
        self.assertEqual(sanitize_payload_for_storage(raw_url), raw_url)

    def test_embedded_url_extractor(self):
        """Verify regex extraction of multiple embedded URLs in plain text or messages."""
        text = "Hello team, see https://legit.org and http://phishing.xyz/token?id=12 for updates."
        urls = extract_embedded_urls(text)
        self.assertEqual(len(urls), 2)
        self.assertIn("https://legit.org", urls)
        self.assertIn("http://phishing.xyz/token?id=12", urls)

    def test_api_detect_payload_endpoint(self):
        """Verify POST /api/v1/detect-payload returns complete classification data."""
        payload_data = {"payload": "WIFI:T:WPA;S=HomeNetwork;P=password;;"}
        res = self.client.post("/api/v1/detect-payload", json=payload_data)

        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("success"))
        info = data.get("classification")
        self.assertIsNotNone(info)
        self.assertEqual(info.get("content_type"), "wifi")
        self.assertEqual(info.get("type_label"), "Wi-Fi configuration")
        self.assertEqual(info.get("security_warning"), "This QR code contains network credentials.")
        self.assertEqual(info.get("details", {}).get("ssid"), "HomeNetwork")

    def test_api_analyze_wifi_payload(self):
        """Verify POST /api/v1/analyze handles Wi-Fi payload gracefully with credential warnings."""
        req_body = {"url": "WIFI:T:WPA;S=HomeNetwork;P=password;;"}
        res = self.client.post("/api/v1/analyze", json=req_body)

        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("success"))
        self.assertIn("payload_info", data)
        payload_info = data.get("payload_info")
        self.assertEqual(payload_info.get("content_type"), "wifi")
        self.assertEqual(payload_info.get("type_label"), "Wi-Fi configuration")
        self.assertEqual(data.get("title"), "Wi-Fi Configuration")
        self.assertEqual(payload_info.get("security_warning"), "This QR code contains network credentials.")
        self.assertIn("sanitized_text", payload_info)
        self.assertNotIn("P=password;", payload_info.get("sanitized_text"))

    def test_api_analyze_vcard_quishing(self):
        """Verify POST /api/v1/analyze flags embedded IP address quishing vectors inside vCards."""
        vcard = (
            "BEGIN:VCARD\n"
            "FN:Suspicious Contact\n"
            "URL:http://192.168.1.1/admin-login\n"
            "END:VCARD"
        )
        res = self.client.post("/api/v1/analyze", json={"url": vcard})

        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("payload_info", {}).get("content_type"), "vcard")
        # Should detect the suspicious embedded direct IP URL
        self.assertGreaterEqual(data.get("score"), 30)

    def test_inspect_payload_plain_text(self):
        """Verify inspect_payload with benign plain text payload."""
        text_payload = "Conference Room 101 - WiFi password is guest2026"
        res = inspect_payload(text_payload)

        self.assertTrue(res["success"])
        self.assertEqual(res["payload_info"]["content_type"], "text")
        self.assertEqual(res["payload_info"]["type_label"], "Plain text")


if __name__ == "__main__":
    unittest.main()
