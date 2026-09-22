"""
Unit and integration tests for Authentication and Analyst Session System.
Tests PBKDF2 hashing, itsdangerous token issuance, sign-up, sign-in,
demo analyst pre-seeding, and session verification routes.
"""

import unittest
import uuid
from fastapi.testclient import TestClient
from app.main import app
from app.services.auth_service import auth_service, hash_password, verify_password


class TestAuthentication(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_password_hashing_and_verification(self):
        """Test PBKDF2-HMAC-SHA256 password hashing and constant-time verification."""
        password = "SecurePassword#2026"
        salt, pwd_hash = hash_password(password)

        self.assertIsNotNone(salt)
        self.assertIsNotNone(pwd_hash)
        self.assertEqual(len(salt), 32)  # 16 bytes hex-encoded = 32 chars
        self.assertEqual(len(pwd_hash), 64)  # SHA-256 = 64 hex chars

        # Verification tests
        self.assertTrue(verify_password(password, salt, pwd_hash))
        self.assertFalse(verify_password("WrongPassword#999", salt, pwd_hash))
        self.assertFalse(verify_password("", salt, pwd_hash))

    def test_demo_analyst_preseeded(self):
        """Verify pre-seeded Demo Analyst account exists and authenticates with Analyst#2026."""
        # By username
        user_by_user = auth_service.signin("demo_analyst", "Analyst#2026")
        self.assertIsNotNone(user_by_user)
        self.assertEqual(user_by_user["username"], "demo_analyst")
        self.assertEqual(user_by_user["role"], "analyst")

        # By email
        user_by_email = auth_service.signin("analyst@quishing.local", "Analyst#2026")
        self.assertIsNotNone(user_by_email)
        self.assertEqual(user_by_email["email"], "analyst@quishing.local")

    def test_signup_success(self):
        """Test successful analyst registration via /api/v1/auth/signup."""
        unique_id = uuid.uuid4().hex[:8]
        payload = {
            "full_name": f"Investigator {unique_id}",
            "username": f"analyst_{unique_id}",
            "email": f"investigator_{unique_id}@cybersecurity.corp",
            "password": "StrongSecurityPassword#2026",
        }

        res = self.client.post("/api/v1/auth/signup", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.json()

        self.assertTrue(data["success"])
        self.assertIn("access_token", data)
        self.assertEqual(data["token_type"], "bearer")
        self.assertEqual(data["user"]["username"], payload["username"])
        self.assertEqual(data["user"]["email"], payload["email"])
        self.assertEqual(data["user"]["full_name"], payload["full_name"])
        self.assertNotIn("password_hash", data["user"])
        self.assertNotIn("salt", data["user"])

    def test_signup_duplicate_username(self):
        """Test registration rejection when username is already registered."""
        unique_id = uuid.uuid4().hex[:8]
        payload = {
            "full_name": "Test User",
            "username": f"dup_user_{unique_id}",
            "email": f"dup_{unique_id}@cyber.org",
            "password": "Password#12345",
        }
        res1 = self.client.post("/api/v1/auth/signup", json=payload)
        self.assertEqual(res1.status_code, 201)

        # Duplicate username with different email
        payload2 = dict(payload)
        payload2["email"] = f"other_{unique_id}@cyber.org"
        res2 = self.client.post("/api/v1/auth/signup", json=payload2)
        self.assertEqual(res2.status_code, 400)
        self.assertIn("already registered", res2.json()["detail"])

    def test_signup_duplicate_email(self):
        """Test registration rejection when email is already in use."""
        unique_id = uuid.uuid4().hex[:8]
        payload = {
            "full_name": "Test User",
            "username": f"email_test_{unique_id}",
            "email": f"dup_email_{unique_id}@cyber.org",
            "password": "Password#12345",
        }
        res1 = self.client.post("/api/v1/auth/signup", json=payload)
        self.assertEqual(res1.status_code, 201)

        # Duplicate email with different username
        payload2 = dict(payload)
        payload2["username"] = f"different_user_{unique_id}"
        res2 = self.client.post("/api/v1/auth/signup", json=payload2)
        self.assertEqual(res2.status_code, 400)
        self.assertIn("already in use", res2.json()["detail"])

    def test_signup_validation_errors(self):
        """Test schema validation errors for short password or invalid email."""
        # Short password (< 8 chars)
        res_short = self.client.post("/api/v1/auth/signup", json={
            "full_name": "Short Pass User",
            "username": "shortpass1",
            "email": "valid@email.com",
            "password": "short",
        })
        self.assertEqual(res_short.status_code, 422)

        # Invalid email format
        res_bad_email = self.client.post("/api/v1/auth/signup", json={
            "full_name": "Bad Email User",
            "username": "bademail1",
            "email": "not-an-email",
            "password": "ValidPassword#2026",
        })
        self.assertEqual(res_bad_email.status_code, 422)

    def test_signin_with_username_and_email(self):
        """Test signing in using either username or email with valid credentials."""
        unique_id = uuid.uuid4().hex[:8]
        password = "ComplexPassword#123"
        username = f"analyst_login_{unique_id}"
        email = f"login_{unique_id}@test.com"

        # Register first
        self.client.post("/api/v1/auth/signup", json={
            "full_name": "Login Tester",
            "username": username,
            "email": email,
            "password": password,
        })

        # 1. Sign in via username
        res_user = self.client.post("/api/v1/auth/signin", json={
            "identifier": username,
            "password": password,
        })
        self.assertEqual(res_user.status_code, 200)
        token_data = res_user.json()
        self.assertIn("access_token", token_data)
        self.assertEqual(token_data["user"]["username"], username)

        # 2. Sign in via email
        res_email = self.client.post("/api/v1/auth/signin", json={
            "identifier": email,
            "password": password,
        })
        self.assertEqual(res_email.status_code, 200)
        self.assertEqual(res_email.json()["user"]["email"], email)

    def test_signin_invalid_credentials(self):
        """Test that invalid password or nonexistent user returns 401."""
        # Wrong password for existing user
        res_wrong = self.client.post("/api/v1/auth/signin", json={
            "identifier": "demo_analyst",
            "password": "CompletelyWrongPassword!",
        })
        self.assertEqual(res_wrong.status_code, 401)
        self.assertIn("Invalid username/email or password", res_wrong.json()["detail"])

        # Nonexistent user
        res_none = self.client.post("/api/v1/auth/signin", json={
            "identifier": "nonexistent_analyst_9999",
            "password": "Password#123",
        })
        self.assertEqual(res_none.status_code, 401)

    def test_get_current_user_profile(self):
        """Test /api/v1/auth/me with valid, invalid, and missing Bearer tokens."""
        # 1. Sign in as demo analyst to get valid token
        res_login = self.client.post("/api/v1/auth/signin", json={
            "identifier": "demo_analyst",
            "password": "Analyst#2026",
        })
        token = res_login.json()["access_token"]

        # 2. Valid token
        res_me = self.client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(res_me.status_code, 200)
        me_data = res_me.json()
        self.assertEqual(me_data["username"], "demo_analyst")
        self.assertEqual(me_data["role"], "analyst")

        # 3. Missing token
        res_no_auth = self.client.get("/api/v1/auth/me")
        self.assertEqual(res_no_auth.status_code, 401)

        # 4. Tampered / invalid token
        res_tampered = self.client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalid.token.signature"},
        )
        self.assertEqual(res_tampered.status_code, 401)

    def test_auth_status_endpoint(self):
        """Test /api/v1/auth/status for both guest and authenticated state."""
        # Guest state
        res_guest = self.client.get("/api/v1/auth/status")
        self.assertEqual(res_guest.status_code, 200)
        guest_data = res_guest.json()
        self.assertFalse(guest_data["authenticated"])
        self.assertIsNone(guest_data["user"])

        # Authenticated state
        res_login = self.client.post("/api/v1/auth/signin", json={
            "identifier": "demo_analyst",
            "password": "Analyst#2026",
        })
        token = res_login.json()["access_token"]

        res_auth = self.client.get(
            "/api/v1/auth/status",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(res_auth.status_code, 200)
        auth_data = res_auth.json()
        self.assertTrue(auth_data["authenticated"])
        self.assertIsNotNone(auth_data["user"])
        self.assertEqual(auth_data["user"]["username"], "demo_analyst")

    def test_signout_endpoint(self):
        """Test /api/v1/auth/signout endpoint."""
        res = self.client.post("/api/v1/auth/signout")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()["success"])


if __name__ == "__main__":
    unittest.main()
