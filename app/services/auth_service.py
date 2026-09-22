"""
Authentication service for QR-Quishing-Inspector.
Handles user registration, PBKDF2-HMAC-SHA256 password hashing,
session token generation/validation with itsdangerous,
and thread-safe persistence in app/data/users.json.
"""

import os
import json
import time
import uuid
import secrets
import hashlib
import hmac
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
SECRET_KEY = os.environ.get("QUISHING_SECRET_KEY", "qr-quishing-inspector-secret-key-2026-v2")
TOKEN_MAX_AGE = 86400  # 24 hours in seconds


def hash_password(password: str, salt_hex: Optional[str] = None) -> tuple[str, str]:
    """
    Hashes a password using PBKDF2-HMAC-SHA256 with 100,000 iterations.
    Returns (salt_hex, hash_hex).
    """
    if not salt_hex:
        salt_hex = secrets.token_hex(16)
    salt_bytes = bytes.fromhex(salt_hex)
    hash_bytes = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, 100000)
    return salt_hex, hash_bytes.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    """Verifies a password against the stored salt and hash."""
    try:
        salt_bytes = bytes.fromhex(salt_hex)
        expected_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, 100000).hex()
        return hmac.compare_digest(expected_hash, hash_hex)
    except Exception:
        return False


class AuthService:
    """Thread-safe user management and session verification service."""

    def __init__(self, users_file: Optional[str] = None):
        self.users_file = users_file or USERS_FILE
        self._lock = threading.Lock()
        self._serializer = URLSafeTimedSerializer(SECRET_KEY, salt="qr-quishing-auth-session")
        self._users: Dict[str, Dict[str, Any]] = {}
        self._load_from_disk()

    def _load_from_disk(self):
        with self._lock:
            os.makedirs(os.path.dirname(self.users_file), exist_ok=True)
            if os.path.exists(self.users_file):
                try:
                    with open(self.users_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            self._users = {u["id"]: u for u in data if "id" in u}
                        elif isinstance(data, dict):
                            self._users = data
                except Exception:
                    self._users = {}
            else:
                self._users = {}

            self._ensure_demo_analyst()

    def _save_to_disk(self):
        try:
            os.makedirs(os.path.dirname(self.users_file), exist_ok=True)
            with open(self.users_file, "w", encoding="utf-8") as f:
                json.dump(list(self._users.values()), f, indent=2)
        except Exception as e:
            print(f"[AuthService Warning] Failed to save users: {e}")

    def _ensure_demo_analyst(self):
        """Seeds the default demo analyst account if not already present."""
        demo_email = "analyst@quishing.local"
        demo_username = "demo_analyst"
        exists = any(
            u.get("username") == demo_username or u.get("email") == demo_email
            for u in self._users.values()
        )
        if not exists:
            salt_hex, hash_hex = hash_password("Analyst#2026")
            now_iso = datetime.now(timezone.utc).isoformat()
            demo_user = {
                "id": "usr_demo_analyst",
                "username": demo_username,
                "email": demo_email,
                "full_name": "Demo Analyst",
                "salt": salt_hex,
                "password_hash": hash_hex,
                "role": "analyst",
                "created_at": now_iso,
                "last_login": None,
            }
            self._users["usr_demo_analyst"] = demo_user
            self._save_to_disk()

    @staticmethod
    def to_public_user(user: Dict[str, Any]) -> Dict[str, Any]:
        """Strips sensitive password and salt fields before returning to caller."""
        return {
            "id": user.get("id", ""),
            "username": user.get("username", ""),
            "email": user.get("email", ""),
            "full_name": user.get("full_name", ""),
            "role": user.get("role", "user"),
            "created_at": user.get("created_at", ""),
        }

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            user = self._users.get(user_id)
            return dict(user) if user else None

    def get_user_by_identifier(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Finds user by case-insensitive username or email."""
        clean = identifier.strip().lower()
        with self._lock:
            for user in self._users.values():
                if user.get("username", "").lower() == clean or user.get("email", "").lower() == clean:
                    return dict(user)
        return None

    def signup(self, full_name: str, username: str, email: str, password: str) -> Dict[str, Any]:
        """Registers a new user account."""
        clean_user = username.strip().lower()
        clean_email = email.strip().lower()
        clean_name = full_name.strip()

        with self._lock:
            for user in self._users.values():
                if user.get("username", "").lower() == clean_user:
                    raise ValueError(f"Username '{clean_user}' is already registered.")
                if user.get("email", "").lower() == clean_email:
                    raise ValueError(f"Email '{clean_email}' is already in use.")

            salt_hex, hash_hex = hash_password(password)
            user_id = f"usr_{uuid.uuid4().hex[:12]}"
            now_iso = datetime.now(timezone.utc).isoformat()

            new_user = {
                "id": user_id,
                "username": clean_user,
                "email": clean_email,
                "full_name": clean_name,
                "salt": salt_hex,
                "password_hash": hash_hex,
                "role": "user",
                "created_at": now_iso,
                "last_login": now_iso,
            }
            self._users[user_id] = new_user
            self._save_to_disk()
            return self.to_public_user(new_user)

    def signin(self, identifier: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticates user with username or email and returns public profile if valid."""
        user = self.get_user_by_identifier(identifier)
        if not user:
            return None

        salt_hex = user.get("salt", "")
        hash_hex = user.get("password_hash", "")
        if not verify_password(password, salt_hex, hash_hex):
            return None

        # Update last_login
        with self._lock:
            if user["id"] in self._users:
                self._users[user["id"]]["last_login"] = datetime.now(timezone.utc).isoformat()
                self._save_to_disk()

        return self.to_public_user(user)

    def create_token(self, user: Dict[str, Any]) -> str:
        """Generates a signed, URL-safe session token."""
        payload = {
            "sub": user.get("id"),
            "username": user.get("username"),
            "role": user.get("role", "user"),
            "iat": int(time.time()),
        }
        return self._serializer.dumps(payload)

    def verify_token(self, token: str, max_age: int = TOKEN_MAX_AGE) -> Optional[Dict[str, Any]]:
        """Verifies a signed session token and returns the current user profile if valid."""
        try:
            payload = self._serializer.loads(token, max_age=max_age)
            user_id = payload.get("sub")
            if not user_id:
                return None
            user = self.get_user_by_id(user_id)
            if not user:
                return None
            return self.to_public_user(user)
        except (BadSignature, SignatureExpired, Exception):
            return None


# Global singleton instance
auth_service = AuthService()
