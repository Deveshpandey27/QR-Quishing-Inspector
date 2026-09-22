"""
Authentication Pydantic schemas for QR-Quishing-Inspector.
Covers registration, sign-in, session tokens, and user profile representations.
"""

from typing import Optional
import re
from pydantic import BaseModel, Field, field_validator


class SignUpRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100, description="Full name of the user")
    username: str = Field(..., min_length=3, max_length=30, description="Unique username (letters, digits, _, -)")
    email: str = Field(..., description="Valid email address")
    password: str = Field(..., min_length=8, max_length=128, description="Secure password (minimum 8 characters)")

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        clean = v.strip().lower()
        if not re.match(r"^[a-zA-Z0-9_-]{3,30}$", clean):
            raise ValueError("Username must contain 3-30 alphanumeric characters, underscores, or hyphens.")
        return clean

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        clean = v.strip().lower()
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", clean):
            raise ValueError("Please provide a valid email address.")
        return clean

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        return v


class SignInRequest(BaseModel):
    identifier: str = Field(..., min_length=2, description="Username or Email address")
    password: str = Field(..., min_length=1, description="Password")


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: str
    role: str = "user"
    created_at: str


class TokenResponse(BaseModel):
    success: bool = True
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 86400
    user: UserResponse


class AuthStatusResponse(BaseModel):
    authenticated: bool
    user: Optional[UserResponse] = None
