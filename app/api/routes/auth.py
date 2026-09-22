"""
Authentication API endpoints for QR-Quishing-Inspector.
Provides sign-up, sign-in, token session verification, status checks, and sign-out.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Header, Depends, status
from app.schemas.auth import (
    SignUpRequest,
    SignInRequest,
    UserResponse,
    TokenResponse,
    AuthStatusResponse,
)
from app.services.auth_service import auth_service

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication & Analyst Sessions"])


def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    """Dependency that extracts and validates the Bearer token from the Authorization header."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Missing Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization scheme. Use 'Bearer <token>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = parts[1]
    user = auth_service.verify_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or tampered session token. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def get_optional_current_user(authorization: Optional[str] = Header(None)) -> Optional[dict]:
    """Dependency for endpoints that can benefit from user context without requiring it."""
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return auth_service.verify_token(parts[1])
    return None


@router.post(
    "/signup",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new analyst or user account",
)
async def api_signup(req: SignUpRequest):
    """
    Registers a new account, hashes the password via PBKDF2-HMAC-SHA256,
    persists the user record, and issues an immediate signed session token.
    """
    try:
        user = auth_service.signup(
            full_name=req.full_name,
            username=req.username,
            email=req.email,
            password=req.password,
        )
        token = auth_service.create_token(user)
        return TokenResponse(
            success=True,
            access_token=token,
            token_type="bearer",
            expires_in=86400,
            user=UserResponse(**user),
        )
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(exc)}",
        )


@router.post(
    "/signin",
    response_model=TokenResponse,
    summary="Sign in with username/email and password",
)
@router.post(
    "/login",
    response_model=TokenResponse,
    include_in_schema=False,
    summary="Alias for /signin",
)
async def api_signin(req: SignInRequest):
    """
    Authenticates an existing user or pre-seeded analyst credentials,
    returning a signed session token.
    """
    user = auth_service.signin(req.identifier, req.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username/email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = auth_service.create_token(user)
    return TokenResponse(
        success=True,
        access_token=token,
        token_type="bearer",
        expires_in=86400,
        user=UserResponse(**user),
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get currently authenticated user profile",
)
async def api_get_current_user_profile(current_user: dict = Depends(get_current_user)):
    """Validates the Bearer token and returns the current user's profile."""
    return UserResponse(**current_user)


@router.get(
    "/status",
    response_model=AuthStatusResponse,
    summary="Check current session authentication state without throwing 401",
)
async def api_auth_status(optional_user: Optional[dict] = Depends(get_optional_current_user)):
    """
    Allows the frontend to inspect if an existing token in localStorage is valid
    without raising an unauthorized exception.
    """
    if optional_user:
        return AuthStatusResponse(authenticated=True, user=UserResponse(**optional_user))
    return AuthStatusResponse(authenticated=False, user=None)


@router.post(
    "/signout",
    summary="Sign out and invalidate local session",
)
@router.post(
    "/logout",
    include_in_schema=False,
    summary="Alias for /signout",
)
async def api_signout():
    """Client clears their local session token."""
    return {"success": True, "message": "Successfully signed out."}
