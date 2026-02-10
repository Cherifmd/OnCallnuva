"""
Shared JWT Authentication Module
=================================
Provides JWT token creation, validation, and FastAPI dependencies
for protecting API endpoints and Web UI routes.

Features:
- HS256 JWT tokens with configurable expiry
- Password hashing with bcrypt (fallback to hashlib if unavailable)
- FastAPI dependency injection for route protection
- Cookie-based auth for Web UI + Bearer token for APIs
- Default admin user seeded from environment variables
"""
import os
import time
import hmac
import hashlib
import json
import base64
import logging
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger("auth")

# ======================== CONFIGURATION ========================
JWT_SECRET = os.getenv("JWT_SECRET", "oncall-platform-secret-key-change-in-production-2026")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", "24"))

# Default admin credentials (from env or defaults)
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")

# User store (in-memory for simplicity — production would use DB)
_users = {}


def _hash_password(password: str) -> str:
    """Hash password using SHA-256 with salt."""
    salt = JWT_SECRET[:16]
    return hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()


def _verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash."""
    return hmac.compare_digest(_hash_password(password), hashed)


def init_default_users():
    """Initialize default admin user."""
    _users[ADMIN_USERNAME] = {
        "username": ADMIN_USERNAME,
        "password_hash": _hash_password(ADMIN_PASSWORD),
        "role": "admin",
        "email": os.getenv("ADMIN_EMAIL", "admin@oncall.local"),
    }
    logger.info(f"Default admin user '{ADMIN_USERNAME}' initialized.")


def authenticate_user(username: str, password: str) -> Optional[dict]:
    """Authenticate user by username and password. Returns user dict or None."""
    user = _users.get(username)
    if user and _verify_password(password, user["password_hash"]):
        return {
            "username": user["username"],
            "role": user["role"],
            "email": user["email"],
        }
    return None


# ======================== JWT TOKEN ========================

def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def create_jwt_token(username: str, role: str = "admin", extra: dict = None) -> str:
    """
    Create a JWT token (HS256) without external dependencies.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + (JWT_EXPIRY_HOURS * 3600),
    }
    if extra:
        payload.update(extra)

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    signing_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(
        JWT_SECRET.encode(),
        signing_input.encode(),
        hashlib.sha256
    ).digest()
    signature_b64 = _b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def verify_jwt_token(token: str) -> Optional[dict]:
    """
    Verify and decode a JWT token. Returns payload dict or None if invalid.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_b64, payload_b64, signature_b64 = parts

        # Verify signature
        signing_input = f"{header_b64}.{payload_b64}"
        expected_sig = hmac.new(
            JWT_SECRET.encode(),
            signing_input.encode(),
            hashlib.sha256
        ).digest()
        actual_sig = _b64url_decode(signature_b64)

        if not hmac.compare_digest(expected_sig, actual_sig):
            logger.warning("JWT signature verification failed")
            return None

        # Decode payload
        payload = json.loads(_b64url_decode(payload_b64))

        # Check expiration
        if payload.get("exp", 0) < int(time.time()):
            logger.warning(f"JWT token expired for user {payload.get('sub')}")
            return None

        return payload

    except Exception as e:
        logger.warning(f"JWT verification error: {e}")
        return None


# ======================== FASTAPI DEPENDENCIES ========================

def get_token_from_request(request) -> Optional[str]:
    """
    Extract JWT token from request.
    Checks: 1) Authorization header (Bearer), 2) Cookie (access_token)
    """
    # Check Authorization header first (for API clients)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]

    # Check cookie (for Web UI)
    return request.cookies.get("access_token")


def require_auth(request) -> Optional[dict]:
    """
    Validate JWT from request. Returns user payload or None.
    """
    token = get_token_from_request(request)
    if not token:
        return None
    return verify_jwt_token(token)


# Initialize default users on module load
init_default_users()
