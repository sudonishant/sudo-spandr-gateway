"""
Enterprise SOC Authentication & RBAC Session Manager for SUDO SPANDR ESG.
Provides cryptographically signed session cookies, password validation, and role identification.
Roles:
  - ADMIN: Full access (Settings, Release from quarantine, Simulation, Configuration)
  - ANALYST: Read-only & triage (Live feeds, Autopsy inspection, Archive viewing)
"""

from __future__ import annotations
import hashlib
import hmac
import time
from typing import Any, Dict, Optional
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse, RedirectResponse

from gateway.config import settings


def hash_password(password: str) -> str:
    """Generates SHA-256 digest with pepper for secure matching."""
    pepper = settings.AUTH_SECRET_KEY.encode("utf-8")
    return hashlib.sha256(pepper + password.encode("utf-8")).hexdigest()


def generate_session_token(username: str, role: str) -> str:
    """Generates tamper-evident HMAC-SHA256 signed session token: username:role:timestamp:signature."""
    ts = int(time.time())
    payload = f"{username}:{role}:{ts}"
    sig = hmac.new(settings.AUTH_SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def verify_session_token(token: str) -> Optional[Dict[str, Any]]:
    """Verifies HMAC signature and expiration of session token."""
    if not token:
        return None
    try:
        parts = token.split(":")
        if len(parts) != 4:
            return None
        username, role, ts_str, sig = parts
        ts = int(ts_str)
        now = int(time.time())
        max_age_seconds = settings.SESSION_EXPIRE_HOURS * 3600

        if (now - ts) > max_age_seconds:
            return None  # Expired

        expected_payload = f"{username}:{role}:{ts}"
        expected_sig = hmac.new(settings.AUTH_SECRET_KEY.encode("utf-8"), expected_payload.encode("utf-8"), hashlib.sha256).hexdigest()

        if hmac.compare_digest(sig, expected_sig):
            return {
                "username": username,
                "role": role,
                "issued_at": ts,
                "is_authenticated": True
            }
        return None
    except Exception:
        return None


def authenticate_user(username: str, password: str) -> Optional[Dict[str, str]]:
    """Validates user credentials against configured administrative and analyst accounts."""
    u = username.strip().lower()
    p = password.strip()

    # 1. Admin Check
    if u == settings.ADMIN_USERNAME.lower() and p == settings.ADMIN_PASSWORD:
        return {
            "username": settings.ADMIN_USERNAME,
            "role": "ADMIN",
            "name": "SOC Lead Administrator"
        }

    # 2. Analyst Check
    if u == settings.ANALYST_USERNAME.lower() and p == settings.ANALYST_PASSWORD:
        return {
            "username": settings.ANALYST_USERNAME,
            "role": "ANALYST",
            "name": "Tier-2 SOC Security Analyst"
        }

    return None


def get_current_user_from_request(request: Request) -> Optional[Dict[str, Any]]:
    """Extracts and verifies current user from either Authorization header or Cookie."""
    # Check Header Authorization: Bearer <token>
    auth_hdr = request.headers.get("Authorization", "")
    token = None
    if auth_hdr.startswith("Bearer "):
        token = auth_hdr[7:].strip()
    elif "spandr_session" in request.cookies:
        token = request.cookies.get("spandr_session")

    if token:
        return verify_session_token(token)
    return None
