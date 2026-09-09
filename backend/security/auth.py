"""
Authentication and Password Security Service.
Implements PBKDF2-HMAC-SHA256 hashing, generic error handling, and token management.
"""
import os
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple

PBKDF2_ITERATIONS = 200_000

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Hashes password with PBKDF2-HMAC-SHA256 and cryptographic per-user salt."""
    if not salt:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        PBKDF2_ITERATIONS
    )
    return dk.hex(), salt

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verifies a password against the stored PBKDF2 hash using constant-time comparison."""
    if not password or not stored_hash or not salt:
        return False
    computed_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(computed_hash, stored_hash)

def generate_session_token() -> str:
    """Generates a high-entropy URL-safe session token."""
    return secrets.token_urlsafe(32)

def generate_mfa_code() -> str:
    """Generates a 6-digit cryptographic OTP code."""
    return f"{secrets.randbelow(900000) + 100000}"

def generate_reset_token() -> str:
    """Generates a 32-byte cryptographic token for password recovery."""
    return secrets.token_urlsafe(32)

def validate_password_strength(password: str) -> Tuple[bool, str]:
    """Strictly validates password complexity without leaking specifics to attackers."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password exceeds maximum allowable length."
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    if sum([has_upper, has_lower, has_digit, has_special]) < 3:
        return False, "Password must include a mix of uppercase, lowercase, numbers, or special characters."
    return True, "Valid"
