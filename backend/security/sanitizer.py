"""
Input sanitization and validation helper to prevent XSS, NoSQL injection, and header smuggling.
"""
import re
import html
from typing import Any, Dict, List, Union

def sanitize_string(val: str, max_length: int = 1000) -> str:
    """Sanitizes a string by trimming, stripping control characters, and escaping HTML."""
    if not isinstance(val, str):
        return ""
    # Strip null bytes and control chars (except newline/tab)
    cleaned = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', val)
    # Truncate
    cleaned = cleaned[:max_length].strip()
    # Escape HTML to prevent XSS
    return html.escape(cleaned)

def sanitize_email(email: str) -> str:
    """Strictly validates and normalizes an email address."""
    if not isinstance(email, str):
        return ""
    email = email.strip().lower()
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(pattern, email) or len(email) > 254:
        raise ValueError("Invalid email format.")
    return email

DANGEROUS_KEYS = {"__proto__", "constructor", "prototype"}

def sanitize_mongo_dict(data: Union[Dict[str, Any], List[Any], Any]) -> Any:
    """Recursively neutralizes MongoDB operator injections and prototype pollution."""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if not isinstance(k, str):
                continue
            # Disallow keys starting with $, containing null bytes, dots, or prototype pollution keys
            k_clean = k.strip()
            if k_clean.startswith("$") or "\x00" in k_clean or "." in k_clean or k_clean.lower() in DANGEROUS_KEYS:
                continue
            sanitized[k_clean] = sanitize_mongo_dict(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_mongo_dict(item) for item in data]
    elif isinstance(data, str):
        return sanitize_string(data)
    return data

