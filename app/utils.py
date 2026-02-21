"""
utils.py - Shared helper utilities used across all modules.
"""

import hashlib
import re
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def hash_email(sender: str, subject: str, body_snippet: str) -> str:
    """SHA-256 fingerprint for deduplication."""
    raw = f"{sender}|{subject}|{body_snippet[:200]}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def extract_urls(text: str) -> list:
    """Extract all HTTP/HTTPS URLs from a block of text."""
    url_pattern = re.compile(r'https?://[^\s\'"<>\)\]]+', re.IGNORECASE)
    return list(set(url_pattern.findall(text)))


def get_domain_from_url(url: str):
    """Parse and return the hostname from a URL."""
    try:
        parsed = urlparse(url)
        return parsed.hostname
    except Exception:
        return None


def get_domain_from_email(email_address: str):
    """Extract domain from an email address like user@domain.com."""
    try:
        return email_address.strip().split("@")[1].lower()
    except (IndexError, AttributeError):
        return None


def sanitize_string(value: str, max_length: int = 1000) -> str:
    """Strip control characters and truncate for safe storage."""
    if not value:
        return ""
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
    return cleaned[:max_length]


def clamp_score(score: int) -> int:
    """Ensure score stays within 0-100 bounds."""
    return max(0, min(100, score))


def classify_risk(score: int) -> str:
    """Map numeric score to human-readable risk level."""
    if score <= 25:
        return "Safe"
    elif score <= 50:
        return "Low Suspicion"
    elif score <= 75:
        return "Suspicious"
    else:
        return "Likely Phishing"
