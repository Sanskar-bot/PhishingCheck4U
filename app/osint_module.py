"""
osint_module.py - OSINT intelligence gathering.
Integrates WHOIS, AbuseIPDB, and VirusTotal.
All functions degrade gracefully when API keys are missing.
"""

import logging
import re
import socket
from datetime import datetime, timezone

import requests
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

TRUSTED_DOMAINS = {
    "google.com", "gmail.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "facebook.com", "linkedin.com", "twitter.com", "github.com",
}

_IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

DISPOSABLE_DOMAINS = {
    "mailinator.com", "tempmail.com", "guerrillamail.com", "throwam.com",
    "yopmail.com", "sharklasers.com", "trashmail.com", "fakeinbox.com",
    "getairmail.com", "dispostable.com", "maildrop.cc", "spamgourmet.com",
}


def check_domain_age(domain: str) -> dict:
    result = {
        "domain": domain, "age_days": None,
        "creation_date": None, "is_new": False, "note": "",
    }
    if not domain or domain in TRUSTED_DOMAINS:
        result["note"] = "Trusted or empty domain; skipped WHOIS."
        return result
    try:
        import whois
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - creation).days
            result["age_days"] = age
            result["creation_date"] = creation.strftime("%Y-%m-%d")
            result["is_new"] = age < 90
            result["note"] = f"Domain is {age} days old."
        else:
            result["note"] = "Creation date not found in WHOIS."
    except Exception as e:
        result["note"] = f"WHOIS lookup failed: {type(e).__name__}"
    return result


def check_ip_reputation(ip: str) -> dict:
    result = {
        "ip": ip, "abuse_score": None,
        "total_reports": None, "is_malicious": False, "note": "",
    }
    if not _IP_PATTERN.match(ip):
        result["note"] = f"'{ip}' is not a valid IPv4 address."
        return result
    api_key = settings.ABUSEIPDB_API_KEY
    if not api_key:
        result["note"] = "AbuseIPDB API key not configured."
        return result
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        result["abuse_score"] = score
        result["total_reports"] = reports
        result["is_malicious"] = score >= 50
        result["note"] = f"AbuseIPDB score: {score}/100 ({reports} reports)."
    except Exception as e:
        result["note"] = f"AbuseIPDB request failed: {type(e).__name__}"
    return result


def check_domain_blacklist(domain: str) -> dict:
    result = {
        "domain": domain, "malicious_votes": None,
        "suspicious_votes": None, "is_blacklisted": False, "note": "",
    }
    if not domain:
        return result
    api_key = settings.VIRUSTOTAL_API_KEY
    if not api_key:
        result["note"] = "VirusTotal API key not configured."
        return result
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": api_key},
            timeout=5,
        )
        if resp.status_code == 404:
            result["note"] = "Domain not found in VirusTotal."
            return result
        resp.raise_for_status()
        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        result["malicious_votes"] = malicious
        result["suspicious_votes"] = suspicious
        result["is_blacklisted"] = malicious >= 3
        result["note"] = f"VirusTotal: {malicious} malicious, {suspicious} suspicious."
    except Exception as e:
        result["note"] = f"VirusTotal request failed: {type(e).__name__}"
    return result


def check_email_reputation(email_address: str) -> dict:
    return {
        "email": email_address,
        "is_disposable": _is_likely_disposable(email_address),
        "is_known_malicious": False,
        "note": "Email reputation check: placeholder implementation.",
    }


def _is_likely_disposable(email_address: str) -> bool:
    domain = email_address.split("@")[-1].lower() if "@" in email_address else ""
    return domain in DISPOSABLE_DOMAINS


def resolve_url_to_ip(url: str):
    try:
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname
        if hostname:
            return socket.gethostbyname(hostname)
    except Exception:
        pass
    return None
