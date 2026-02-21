"""
parser.py - Transforms raw ParsedEmail into a structured AnalysisPayload
ready for the scoring engine.
"""

import logging
import re
from dataclasses import dataclass, field
from app.utils import get_domain_from_email, get_domain_from_url

logger = logging.getLogger(__name__)

PHISHING_KEYWORDS = [
    "verify your account", "confirm your identity", "update your information",
    "your account has been suspended", "unusual activity", "click here",
    "reset your password", "enter your password", "login immediately",
    "urgent action required", "limited time", "act now",
    "your account will be closed", "congratulations you won",
    "wire transfer", "bank account", "social security", "credit card",
    "gift card", "bitcoin", "invoice attached", "payment required",
    "verify now", "confirm now", "update now", "security alert",
]

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
    ".club", ".online", ".site", ".info", ".work", ".click",
    ".loan", ".download", ".win", ".bid", ".stream", ".gdn",
    ".racing", ".party", ".review", ".trade", ".date",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "tiny.cc", "rebrand.ly", "cutt.ly",
    "shorturl.at", "rb.gy", "clck.ru",
}

RISKY_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".msi", ".jar",
    ".zip", ".rar", ".7z", ".gz", ".iso", ".img",
    ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
    ".js", ".jse", ".wsf", ".wsh", ".lnk", ".scr", ".pif",
}

_IP_PATTERN = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")


@dataclass
class AnalysisPayload:
    sender_email: str
    sender_domain: str
    reply_to_email: str
    reply_to_domain: str
    subject: str
    body_text: str
    headers: dict
    urls: list
    url_domains: list
    attachments: list
    risky_attachments: list
    shortened_urls: list
    ip_in_url: list
    suspicious_keywords_found: list
    has_html_body: bool
    sender_display_domain: str = ""
    mismatched_domains: list = field(default_factory=list)


def _extract_email_address(raw: str) -> str:
    match = re.search(r"<([^>]+)>", raw)
    if match:
        return match.group(1).strip().lower()
    return raw.strip().lower()


def _is_shortened(url: str) -> bool:
    domain = get_domain_from_url(url) or ""
    return domain in URL_SHORTENERS


def build_analysis_payload(parsed) -> AnalysisPayload:
    sender_email = _extract_email_address(parsed.sender)
    sender_domain = get_domain_from_email(sender_email) or ""
    reply_to_email = _extract_email_address(parsed.reply_to)
    reply_to_domain = get_domain_from_email(reply_to_email) or ""

    url_domains = [d for u in parsed.urls if (d := get_domain_from_url(u))]
    shortened_urls = [u for u in parsed.urls if _is_shortened(u)]
    ip_in_url = [u for u in parsed.urls if _IP_PATTERN.match(u)]

    risky_attachments = [
        a["filename"] for a in parsed.attachments
        if any(a["filename"].lower().endswith(ext) for ext in RISKY_EXTENSIONS)
    ]

    body_lower = parsed.body_text.lower()
    keywords_found = [kw for kw in PHISHING_KEYWORDS if kw in body_lower]

    display_name_domains = re.findall(
        r'(?:paypal|amazon|apple|google|microsoft|netflix|facebook|'
        r'instagram|linkedin|dropbox|chase|wellsfargo|bankofamerica)\b',
        parsed.sender.lower()
    )

    mismatched = []
    if sender_domain:
        for domain in url_domains:
            if domain and not (
                domain == sender_domain or
                domain.endswith(f".{sender_domain}")
            ):
                mismatched.append(domain)

    return AnalysisPayload(
        sender_email=sender_email,
        sender_domain=sender_domain,
        reply_to_email=reply_to_email,
        reply_to_domain=reply_to_domain,
        subject=parsed.subject,
        body_text=parsed.body_text,
        headers=parsed.headers,
        urls=parsed.urls,
        url_domains=list(set(url_domains)),
        attachments=parsed.attachments,
        risky_attachments=risky_attachments,
        shortened_urls=shortened_urls,
        ip_in_url=ip_in_url,
        suspicious_keywords_found=keywords_found,
        has_html_body=bool(parsed.body_html),
        sender_display_domain=",".join(display_name_domains),
        mismatched_domains=list(set(mismatched))[:10],
    )
