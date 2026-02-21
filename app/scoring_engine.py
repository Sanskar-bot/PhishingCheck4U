"""
scoring_engine.py - Rule-based phishing risk scoring engine.
Score range: 0-100. Each rule returns triggered status, points, and detail.

Score bands:
  0-25   → Safe
  26-50  → Low Suspicion
  51-75  → Suspicious
  76-100 → Likely Phishing
"""

import logging
import re
from dataclasses import dataclass, field

from app.parser import AnalysisPayload, SUSPICIOUS_TLDS
from app.osint_module import (
    check_domain_age, check_domain_blacklist,
    check_ip_reputation, _is_likely_disposable
)
from app.utils import clamp_score, classify_risk

logger = logging.getLogger(__name__)


@dataclass
class RuleResult:
    label: str
    triggered: bool
    points: int
    detail: str


@dataclass
class ScoringResult:
    score: int
    risk_level: str
    triggered_rules: list = field(default_factory=list)
    all_rules: list = field(default_factory=list)
    osint_data: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Rule functions - each returns a RuleResult
# ---------------------------------------------------------------------------

def rule_suspicious_tld(payload: AnalysisPayload) -> RuleResult:
    found = [
        d for d in [payload.sender_domain] + payload.url_domains
        if any(d.endswith(tld) for tld in SUSPICIOUS_TLDS)
    ]
    triggered = bool(found)
    return RuleResult(
        label="Suspicious TLD", triggered=triggered,
        points=12 if triggered else 0,
        detail=f"Flagged: {', '.join(found)}" if triggered else "No suspicious TLDs.",
    )


def rule_reply_to_mismatch(payload: AnalysisPayload) -> RuleResult:
    mismatch = (
        bool(payload.reply_to_domain) and
        payload.sender_domain and
        payload.reply_to_domain != payload.sender_domain
    )
    return RuleResult(
        label="Reply-To Domain Mismatch", triggered=mismatch,
        points=15 if mismatch else 0,
        detail=(f"Sender: {payload.sender_domain} | Reply-To: {payload.reply_to_domain}"
                if mismatch else "Reply-To matches sender."),
    )


def rule_spf_fail(payload: AnalysisPayload) -> RuleResult:
    auth = payload.headers.get("authentication-results", "").lower()
    spf = payload.headers.get("received-spf", "").lower()
    if "spf=fail" in auth or "spf=softfail" in auth or "fail" in spf:
        return RuleResult("SPF Failure", True, 18, "SPF check failed.")
    if "spf=none" in auth and "spf=pass" not in auth:
        return RuleResult("SPF None", True, 8, "No SPF record found.")
    return RuleResult("SPF Failure", False, 0, "SPF passed.")


def rule_dkim_fail(payload: AnalysisPayload) -> RuleResult:
    auth = payload.headers.get("authentication-results", "").lower()
    if "dkim=fail" in auth:
        return RuleResult("DKIM Failure", True, 15, "DKIM signature failed.")
    if "dkim=none" in auth and "dkim=pass" not in auth:
        return RuleResult("DKIM None", True, 6, "No DKIM signature.")
    return RuleResult("DKIM Failure", False, 0, "DKIM passed.")


def rule_dmarc_fail(payload: AnalysisPayload) -> RuleResult:
    auth = payload.headers.get("authentication-results", "").lower()
    if "dmarc=fail" in auth:
        return RuleResult("DMARC Failure", True, 20, "DMARC policy failed.")
    return RuleResult("DMARC Failure", False, 0, "DMARC passed.")


def rule_url_domain_mismatch(payload: AnalysisPayload) -> RuleResult:
    if payload.mismatched_domains:
        return RuleResult(
            label="URL Domain Mismatch", triggered=True,
            points=min(len(payload.mismatched_domains) * 5, 15),
            detail=f"External domains: {', '.join(payload.mismatched_domains[:5])}",
        )
    return RuleResult("URL Domain Mismatch", False, 0, "All links match sender domain.")


def rule_shortened_urls(payload: AnalysisPayload) -> RuleResult:
    if payload.shortened_urls:
        return RuleResult(
            label="Shortened URLs", triggered=True, points=10,
            detail=f"Found: {', '.join(payload.shortened_urls[:3])}",
        )
    return RuleResult("Shortened URLs", False, 0, "No shortened URLs.")


def rule_ip_in_url(payload: AnalysisPayload) -> RuleResult:
    if payload.ip_in_url:
        return RuleResult(
            label="IP Address in URL", triggered=True, points=12,
            detail=f"IP URLs: {', '.join(payload.ip_in_url[:3])}",
        )
    return RuleResult("IP Address in URL", False, 0, "No IP addresses in URLs.")


def rule_phishing_keywords(payload: AnalysisPayload) -> RuleResult:
    count = len(payload.suspicious_keywords_found)
    if count == 0:
        return RuleResult("Phishing Keywords", False, 0, "No suspicious keywords.")
    points = min(count * 3, 15)
    return RuleResult(
        label="Phishing Keywords", triggered=True, points=points,
        detail=f"{count} keyword(s): {', '.join(payload.suspicious_keywords_found[:5])}",
    )


def rule_risky_attachments(payload: AnalysisPayload) -> RuleResult:
    if payload.risky_attachments:
        return RuleResult(
            label="Risky Attachments", triggered=True, points=20,
            detail=f"Dangerous files: {', '.join(payload.risky_attachments[:5])}",
        )
    return RuleResult("Risky Attachments", False, 0, "No risky attachments.")


def rule_display_name_spoofing(payload: AnalysisPayload) -> RuleResult:
    if payload.sender_display_domain and payload.sender_domain:
        brand = payload.sender_display_domain.split(",")[0]
        if brand and brand not in payload.sender_domain:
            return RuleResult(
                label="Display Name Spoofing", triggered=True, points=18,
                detail=f"Name suggests '{brand}' but domain is '{payload.sender_domain}'.",
            )
    return RuleResult("Display Name Spoofing", False, 0, "No spoofing detected.")


def rule_disposable_email(payload: AnalysisPayload) -> RuleResult:
    if _is_likely_disposable(payload.sender_email):
        return RuleResult(
            label="Disposable Email", triggered=True, points=10,
            detail=f"{payload.sender_domain} is a disposable email service.",
        )
    return RuleResult("Disposable Email", False, 0, "Not a disposable domain.")


# ---------------------------------------------------------------------------
# OSINT-backed rules (make external calls)
# ---------------------------------------------------------------------------

def rule_new_domain(payload: AnalysisPayload):
    osint = check_domain_age(payload.sender_domain)
    if osint["is_new"]:
        result = RuleResult("New Domain (< 90 days)", True, 20, osint["note"])
    elif osint["age_days"] is not None and osint["age_days"] < 365:
        result = RuleResult("New Domain (< 1 year)", True, 8, osint["note"])
    else:
        result = RuleResult("New Domain", False, 0, osint["note"])
    return result, {"domain_age": osint}


def rule_ip_reputation(payload: AnalysisPayload):
    if not payload.ip_in_url:
        return RuleResult("IP Reputation", False, 0, "No IP URLs to check."), {}
    ip_match = re.search(r"(\d{1,3}\.){3}\d{1,3}", payload.ip_in_url[0])
    if not ip_match:
        return RuleResult("IP Reputation", False, 0, "Could not extract IP."), {}
    osint = check_ip_reputation(ip_match.group())
    if osint.get("is_malicious"):
        return RuleResult("Malicious IP", True, 25, osint["note"]), {"ip_reputation": osint}
    return RuleResult("IP Reputation", False, 0, osint["note"]), {"ip_reputation": osint}


def rule_domain_blacklist(payload: AnalysisPayload):
    osint = check_domain_blacklist(payload.sender_domain)
    if osint.get("is_blacklisted"):
        return RuleResult("Blacklisted Domain", True, 30, osint["note"]), {"domain_blacklist": osint}
    return RuleResult("Domain Blacklist", False, 0, osint.get("note", "")), {"domain_blacklist": osint}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

FAST_RULES = [
    rule_suspicious_tld, rule_reply_to_mismatch, rule_spf_fail,
    rule_dkim_fail, rule_dmarc_fail, rule_url_domain_mismatch,
    rule_shortened_urls, rule_ip_in_url, rule_phishing_keywords,
    rule_risky_attachments, rule_display_name_spoofing, rule_disposable_email,
]

OSINT_RULES = [rule_new_domain, rule_ip_reputation, rule_domain_blacklist]


def score_email(payload: AnalysisPayload) -> ScoringResult:
    all_results = []
    triggered_results = []
    osint_data = {}

    for rule_fn in FAST_RULES:
        try:
            result = rule_fn(payload)
            all_results.append(result)
            if result.triggered:
                triggered_results.append(result)
        except Exception as e:
            logger.error(f"Rule {rule_fn.__name__} error: {e}", exc_info=True)

    for rule_fn in OSINT_RULES:
        try:
            result, data = rule_fn(payload)
            all_results.append(result)
            osint_data.update(data)
            if result.triggered:
                triggered_results.append(result)
        except Exception as e:
            logger.error(f"OSINT rule {rule_fn.__name__} error: {e}", exc_info=True)

    final_score = clamp_score(sum(r.points for r in triggered_results))

    return ScoringResult(
        score=final_score,
        risk_level=classify_risk(final_score),
        triggered_rules=triggered_results,
        all_rules=all_results,
        osint_data=osint_data,
    )
