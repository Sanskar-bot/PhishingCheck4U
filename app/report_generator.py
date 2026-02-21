"""
report_generator.py - Generates user-friendly and technical phishing reports.
"""

import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

RISK_ICONS = {
    "Safe": "[SAFE]",
    "Low Suspicion": "[LOW SUSPICION]",
    "Suspicious": "[SUSPICIOUS]",
    "Likely Phishing": "[LIKELY PHISHING]",
}

RISK_ADVICE = {
    "Safe": (
        "This email appears legitimate. However, always exercise caution - "
        "no automated tool is 100% accurate."
    ),
    "Low Suspicion": (
        "This email has minor warning signs. Do not click links or download "
        "attachments unless you are certain of the sender."
    ),
    "Suspicious": (
        "This email shows multiple phishing characteristics. Do NOT click any "
        "links or download attachments. Verify the sender independently."
    ),
    "Likely Phishing": (
        "WARNING: This email is very likely a phishing attempt. Do NOT interact "
        "with it. Report to your IT/security team and delete immediately."
    ),
}


def generate_report(payload, scoring) -> tuple:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    icon = RISK_ICONS.get(scoring.risk_level, "[UNKNOWN]")
    advice = RISK_ADVICE.get(scoring.risk_level, "")

    subject = (
        f"[PhishingCheck4U] {scoring.risk_level.upper()} "
        f"(Score: {scoring.score}/100) - {payload.subject[:60]}"
    )

    lines = [
        "=" * 62,
        "  PHISHINGCHECK4U - EMAIL PHISHING ANALYSIS REPORT",
        "=" * 62,
        "",
        f"  Analyzed:     {now}",
        f"  From:         {payload.sender_email}",
        f"  Subject:      {payload.subject[:80]}",
        "",
        "-" * 62,
        "  RISK ASSESSMENT",
        "-" * 62,
        "",
        f"  {icon}",
        f"  Risk Level:  {scoring.risk_level}",
        f"  Score:       {scoring.score} / 100",
        "",
        f"  {advice}",
        "",
    ]

    if scoring.triggered_rules:
        lines += ["-" * 62, "  KEY CONCERNS", "-" * 62, ""]
        for rule in scoring.triggered_rules[:5]:
            lines.append(f"  [!] {rule.label}")
            lines.append(f"      {rule.detail}")
            lines.append("")

    lines += ["-" * 62, "  FULL RULE BREAKDOWN", "-" * 62, ""]
    for rule in scoring.all_rules:
        status = f"[+{rule.points:>3}pts TRIGGERED]" if rule.triggered else "[     PASSED  ]"
        lines.append(f"  {status}  {rule.label}")
        lines.append(f"             {rule.detail}")
        lines.append("")

    if scoring.osint_data:
        lines += ["-" * 62, "  OSINT INTELLIGENCE", "-" * 62, ""]
        for key, data in scoring.osint_data.items():
            lines.append(f"  [{key.upper().replace('_', ' ')}]")
            for k, v in data.items():
                lines.append(f"    {k}: {v}")
            lines.append("")

    lines += [
        "-" * 62,
        "  EMAIL METADATA",
        "-" * 62,
        "",
        f"  Sender:        {payload.sender_email}",
        f"  Sender Domain: {payload.sender_domain}",
        f"  Reply-To:      {payload.reply_to_email}",
        f"  URLs Found:    {len(payload.urls)}",
        f"  Attachments:   {len(payload.attachments)}",
    ]

    if payload.risky_attachments:
        lines.append(f"  Risky Files:   {', '.join(payload.risky_attachments[:5])}")

    if payload.urls:
        lines += ["", "  URLS (first 10):"]
        for url in payload.urls[:10]:
            lines.append(f"    {url}")

    auth_header = payload.headers.get("authentication-results", "Not present")
    lines += [
        "",
        f"  AUTH-RESULTS:  {auth_header[:200]}",
        "",
        "-" * 62,
        "  DISCLAIMER: Auto-generated report. Human judgment required.",
        "  PhishingCheck4U | Rule-based + OSINT Analysis",
        "=" * 62,
    ]

    return subject, "\n".join(lines)


def get_triggered_checks_json(scoring) -> str:
    return json.dumps([r.label for r in scoring.triggered_rules])
