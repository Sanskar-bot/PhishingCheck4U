"""
email_responder.py - Sends phishing analysis reports via SMTP/STARTTLS.
Credentials loaded exclusively from environment variables.
"""

import logging
import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def _is_valid_email(address: str) -> bool:
    return bool(_EMAIL_RE.match(address.strip()))


def send_report(recipient_email: str, subject: str, body: str) -> bool:
    """
    Send analysis report to recipient via SMTP with STARTTLS.
    Returns True on success, False on failure.
    """
    if not settings.REPORT_REPLY_ENABLED:
        logger.info("Email replies disabled. Skipping send.")
        return False

    if not _is_valid_email(recipient_email):
        logger.warning(f"Invalid recipient: '{recipient_email}'. Aborting.")
        return False

    msg = MIMEMultipart("alternative")
    msg["From"] = settings.EMAIL_ADDRESS
    msg["To"] = recipient_email
    msg["Subject"] = subject
    msg["X-Mailer"] = "PhishingCheck4U"
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(settings.EMAIL_ADDRESS, settings.EMAIL_APP_PASSWORD)
            server.sendmail(settings.EMAIL_ADDRESS, [recipient_email], msg.as_string())
        logger.info(f"Report sent to {recipient_email}.")
        return True
    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP authentication failed. Check EMAIL_ADDRESS and EMAIL_APP_PASSWORD.")
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error: {e}")
    except TimeoutError:
        logger.error("SMTP connection timed out.")
    except Exception as e:
        logger.error(f"Unexpected error sending report: {e}", exc_info=True)
    return False
