"""
email_reader.py - Secure IMAP inbox reader for Gmail.
Uses SSL on port 993 and Gmail App Password authentication.
Credentials are loaded exclusively from environment variables.
"""

import email
import imaplib
import logging
from dataclasses import dataclass, field
from email.header import decode_header

from app.config import get_settings
from app.utils import extract_urls, sanitize_string

logger = logging.getLogger(__name__)
settings = get_settings()

RISKY_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".msi", ".jar",
    ".zip", ".rar", ".7z", ".gz", ".iso", ".img",
    ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
    ".js", ".jse", ".wsf", ".wsh", ".lnk", ".scr", ".pif",
}


@dataclass
class ParsedEmail:
    uid: str
    sender: str
    reply_to: str
    subject: str
    body_text: str
    body_html: str
    headers: dict
    urls: list
    attachments: list
    raw_headers: str


def _decode_header_value(value: str) -> str:
    parts = decode_header(value or "")
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(str(part))
    return "".join(decoded)


def _extract_body(msg):
    text_body, html_body = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))
            if "attachment" in disposition:
                continue
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            decoded = payload.decode(charset, errors="replace")
            if ct == "text/plain" and not text_body:
                text_body = decoded
            elif ct == "text/html" and not html_body:
                html_body = decoded
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            text_body = payload.decode(charset, errors="replace")
    return text_body, html_body


def _extract_attachments(msg):
    attachments = []
    for part in msg.walk():
        disposition = str(part.get("Content-Disposition", ""))
        if "attachment" in disposition:
            filename = _decode_header_value(part.get_filename() or "")
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": sanitize_string(filename, 255),
                "content_type": part.get_content_type(),
                "size_bytes": len(payload),
            })
    return attachments


def fetch_unread_emails(max_count: int = 20) -> list:
    """
    Connect to Gmail via IMAP SSL, fetch unread emails,
    parse them, mark as read, and return ParsedEmail list.
    """
    parsed_emails = []
    try:
        imap = imaplib.IMAP4_SSL(settings.IMAP_SERVER, settings.IMAP_PORT)
        imap.login(settings.EMAIL_ADDRESS, settings.EMAIL_APP_PASSWORD)
        logger.info("IMAP login successful.")

        imap.select("INBOX")
        status, data = imap.search(None, "UNSEEN")
        if status != "OK":
            imap.logout()
            return []

        uids = data[0].split()
        logger.info(f"Found {len(uids)} unread email(s). Processing up to {max_count}.")
        uids = uids[:max_count]

        for uid in uids:
            try:
                status, msg_data = imap.fetch(uid, "(RFC822)")
                if status != "OK" or not msg_data:
                    continue

                raw = msg_data[0][1]
                msg = email.message_from_bytes(raw)

                sender = _decode_header_value(msg.get("From", ""))
                reply_to = _decode_header_value(msg.get("Reply-To", sender))
                subject = _decode_header_value(msg.get("Subject", "(no subject)"))
                headers = {k.lower(): v for k, v in msg.items()}
                raw_headers = str(msg)[:3000]

                body_text, body_html = _extract_body(msg)
                attachments = _extract_attachments(msg)
                urls = extract_urls(body_text + " " + body_html)

                parsed_emails.append(ParsedEmail(
                    uid=uid.decode(),
                    sender=sanitize_string(sender, 256),
                    reply_to=sanitize_string(reply_to, 256),
                    subject=sanitize_string(subject, 512),
                    body_text=sanitize_string(body_text, 5000),
                    body_html=sanitize_string(body_html, 5000),
                    headers=headers,
                    urls=urls[:50],
                    attachments=attachments,
                    raw_headers=raw_headers,
                ))

                imap.store(uid, "+FLAGS", "\\Seen")
                logger.debug(f"Processed UID {uid.decode()}")

            except Exception as e:
                logger.error(f"Error processing UID {uid}: {e}", exc_info=True)

        imap.logout()

    except imaplib.IMAP4.error as e:
        logger.error(f"IMAP error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in fetch_unread_emails: {e}", exc_info=True)

    return parsed_emails
