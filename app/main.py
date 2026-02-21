"""
main.py - FastAPI application entry point.

Endpoints:
  GET  /health        - Health check
  POST /analyze       - Submit email for analysis
  GET  /logs          - Recent analysis history
  POST /trigger-poll  - Manually trigger inbox poll

Background task polls Gmail inbox every POLL_INTERVAL_SECONDS.
"""

import json
import logging
import asyncio
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.config import get_settings, setup_logging
from app.database import init_db, get_db, log_analysis, get_recent_logs, SessionLocal
from app.email_reader import fetch_unread_emails, ParsedEmail
from app.parser import build_analysis_payload
from app.scoring_engine import score_email
from app.report_generator import generate_report, get_triggered_checks_json
from app.email_responder import send_report
from app.utils import hash_email

settings = get_settings()
setup_logging(settings.LOG_LEVEL)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core processing pipeline
# ---------------------------------------------------------------------------

def process_email(parsed: ParsedEmail, db: Session) -> None:
    """Parse -> Score -> Report -> Log -> Reply."""
    try:
        email_hash = hash_email(parsed.sender, parsed.subject, parsed.body_text)
        payload = build_analysis_payload(parsed)
        scoring = score_email(payload)

        logger.info(
            f"Score={scoring.score} | Risk={scoring.risk_level} | From={payload.sender_email}"
        )

        subject, body = generate_report(payload, scoring)
        triggered_json = get_triggered_checks_json(scoring)

        record = log_analysis(
            db=db,
            email_hash=email_hash,
            sender=payload.sender_email,
            subject=parsed.subject,
            score=scoring.score,
            risk_level=scoring.risk_level,
            triggered_checks=triggered_json,
            report_sent=False,
        )

        if settings.REPORT_REPLY_ENABLED and record:
            reply_target = payload.reply_to_email or payload.sender_email
            sent = send_report(reply_target, subject, body)
            if sent:
                from app.database import EmailAnalysisLog
                rec = db.query(EmailAnalysisLog).filter_by(email_hash=email_hash).first()
                if rec:
                    rec.report_sent = True
                    db.commit()

    except Exception as e:
        logger.error(f"Failed to process email: {e}", exc_info=True)


# ---------------------------------------------------------------------------
# Background inbox polling
# ---------------------------------------------------------------------------

async def poll_inbox_loop():
    logger.info(f"Inbox polling started. Interval: {settings.POLL_INTERVAL_SECONDS}s")
    while True:
        try:
            await asyncio.sleep(settings.POLL_INTERVAL_SECONDS)
            logger.info("Polling inbox...")
            emails = fetch_unread_emails(max_count=settings.MAX_EMAILS_PER_RUN)
            if emails:
                db = SessionLocal()
                try:
                    for parsed in emails:
                        process_email(parsed, db)
                finally:
                    db.close()
            else:
                logger.info("No new emails.")
        except asyncio.CancelledError:
            logger.info("Polling stopped.")
            break
        except Exception as e:
            logger.error(f"Polling error: {e}", exc_info=True)
            await asyncio.sleep(30)


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("PhishingCheck4U started.")
    task = asyncio.create_task(poll_inbox_loop())
    yield
    task.cancel()
    logger.info("PhishingCheck4U shutting down.")


app = FastAPI(
    title="PhishingCheck4U",
    description="Hosted Email Phishing Detection and OSINT Intelligence Service",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------

class EmailAnalysisRequest(BaseModel):
    sender: str
    subject: str
    body_text: str
    body_html: Optional[str] = ""
    reply_to: Optional[str] = ""
    headers: Optional[dict] = {}
    urls: Optional[list] = []
    attachments: Optional[list] = []

    @field_validator("sender", "subject", "body_text")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Field cannot be empty.")
        return v.strip()


class AnalysisResponse(BaseModel):
    score: int
    risk_level: str
    triggered_rules: list
    report_subject: str
    report_body: str
    sender: str


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.get("/health", tags=["System"])
async def health_check():
    return {"status": "ok", "service": "PhishingCheck4U"}


@app.post("/analyze", response_model=AnalysisResponse, tags=["Analysis"])
async def analyze_email(
    request: EmailAnalysisRequest,
    db: Session = Depends(get_db),
):
    """Submit an email for immediate phishing analysis."""
    parsed = ParsedEmail(
        uid="api-submitted",
        sender=request.sender,
        reply_to=request.reply_to or request.sender,
        subject=request.subject,
        body_text=request.body_text,
        body_html=request.body_html or "",
        headers=request.headers or {},
        urls=request.urls or [],
        attachments=request.attachments or [],
        raw_headers="",
    )

    payload = build_analysis_payload(parsed)
    scoring = score_email(payload)
    subject, body = generate_report(payload, scoring)
    triggered_json = get_triggered_checks_json(scoring)

    email_hash = hash_email(parsed.sender, parsed.subject, parsed.body_text)
    log_analysis(
        db=db,
        email_hash=email_hash,
        sender=payload.sender_email,
        subject=parsed.subject,
        score=scoring.score,
        risk_level=scoring.risk_level,
        triggered_checks=triggered_json,
        report_sent=False,
    )

    return AnalysisResponse(
        score=scoring.score,
        risk_level=scoring.risk_level,
        triggered_rules=[r.label for r in scoring.triggered_rules],
        report_subject=subject,
        report_body=body,
        sender=payload.sender_email,
    )


@app.get("/logs", tags=["Analysis"])
async def get_logs(limit: int = 50, db: Session = Depends(get_db)):
    """Return recent analysis logs."""
    if limit > 200:
        raise HTTPException(status_code=400, detail="limit cannot exceed 200.")
    records = get_recent_logs(db, limit=limit)
    return [
        {
            "id": r.id,
            "sender": r.sender,
            "subject": r.subject,
            "score": r.score,
            "risk_level": r.risk_level,
            "triggered_checks": json.loads(r.triggered_checks or "[]"),
            "report_sent": r.report_sent,
            "timestamp": r.timestamp.isoformat(),
        }
        for r in records
    ]


@app.post("/trigger-poll", tags=["Admin"])
async def trigger_poll(background_tasks: BackgroundTasks):
    """Manually trigger an inbox poll."""
    async def _poll():
        db = SessionLocal()
        try:
            emails = fetch_unread_emails(max_count=settings.MAX_EMAILS_PER_RUN)
            for parsed in emails:
                process_email(parsed, db)
        finally:
            db.close()

    background_tasks.add_task(_poll)
    return {"status": "poll triggered"}
