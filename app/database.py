"""
database.py - SQLite persistence using SQLAlchemy.
Logs every analyzed email with score, risk level, and triggered checks.
"""

import logging
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


class EmailAnalysisLog(Base):
    __tablename__ = "email_analysis_log"

    id = Column(Integer, primary_key=True, index=True)
    email_hash = Column(String(64), unique=True, index=True)
    sender = Column(String(256))
    subject = Column(String(512))
    score = Column(Integer)
    risk_level = Column(String(32))
    triggered_checks = Column(Text)
    report_sent = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized.")


def get_db():
    """FastAPI dependency: yields a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def log_analysis(db: Session, email_hash: str, sender: str, subject: str,
                 score: int, risk_level: str, triggered_checks: str,
                 report_sent: bool = False):
    """Persist analysis result. Returns None if duplicate."""
    existing = db.query(EmailAnalysisLog).filter_by(email_hash=email_hash).first()
    if existing:
        logger.debug(f"Duplicate email hash {email_hash[:12]}... skipping.")
        return None

    record = EmailAnalysisLog(
        email_hash=email_hash,
        sender=sender,
        subject=subject,
        score=score,
        risk_level=risk_level,
        triggered_checks=triggered_checks,
        report_sent=report_sent,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    logger.info(f"Logged: score={score} risk={risk_level} from={sender}")
    return record


def get_recent_logs(db: Session, limit: int = 50):
    return (
        db.query(EmailAnalysisLog)
        .order_by(EmailAnalysisLog.timestamp.desc())
        .limit(limit)
        .all()
    )
