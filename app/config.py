"""
config.py - All configuration loaded from environment variables.
Never hardcode credentials. Use .env file via pydantic-settings.
"""

import logging
from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Gmail credentials - loaded from .env file
    EMAIL_ADDRESS: str
    EMAIL_APP_PASSWORD: str
    IMAP_SERVER: str = "imap.gmail.com"
    IMAP_PORT: int = 993
    SMTP_SERVER: str = "smtp.gmail.com"
    SMTP_PORT: int = 587

    # Database
    DATABASE_URL: str = "sqlite:///./phishingcheck4u.db"

    # Optional OSINT API keys (leave blank to skip those checks)
    ABUSEIPDB_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""

    # App behavior
    LOG_LEVEL: str = "INFO"
    MAX_EMAILS_PER_RUN: int = 20
    POLL_INTERVAL_SECONDS: int = 60
    REPORT_REPLY_ENABLED: bool = True

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


@lru_cache()
def get_settings() -> Settings:
    return Settings()


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
