"""
Configuration module for Cyber Squad Enterprise Email Security Gateway (ESG).
Uses Pydantic Settings with environment variable and .env file overrides.
"""

from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

BASE_DIR = Path(__file__).resolve().parent.parent

class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CS_GW_",
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Core metadata
    PROJECT_NAME: str = "Cyber Squad Secure Email Gateway (ESG)"
    VERSION: str = "4.0.0"
    TEAM_NAME: str = "Cyber Squad - SIH 2026 #26106"
    ENVIRONMENT: str = "production"
    LOG_LEVEL: str = "INFO"

    # SMTP Proxy Interceptor Configuration
    SMTP_ENABLED: bool = True
    SMTP_LISTEN_HOST: str = "0.0.0.0"
    SMTP_LISTEN_PORT: int = 10025
    SMTP_RELAY_HOST: str = "127.0.0.1"
    SMTP_RELAY_PORT: int = 2525
    SMTP_MAX_SIZE_BYTES: int = 25 * 1024 * 1024  # 25 MB
    SMTP_BANNER: str = "220 cybersquad-esg.local Cyber Squad ESG Ready (RFC 5321 / SIH #26106)"

    # Postfix Milter Protocol Configuration
    MILTER_ENABLED: bool = True
    MILTER_LISTEN_HOST: str = "0.0.0.0"
    MILTER_LISTEN_PORT: int = 8893
    MILTER_SOCKET_PATH: str = "/tmp/cybersquad-milter.sock"

    # Admin Control Plane & Web SOC Dashboard
    API_ENABLED: bool = True
    API_LISTEN_HOST: str = "0.0.0.0"
    API_LISTEN_PORT: int = 8002

    # Policy Action Thresholds
    CLEAN_THRESHOLD: int = 40        # Score < 40 -> ACCEPT (Deliver cleanly)
    SUSPICIOUS_THRESHOLD: int = 75   # 40 <= Score < 75 -> TAG_SUBJECT & route to Spam
    REJECT_THRESHOLD: int = 75       # Score >= 75 -> REJECT / QUARANTINE
    SUBJECT_TAG_PREFIX: str = "[SUSPICIOUS / PHISHING]"
    AUTO_QUARANTINE_HIGH_RISK: bool = True

    # Quarantine Vault Storage
    QUARANTINE_DIR: Path = Field(default_factory=lambda: BASE_DIR / "quarantine_vault")
    QUARANTINE_SECRET: str = "cybersquad-section63-evidence-seal-2026"

    # Upstream Web Core Integration
    WEB_BACKEND_URL: str = "http://localhost:8001/api/gateway-milter-check"
    WEB_BACKEND_TIMEOUT: float = 3.0
    ENABLE_HYBRID_DELEGATION: bool = True

    # Real-time DNS Authentication & Verification
    ENABLE_DNS_AUTH: bool = True
    DNS_RESOLVER_TIMEOUT: float = 2.0

    # SIEM / Webhook Alerting
    WEBHOOK_URL: Optional[str] = None
    WEBHOOK_MIN_SCORE: int = 70


settings = GatewaySettings()
