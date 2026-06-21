"""Application settings — all secrets from environment variables only."""
from __future__ import annotations
from pathlib import Path
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8",
        case_sensitive=False, extra="ignore",
    )
    virustotal_api_key: str = Field(default="")
    abuseipdb_api_key: str = Field(default="")
    evidence_base_dir: Path = Field(default=Path("/tmp/nyx_evidence"))
    reports_dir: Path = Field(default=Path("/tmp/nyx_reports"))
    api_timeout_seconds: int = Field(default=30, ge=5, le=120)
    api_max_retries: int = Field(default=3, ge=1, le=10)
    max_file_size_mb: int = Field(default=100, ge=1, le=2048)
    allowed_evidence_dirs: list[str] = Field(
        default=["/var/log", "/tmp", "/home", "/etc",
                 "C:\\Windows\\Logs", "C:\\Windows\\System32\\winevt"]
    )
    enable_virustotal: bool = Field(default=True)
    enable_abuseipdb: bool = Field(default=True)
    report_max_iocs: int = Field(default=100, ge=1, le=1000)
    log_level: str = Field(default="INFO")
    log_file: Path = Field(default=Path("logs/nyx_sentinel.log"))

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid:
            raise ValueError(f"log_level must be one of {valid}")
        return upper

    @field_validator("evidence_base_dir", "reports_dir", "log_file", mode="before")
    @classmethod
    def expand_paths(cls, v: object) -> Path:
        return Path(str(v)).expanduser()


settings = Settings()
