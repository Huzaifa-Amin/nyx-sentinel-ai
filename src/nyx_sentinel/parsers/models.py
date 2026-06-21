"""Pydantic v2 data models for the entire NYX SENTINEL pipeline."""
from __future__ import annotations
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Optional
from uuid import uuid4
from pydantic import BaseModel, Field, field_validator, model_validator


class AlertSeverity(IntEnum):
    INFORMATIONAL = 1
    LOW = 4
    MEDIUM = 7
    HIGH = 10
    CRITICAL = 13

    @classmethod
    def from_wazuh_level(cls, level: int) -> "AlertSeverity":
        if level <= 3: return cls.INFORMATIONAL
        if level <= 6: return cls.LOW
        if level <= 9: return cls.MEDIUM
        if level <= 12: return cls.HIGH
        return cls.CRITICAL

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @property
    def css_class(self) -> str:
        return {"INFORMATIONAL":"info","LOW":"low","MEDIUM":"medium",
                "HIGH":"high","CRITICAL":"critical"}[self.name]


class IOCType(str):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5_hash"
    SHA1 = "sha1_hash"
    SHA256 = "sha256_hash"
    EMAIL = "email"
    USERNAME = "username"
    PROCESS = "process_name"
    FILE_PATH = "file_path"
    CVE = "cve"


class IncidentStatus(str):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class MitreAttack(BaseModel):
    techniques: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    technique_names: list[str] = Field(default_factory=list)


class AgentInfo(BaseModel):
    agent_id: str
    agent_name: str
    agent_ip: Optional[str] = None


class RuleInfo(BaseModel):
    rule_id: str
    level: int = Field(ge=0, le=15)
    description: str
    groups: list[str] = Field(default_factory=list)
    mitre: MitreAttack = Field(default_factory=MitreAttack)


class IOC(BaseModel):
    ioc_id: str = Field(default_factory=lambda: str(uuid4())[:8])
    ioc_type: str
    value: str
    source_field: str = Field(default="unknown")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    vt_malicious: Optional[int] = None
    vt_total: Optional[int] = None
    abuse_confidence: Optional[int] = None
    abuse_country: Optional[str] = None
    is_malicious: bool = False
    enrichment_error: Optional[str] = None

    @field_validator("value")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        return v.strip()


class EvidenceFile(BaseModel):
    file_name: str
    original_path: str
    collected_path: str
    sha256: str
    size_bytes: int
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    error: Optional[str] = None


class EvidenceManifest(BaseModel):
    manifest_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_files: int = 0
    total_size_bytes: int = 0
    files: list[EvidenceFile] = Field(default_factory=list)
    collection_errors: list[str] = Field(default_factory=list)


class IncidentClassification(BaseModel):
    incident_id: str = Field(default_factory=lambda: str(uuid4()))
    severity: AlertSeverity
    severity_score: float = Field(ge=0.0, le=100.0)
    incident_type: str
    confidence: float = Field(ge=0.0, le=1.0)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    summary: str = ""
    status: str = IncidentStatus.OPEN
    classified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ParsedAlert(BaseModel):
    alert_id: str
    timestamp: datetime
    rule: RuleInfo
    agent: AgentInfo
    full_log: Optional[str] = None
    raw_data: dict[str, Any] = Field(default_factory=dict)
    severity: AlertSeverity = AlertSeverity.INFORMATIONAL
    iocs: list[IOC] = Field(default_factory=list)
    classification: Optional[IncidentClassification] = None
    evidence: Optional[EvidenceManifest] = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        if isinstance(v, str):
            for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                        "%Y-%m-%dT%H:%M:%S.000+0000", "%Y-%m-%dT%H:%M:%S.%fZ",
                        "%Y-%m-%dT%H:%M:%SZ"):
                try:
                    dt = datetime.strptime(v, fmt)
                    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
        raise ValueError(f"Cannot parse timestamp '{v}'")

    @model_validator(mode="after")
    def set_severity_from_rule(self) -> "ParsedAlert":
        self.severity = AlertSeverity.from_wazuh_level(self.rule.level)
        return self
