"""
tests/conftest.py
==================
Shared pytest fixtures used across the entire NYX SENTINEL test suite.

All fixtures provide minimal, fully valid data objects so individual
test files only need to override the fields they care about.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from nyx_sentinel.parsers.models import (
    AgentInfo,
    AlertSeverity,
    EvidenceFile,
    EvidenceManifest,
    IOC,
    IOCType,
    IncidentClassification,
    MitreAttack,
    ParsedAlert,
    RuleInfo,
)


# ---------------------------------------------------------------------------
# Raw JSON fixtures (as strings / dicts for parser tests)
# ---------------------------------------------------------------------------

VALID_ALERT_DICT = {
    "id": "1706000001.112233",
    "timestamp": "2024-01-24T03:17:42.000+0000",
    "rule": {
        "level": 10,
        "description": "Multiple Windows Logon Failures",
        "id": "18302",
        "mitre": {
            "attack": ["T1110", "T1110.001"],
            "tactic": ["Credential Access"],
            "technique": ["Brute Force"],
        },
        "groups": ["windows", "authentication_failed"],
    },
    "agent": {"id": "001", "name": "CORP-WIN-WKS01", "ip": "10.10.20.15"},
    "manager": {"name": "wazuh-manager-01"},
    "full_log": (
        "Source Network Address: 192.168.50.99 "
        "Target User: Administrator "
        "Hash: 3a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f678"
    ),
    "data": {
        "win": {
            "eventdata": {
                "targetUserName": "Administrator",
                "ipAddress": "192.168.50.99",
                "logonType": "3",
            }
        }
    },
}


# ---------------------------------------------------------------------------
# Parsed model fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_mitre() -> MitreAttack:
    return MitreAttack(
        techniques=["T1110", "T1110.001"],
        tactics=["Credential Access"],
        technique_names=["Brute Force", "Password Guessing"],
    )


@pytest.fixture
def sample_rule(sample_mitre: MitreAttack) -> RuleInfo:
    return RuleInfo(
        rule_id="18302",
        level=10,
        description="Multiple Windows Logon Failures",
        groups=["windows", "authentication_failed"],
        mitre=sample_mitre,
    )


@pytest.fixture
def sample_agent() -> AgentInfo:
    return AgentInfo(
        agent_id="001",
        agent_name="CORP-WIN-WKS01",
        agent_ip="10.10.20.15",
    )


@pytest.fixture
def sample_alert(sample_rule: RuleInfo, sample_agent: AgentInfo) -> ParsedAlert:
    return ParsedAlert(
        alert_id="1706000001.112233",
        timestamp=datetime(2024, 1, 24, 3, 17, 42, tzinfo=timezone.utc),
        rule=sample_rule,
        agent=sample_agent,
        full_log=(
            "Source IP: 192.168.50.99 target=Administrator "
            "hash=3a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f678"
        ),
        raw_data=VALID_ALERT_DICT,
    )


@pytest.fixture
def sample_ioc_ip() -> IOC:
    return IOC(
        ioc_type=IOCType.IP_ADDRESS,
        value="192.168.50.99",
        source_field="data.win.eventdata.ipAddress",
        confidence=0.95,
    )


@pytest.fixture
def sample_ioc_hash() -> IOC:
    return IOC(
        ioc_type=IOCType.SHA256,
        value="3a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f678",
        source_field="full_log",
        confidence=1.0,
    )


@pytest.fixture
def sample_iocs(sample_ioc_ip: IOC, sample_ioc_hash: IOC) -> list[IOC]:
    return [sample_ioc_ip, sample_ioc_hash]


@pytest.fixture
def enriched_alert(sample_alert: ParsedAlert, sample_iocs: list[IOC]) -> ParsedAlert:
    """Alert with IOCs attached and one flagged as malicious."""
    sample_alert.iocs = sample_iocs
    sample_iocs[0].vt_malicious = 10
    sample_iocs[0].vt_total = 72
    sample_iocs[0].abuse_confidence = 85
    sample_iocs[0].abuse_country = "RU"
    sample_iocs[0].is_malicious = True
    return sample_alert


@pytest.fixture
def sample_classification() -> IncidentClassification:
    return IncidentClassification(
        severity=AlertSeverity.HIGH,
        severity_score=72.5,
        incident_type="Credential Brute Force",
        confidence=0.85,
        mitre_tactics=["Credential Access"],
        mitre_techniques=["T1110", "T1110.001"],
        recommended_actions=[
            "Lock the targeted account",
            "Block source IP at firewall",
        ],
        summary="A HIGH severity Credential Brute Force incident was detected.",
    )


@pytest.fixture
def sample_evidence_manifest() -> EvidenceManifest:
    return EvidenceManifest(
        incident_id="test-incident-001",
        total_files=1,
        total_size_bytes=1024,
        files=[
            EvidenceFile(
                file_name="test_file.log",
                original_path="/var/log/test_file.log",
                collected_path="/tmp/nyx_evidence/test-incident-001/abc_test_file.log",
                sha256="a" * 64,
                size_bytes=1024,
            )
        ],
    )


@pytest.fixture
def alert_file_path(tmp_path: Path) -> Path:
    """Write a valid single-alert JSON file to a temp directory."""
    p = tmp_path / "alert.json"
    p.write_text(json.dumps(VALID_ALERT_DICT), encoding="utf-8")
    return p


@pytest.fixture
def alert_array_file_path(tmp_path: Path) -> Path:
    """Write a valid JSON array of two alerts to a temp directory."""
    p = tmp_path / "alerts.json"
    p.write_text(json.dumps([VALID_ALERT_DICT, VALID_ALERT_DICT]), encoding="utf-8")
    return p
