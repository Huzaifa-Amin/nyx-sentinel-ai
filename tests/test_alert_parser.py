"""
tests/test_alert_parser.py
============================
Unit tests for the Wazuh alert parser.

Tests cover:
- Valid single alert parsing
- Batch file parsing (array and NDJSON)
- Missing required fields → ValueError
- Malformed JSON → ValueError
- Timestamp normalization
- Severity derivation from rule level
- Wazuh fields where mitre/groups can be a string OR list
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nyx_sentinel.parsers.alert_parser import (
    parse_alert,
    parse_alerts_from_file,
    parse_alerts_from_json,
)
from nyx_sentinel.parsers.models import AlertSeverity
from tests.conftest import VALID_ALERT_DICT


# ---------------------------------------------------------------------------
# parse_alert — valid input
# ---------------------------------------------------------------------------


class TestParseAlertValid:
    def test_returns_parsed_alert(self):
        alert = parse_alert(VALID_ALERT_DICT)
        assert alert.alert_id == "1706000001.112233"

    def test_timestamp_is_parsed(self):
        alert = parse_alert(VALID_ALERT_DICT)
        assert alert.timestamp.year == 2024
        assert alert.timestamp.month == 1
        assert alert.timestamp.day == 24

    def test_rule_id_and_level(self):
        alert = parse_alert(VALID_ALERT_DICT)
        assert alert.rule.rule_id == "18302"
        assert alert.rule.level == 10

    def test_agent_name_and_ip(self):
        alert = parse_alert(VALID_ALERT_DICT)
        assert alert.agent.agent_name == "CORP-WIN-WKS01"
        assert alert.agent.agent_ip == "10.10.20.15"

    def test_mitre_techniques_list(self):
        alert = parse_alert(VALID_ALERT_DICT)
        assert "T1110" in alert.rule.mitre.techniques
        assert "T1110.001" in alert.rule.mitre.techniques

    def test_severity_derived_from_level_10(self):
        alert = parse_alert(VALID_ALERT_DICT)
        assert alert.severity == AlertSeverity.HIGH

    def test_severity_critical_for_level_14(self):
        data = {**VALID_ALERT_DICT, "rule": {**VALID_ALERT_DICT["rule"], "level": 14}}
        alert = parse_alert(data)
        assert alert.severity == AlertSeverity.CRITICAL

    def test_severity_informational_for_level_2(self):
        data = {**VALID_ALERT_DICT, "rule": {**VALID_ALERT_DICT["rule"], "level": 2}}
        alert = parse_alert(data)
        assert alert.severity == AlertSeverity.INFORMATIONAL

    def test_groups_parsed_as_list(self):
        alert = parse_alert(VALID_ALERT_DICT)
        assert isinstance(alert.rule.groups, list)
        assert "authentication_failed" in alert.rule.groups

    def test_full_log_preserved(self):
        alert = parse_alert(VALID_ALERT_DICT)
        assert "192.168.50.99" in (alert.full_log or "")

    def test_raw_data_stored(self):
        alert = parse_alert(VALID_ALERT_DICT)
        assert alert.raw_data["id"] == "1706000001.112233"

    def test_mitre_as_string_is_coerced_to_list(self):
        """Wazuh sometimes returns mitre fields as a single string."""
        data = json.loads(json.dumps(VALID_ALERT_DICT))
        data["rule"]["mitre"]["attack"] = "T1110"
        alert = parse_alert(data)
        assert alert.rule.mitre.techniques == ["T1110"]

    def test_no_mitre_section_produces_empty_lists(self):
        data = json.loads(json.dumps(VALID_ALERT_DICT))
        del data["rule"]["mitre"]
        alert = parse_alert(data)
        assert alert.rule.mitre.techniques == []
        assert alert.rule.mitre.tactics == []

    def test_agent_without_ip_is_allowed(self):
        data = json.loads(json.dumps(VALID_ALERT_DICT))
        del data["agent"]["ip"]
        alert = parse_alert(data)
        assert alert.agent.agent_ip is None


# ---------------------------------------------------------------------------
# parse_alert — invalid input
# ---------------------------------------------------------------------------


class TestParseAlertInvalid:
    def test_missing_id_raises_value_error(self):
        data = {k: v for k, v in VALID_ALERT_DICT.items() if k != "id"}
        with pytest.raises(ValueError, match="Required field"):
            parse_alert(data)

    def test_missing_timestamp_raises_value_error(self):
        data = {k: v for k, v in VALID_ALERT_DICT.items() if k != "timestamp"}
        with pytest.raises(ValueError, match="Required field"):
            parse_alert(data)

    def test_missing_rule_raises_value_error(self):
        data = {k: v for k, v in VALID_ALERT_DICT.items() if k != "rule"}
        with pytest.raises(ValueError, match="Required field"):
            parse_alert(data)

    def test_missing_agent_raises_value_error(self):
        data = {k: v for k, v in VALID_ALERT_DICT.items() if k != "agent"}
        with pytest.raises(ValueError, match="Required field"):
            parse_alert(data)

    def test_invalid_rule_level_too_high(self):
        data = json.loads(json.dumps(VALID_ALERT_DICT))
        data["rule"]["level"] = 99
        with pytest.raises(ValueError):
            parse_alert(data)

    def test_missing_rule_id_raises_value_error(self):
        data = json.loads(json.dumps(VALID_ALERT_DICT))
        del data["rule"]["id"]
        with pytest.raises(ValueError):
            parse_alert(data)

    def test_empty_dict_raises_value_error(self):
        with pytest.raises(ValueError):
            parse_alert({})


# ---------------------------------------------------------------------------
# parse_alerts_from_file
# ---------------------------------------------------------------------------


class TestParseAlertsFromFile:
    def test_single_alert_file(self, alert_file_path: Path):
        alerts = parse_alerts_from_file(alert_file_path)
        assert len(alerts) == 1
        assert alerts[0].alert_id == "1706000001.112233"

    def test_array_alert_file(self, alert_array_file_path: Path):
        alerts = parse_alerts_from_file(alert_array_file_path)
        assert len(alerts) == 2

    def test_file_not_found_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            parse_alerts_from_file(tmp_path / "nonexistent.json")

    def test_ndjson_file(self, tmp_path: Path):
        p = tmp_path / "alerts.ndjson"
        p.write_text(
            json.dumps(VALID_ALERT_DICT) + "\n" + json.dumps(VALID_ALERT_DICT),
            encoding="utf-8",
        )
        alerts = parse_alerts_from_file(p)
        assert len(alerts) == 2

    def test_partial_bad_records_are_skipped(self, tmp_path: Path):
        bad = {"id": "bad", "timestamp": "not-a-date", "rule": {"level": 5, "description": "x", "id": "1"}, "agent": {"id": "a", "name": "b"}}
        p = tmp_path / "mixed.json"
        p.write_text(json.dumps([VALID_ALERT_DICT, bad]), encoding="utf-8")
        alerts = parse_alerts_from_file(p)
        assert len(alerts) == 1

    def test_real_brute_force_file(self):
        path = Path("data/sample_alerts/brute_force_alert.json")
        if path.exists():
            alerts = parse_alerts_from_file(path)
            assert len(alerts) == 1
            assert alerts[0].rule.rule_id == "18302"


# ---------------------------------------------------------------------------
# parse_alerts_from_json
# ---------------------------------------------------------------------------


class TestParseAlertsFromJson:
    def test_valid_json_string(self):
        alerts = parse_alerts_from_json(json.dumps(VALID_ALERT_DICT))
        assert len(alerts) == 1

    def test_invalid_json_raises_value_error(self):
        with pytest.raises(ValueError, match="not valid JSON"):
            parse_alerts_from_json("{not valid json")

    def test_wrong_type_raises_value_error(self):
        with pytest.raises(ValueError, match="Expected"):
            parse_alerts_from_json('"just a string"')
