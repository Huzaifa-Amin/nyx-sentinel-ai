"""Safe ingestion and validation of raw Wazuh JSON alerts."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from loguru import logger
from pydantic import ValidationError
from nyx_sentinel.parsers.models import AgentInfo, MitreAttack, ParsedAlert, RuleInfo


def parse_alert(raw: dict[str, Any]) -> ParsedAlert:
    _require_keys(raw, ["id", "timestamp", "rule", "agent"])
    rule_raw = raw["rule"]
    _require_keys(rule_raw, ["id", "level", "description"])
    agent_raw = raw["agent"]
    _require_keys(agent_raw, ["id", "name"])
    mitre_raw = rule_raw.get("mitre", {})
    mitre = MitreAttack(
        techniques=_safe_list(mitre_raw.get("attack", [])),
        tactics=_safe_list(mitre_raw.get("tactic", [])),
        technique_names=_safe_list(mitre_raw.get("technique", [])),
    )
    rule = RuleInfo(
        rule_id=str(rule_raw["id"]),
        level=int(rule_raw["level"]),
        description=str(rule_raw["description"]),
        groups=_safe_list(rule_raw.get("groups", [])),
        mitre=mitre,
    )
    agent = AgentInfo(
        agent_id=str(agent_raw["id"]),
        agent_name=str(agent_raw["name"]),
        agent_ip=agent_raw.get("ip"),
    )
    try:
        alert = ParsedAlert(
            alert_id=str(raw["id"]),
            timestamp=raw["timestamp"],
            rule=rule, agent=agent,
            full_log=raw.get("full_log"),
            raw_data=raw,
        )
    except ValidationError as exc:
        first = exc.errors()[0]
        raise ValueError(
            f"Alert validation failed on field '{'.'.join(str(x) for x in first['loc'])}': {first['msg']}"
        ) from exc
    logger.debug("Parsed alert id={} rule_id={} level={}", alert.alert_id, rule.rule_id, rule.level)
    return alert


def parse_alerts_from_file(path: Path) -> list[ParsedAlert]:
    resolved = path.resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"Alert file not found: {resolved}")
    raw_text = resolved.read_text(encoding="utf-8")
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError:
        data = _parse_ndjson(raw_text, path)
    if isinstance(data, dict):
        raw_alerts: list[dict[str, Any]] = [data]
    elif isinstance(data, list):
        raw_alerts = data
    else:
        raise ValueError(f"Expected JSON object or array in '{path}', got {type(data).__name__}")
    results: list[ParsedAlert] = []
    for idx, raw in enumerate(raw_alerts):
        try:
            results.append(parse_alert(raw))
        except (ValueError, KeyError, TypeError) as exc:
            logger.warning("Skipping alert index {} in '{}': {}", idx, path, exc)
    logger.info("Loaded {} / {} alerts from '{}'", len(results), len(raw_alerts), path)
    return results


def parse_alerts_from_json(json_string: str) -> list[ParsedAlert]:
    try:
        data = json.loads(json_string)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Input is not valid JSON: {exc}") from exc
    if isinstance(data, dict):
        return [parse_alert(data)]
    if isinstance(data, list):
        results = []
        for idx, item in enumerate(data):
            try:
                results.append(parse_alert(item))
            except (ValueError, KeyError, TypeError) as exc:
                logger.warning("Skipping alert index {}: {}", idx, exc)
        return results
    raise ValueError(f"Expected a JSON object or array, got {type(data).__name__}")


def _require_keys(obj: dict[str, Any], keys: list[str]) -> None:
    missing = [k for k in keys if k not in obj]
    if missing:
        raise ValueError(f"Required field(s) missing from alert: {missing}")


def _safe_list(value: Any) -> list[str]:
    if value is None: return []
    if isinstance(value, str): return [value]
    if isinstance(value, list): return [str(i) for i in value]
    return [str(value)]


def _parse_ndjson(text: str, path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line: continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            logger.warning("Skipping invalid JSON on line {} of '{}': {}", line_no, path, exc)
    return records
