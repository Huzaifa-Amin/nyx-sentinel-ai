"""MITRE ATT&CK incident classification with weighted severity scoring."""
from __future__ import annotations
from uuid import uuid4
from loguru import logger
from nyx_sentinel.parsers.models import AlertSeverity, IncidentClassification, ParsedAlert

_MITRE_DB: dict[str, dict] = {
    "T1110":    {"name":"Brute Force",                        "tactic":"Credential Access",   "severity_weight":8},
    "T1110.001":{"name":"Password Guessing",                  "tactic":"Credential Access",   "severity_weight":7},
    "T1110.003":{"name":"Password Spraying",                  "tactic":"Credential Access",   "severity_weight":8},
    "T1078":    {"name":"Valid Accounts",                     "tactic":"Initial Access",       "severity_weight":9},
    "T1059":    {"name":"Command and Scripting Interpreter",  "tactic":"Execution",            "severity_weight":7},
    "T1059.001":{"name":"PowerShell",                         "tactic":"Execution",            "severity_weight":8},
    "T1059.003":{"name":"Windows Command Shell",              "tactic":"Execution",            "severity_weight":7},
    "T1027":    {"name":"Obfuscated Files or Information",    "tactic":"Defense Evasion",      "severity_weight":7},
    "T1046":    {"name":"Network Service Discovery",          "tactic":"Discovery",            "severity_weight":5},
    "T1018":    {"name":"Remote System Discovery",            "tactic":"Discovery",            "severity_weight":5},
    "T1082":    {"name":"System Information Discovery",       "tactic":"Discovery",            "severity_weight":4},
    "T1055":    {"name":"Process Injection",                  "tactic":"Defense Evasion",      "severity_weight":9},
    "T1068":    {"name":"Exploitation for Privilege Escalation","tactic":"Privilege Escalation","severity_weight":10},
    "T1134":    {"name":"Access Token Manipulation",          "tactic":"Defense Evasion",      "severity_weight":9},
    "T1547":    {"name":"Boot or Logon Autostart Execution",  "tactic":"Persistence",          "severity_weight":8},
    "T1547.001":{"name":"Registry Run Keys / Startup Folder", "tactic":"Persistence",          "severity_weight":8},
    "T1053":    {"name":"Scheduled Task/Job",                 "tactic":"Persistence",          "severity_weight":7},
    "T1053.005":{"name":"Scheduled Task",                     "tactic":"Persistence",          "severity_weight":7},
    "T1543.003":{"name":"Windows Service",                    "tactic":"Persistence",          "severity_weight":8},
    "T1003":    {"name":"OS Credential Dumping",              "tactic":"Credential Access",    "severity_weight":10},
    "T1021":    {"name":"Remote Services",                    "tactic":"Lateral Movement",     "severity_weight":8},
    "T1021.001":{"name":"Remote Desktop Protocol",            "tactic":"Lateral Movement",     "severity_weight":7},
    "T1105":    {"name":"Ingress Tool Transfer",              "tactic":"Command and Control",  "severity_weight":8},
    "T1566":    {"name":"Phishing",                           "tactic":"Initial Access",       "severity_weight":7},
    "T1190":    {"name":"Exploit Public-Facing Application",  "tactic":"Initial Access",       "severity_weight":10},
    "T1486":    {"name":"Data Encrypted for Impact",          "tactic":"Impact",               "severity_weight":10},
    "T1489":    {"name":"Service Stop",                       "tactic":"Impact",               "severity_weight":9},
}

_TACTIC_WEIGHTS: dict[str, float] = {
    "Initial Access":8.0,"Execution":7.0,"Persistence":7.5,"Privilege Escalation":8.5,
    "Defense Evasion":7.0,"Credential Access":8.0,"Discovery":4.0,"Lateral Movement":8.5,
    "Collection":7.0,"Command and Control":8.0,"Exfiltration":9.0,"Impact":9.5,
}

_GROUP_TO_TYPE: list[tuple[str,str]] = [
    ("authentication_failed","Credential Brute Force"),("brute_force","Credential Brute Force"),
    ("win_ms_powershell","Suspicious PowerShell Execution"),("powershell","Suspicious PowerShell Execution"),
    ("network_scan","Network Reconnaissance"),("recon","Network Reconnaissance"),
    ("web_attack","Web Application Attack"),("sql_injection","SQL Injection Attempt"),
    ("rootkit","Rootkit / Privilege Escalation"),("privilege_escalation","Privilege Escalation"),
    ("persistence","Persistence Mechanism"),("malware","Malware Execution"),
    ("ransomware","Ransomware Activity"),("lateral_movement","Lateral Movement"),
    ("exfiltration","Data Exfiltration"),("phishing","Phishing Attempt"),
]


def classify_incident(alert: ParsedAlert) -> IncidentClassification:
    score = _compute_severity_score(alert)
    severity = _score_to_severity(score)
    incident_type = _determine_incident_type(alert)
    techniques, tactics = _resolve_mitre(alert)
    actions = _recommend_actions(incident_type, severity, alert)
    summary = _build_summary(alert, incident_type, severity, score)
    clf = IncidentClassification(
        incident_id=str(uuid4()),
        severity=severity, severity_score=round(score, 2),
        incident_type=incident_type, confidence=_compute_confidence(alert),
        mitre_tactics=list(dict.fromkeys(tactics)),
        mitre_techniques=list(dict.fromkeys(techniques)),
        recommended_actions=actions, summary=summary,
    )
    logger.info("Classified alert id={} → type='{}' severity={} score={:.1f}",
                alert.alert_id, incident_type, severity.name, score)
    return clf


def _compute_severity_score(alert: ParsedAlert) -> float:
    rule_component = (alert.rule.level / 15.0) * 40.0
    malicious_count = sum(1 for ioc in alert.iocs if ioc.is_malicious)
    total_iocs = max(len(alert.iocs), 1)
    ioc_ratio = min(malicious_count / total_iocs, 1.0)
    ioc_boost = min(malicious_count * 5, 30)
    ioc_component = (ioc_ratio * 15) + min(ioc_boost, 30)
    tactic_scores = []
    for tech_id in alert.rule.mitre.techniques:
        entry = _MITRE_DB.get(tech_id)
        if entry:
            tactic_scores.append(_TACTIC_WEIGHTS.get(entry.get("tactic", ""), 5.0))
    tactic_component = (max(tactic_scores, default=0.0) / 10.0) * 20.0
    max_abuse = max((ioc.abuse_confidence or 0 for ioc in alert.iocs), default=0)
    max_vt = max(
        ((ioc.vt_malicious or 0) / max(ioc.vt_total or 1, 1) * 100 for ioc in alert.iocs),
        default=0)
    enrichment_component = (max(max_abuse, max_vt) / 100.0) * 10.0
    return min(rule_component + ioc_component + tactic_component + enrichment_component, 100.0)


def _score_to_severity(score: float) -> AlertSeverity:
    if score >= 80: return AlertSeverity.CRITICAL
    if score >= 60: return AlertSeverity.HIGH
    if score >= 40: return AlertSeverity.MEDIUM
    if score >= 20: return AlertSeverity.LOW
    return AlertSeverity.INFORMATIONAL


def _compute_confidence(alert: ParsedAlert) -> float:
    signals = sum([bool(alert.iocs),
                   any(ioc.vt_malicious is not None for ioc in alert.iocs),
                   bool(alert.rule.mitre.techniques),
                   bool(alert.rule.groups)])
    return round(signals / 4, 2)


def _determine_incident_type(alert: ParsedAlert) -> str:
    groups_lower = [g.lower() for g in alert.rule.groups]
    for keyword, label in _GROUP_TO_TYPE:
        if any(keyword in g for g in groups_lower):
            return label
    for tech_id in alert.rule.mitre.techniques:
        entry = _MITRE_DB.get(tech_id)
        if entry: return entry["name"]
    return alert.rule.description.strip() or "Unknown Security Event"


def _resolve_mitre(alert: ParsedAlert) -> tuple[list[str], list[str]]:
    techniques = list(alert.rule.mitre.techniques)
    tactics = list(alert.rule.mitre.tactics)
    for tech_id in techniques:
        entry = _MITRE_DB.get(tech_id)
        if entry and entry["tactic"] not in tactics:
            tactics.append(entry["tactic"])
    return techniques, tactics


def _recommend_actions(incident_type: str, severity: AlertSeverity, alert: ParsedAlert) -> list[str]:
    actions: list[str] = []
    if severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL):
        actions.append("IMMEDIATE: Notify SOC lead and escalate to Tier 2 analyst.")
        actions.append(f"IMMEDIATE: Isolate endpoint '{alert.agent.agent_name}' (IP: {alert.agent.agent_ip or 'unknown'}) from the network.")
    lower_type = incident_type.lower()
    if "brute force" in lower_type or "credential" in lower_type:
        actions += ["Lock the targeted account(s) and reset credentials.",
                    "Review authentication logs for successful logins from the same source IP.",
                    "Block the attacking IP(s) at the perimeter firewall.",
                    "Enable account lockout policy if not already enforced."]
    elif "powershell" in lower_type:
        actions += ["Decode and analyse the Base64/obfuscated PowerShell command if present.",
                    "Review PowerShell ScriptBlock logging (Event ID 4104) on the affected host.",
                    "Check for child processes spawned by PowerShell.",
                    "Search EDR telemetry for the same command on other endpoints."]
    elif "reconnaissance" in lower_type or "discovery" in lower_type:
        actions += ["Identify the scanning source (internal vs external).",
                    "Check for subsequent exploitation attempts from the same source.",
                    "Block scanning source IP if external and unauthorised."]
    elif "privilege escalation" in lower_type or "rootkit" in lower_type:
        actions += ["Preserve a memory dump from the affected system immediately.",
                    "Check for new local admin accounts or group membership changes.",
                    "Initiate full forensic acquisition of the affected endpoint."]
    elif "persistence" in lower_type:
        actions += ["Identify and remove the persistence mechanism.",
                    "Run a full AV/EDR scan on the affected endpoint.",
                    "Search for the same artefact across the environment."]
    elif "malware" in lower_type or "ransomware" in lower_type:
        actions += ["CRITICAL: Immediately isolate the affected host.",
                    "Preserve evidence before any remediation (memory dump, disk image).",
                    "Identify the malware family using hash lookups (VirusTotal, MalwareBazaar).",
                    "Initiate business continuity and incident response plans."]
    elif "exfiltration" in lower_type:
        actions += ["Identify the destination IP/domain and volume of data transferred.",
                    "Block outbound connections to the identified endpoint.",
                    "Notify the Data Protection Officer if personal data is involved."]
    else:
        actions += ["Collect and preserve relevant logs from the affected endpoint.",
                    "Correlate this alert with other alerts in the same time window."]
    malicious_iocs = [ioc for ioc in alert.iocs if ioc.is_malicious]
    if malicious_iocs:
        actions.append(f"Block {len(malicious_iocs)} malicious IOC(s) at network and endpoint controls.")
    actions += ["Document all findings in the incident ticket.",
                "Update detection rules based on artefacts found.",
                "Perform a post-incident review within 5 business days."]
    return actions


def _build_summary(alert: ParsedAlert, incident_type: str, severity: AlertSeverity, score: float) -> str:
    malicious = sum(1 for ioc in alert.iocs if ioc.is_malicious)
    tech_str = ", ".join(alert.rule.mitre.techniques[:3]) if alert.rule.mitre.techniques else "No MITRE techniques identified"
    return (f"A {severity.name} severity {incident_type} incident (score {score:.0f}/100) was detected on endpoint "
            f"'{alert.agent.agent_name}' (IP: {alert.agent.agent_ip or 'unknown'}) at "
            f"{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}. "
            f"Wazuh rule '{alert.rule.rule_id}' ({alert.rule.description}) triggered at level {alert.rule.level}. "
            f"{len(alert.iocs)} IOC(s) extracted, {malicious} flagged malicious. MITRE: {tech_str}.")
