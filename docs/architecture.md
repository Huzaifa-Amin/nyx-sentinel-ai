# NYX SENTINEL AI — Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        NYX SENTINEL AI                              │
│                  AI-Enhanced SOC/DFIR Platform                      │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────┐    ┌──────────────┐    ┌──────────────────────────┐
│  Wazuh SIEM  │    │  Suricata    │    │  Windows Event Logs      │
│  (alerts.json│    │  (eve.json)  │    │  (Sysmon + Security)     │
└──────┬───────┘    └──────┬───────┘    └────────────┬─────────────┘
       │                   │                         │
       └───────────────────┴─────────────────────────┘
                                │
                                ▼
                  ┌─────────────────────────┐
                  │   STAGE 1: PARSE        │
                  │   alert_parser.py       │
                  │   • Schema validation   │
                  │   • Pydantic v2 models  │
                  │   • Timestamp norm.     │
                  └────────────┬────────────┘
                               │  ParsedAlert
                               ▼
                  ┌─────────────────────────┐
                  │   STAGE 2: EXTRACT      │
                  │   ioc_extractor.py      │
                  │   • IPv4 addresses      │
                  │   • Domains / URLs      │
                  │   • MD5/SHA1/SHA256     │
                  │   • CVE identifiers     │
                  │   • Usernames / procs   │
                  └────────────┬────────────┘
                               │  list[IOC]
                               ▼
                  ┌─────────────────────────┐
                  │   STAGE 3: ENRICH       │
                  │   threat_intel.py       │
                  │                         │
                  │  VirusTotal v3 API ─────┤
                  │  AbuseIPDB v2 API  ─────┤
                  └────────────┬────────────┘
                               │  list[IOC] (enriched)
                               ▼
                  ┌─────────────────────────┐
                  │   STAGE 4: CLASSIFY     │
                  │   incident_classifier   │
                  │   • MITRE ATT&CK map    │
                  │   • Severity score      │
                  │   • Incident type       │
                  │   • Response actions    │
                  └────────────┬────────────┘
                               │  IncidentClassification
                               ▼
                  ┌─────────────────────────┐
                  │   STAGE 5: COLLECT      │
                  │   collector.py          │
                  │   • Whitelist check     │
                  │   • SHA-256 hashing     │
                  │   • Manifest JSON       │
                  └────────────┬────────────┘
                               │  EvidenceManifest
                               ▼
                  ┌─────────────────────────┐
                  │   STAGE 6: REPORT       │
                  │   report_generator.py   │
                  │   • HTML (Jinja2)       │
                  │   • PDF (fpdf2)         │
                  │   • XSS-safe output     │
                  └─────────────────────────┘
```

---

## Data Models

```
ParsedAlert
├── alert_id: str
├── timestamp: datetime
├── severity: AlertSeverity
├── rule: RuleInfo
│   ├── rule_id, level, description, groups
│   └── mitre: MitreAttack
│       ├── techniques: list[str]
│       └── tactics: list[str]
├── agent: AgentInfo
│   ├── agent_id, agent_name, agent_ip
├── iocs: list[IOC]               ← populated by extractor
│   ├── ioc_type, value, source_field
│   ├── vt_malicious, vt_total   ← populated by enrichment
│   ├── abuse_confidence, country
│   └── is_malicious: bool
├── classification: IncidentClassification   ← from classifier
│   ├── severity, severity_score
│   ├── incident_type, confidence
│   ├── mitre_tactics, mitre_techniques
│   └── recommended_actions: list[str]
└── evidence: EvidenceManifest    ← from collector
    ├── files: list[EvidenceFile]
    │   ├── file_name, sha256, size_bytes
    │   └── original_path, collected_path
    └── collection_errors: list[str]
```

---

## Security Architecture

```
External Input (untrusted JSON)
         │
         ▼
   Pydantic v2 strict validation
   ─ reject malformed input
   ─ safe type coercion
   ─ no silent fallbacks
         │
         ▼
   IOC extraction
   ─ anchored regex (ReDoS-safe)
   ─ noise filtering
   ─ value normalisation
         │
         ▼
   External API calls
   ─ keys from env only (never hardcoded)
   ─ explicit timeouts on every request
   ─ exponential back-off retries
   ─ no IOC values logged at INFO
         │
         ▼
   Evidence collection
   ─ approved directory whitelist
   ─ Path.resolve() before whitelist check
   ─ file size cap (configurable)
   ─ SHA-256 hash verification
         │
         ▼
   Report generation
   ─ Jinja2 autoescape=True
   ─ html.escape() on all values
   ─ no secrets in output
   ─ output path validated
```

---

## Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Language | Python | 3.11+ |
| Data validation | Pydantic | v2.5+ |
| Configuration | pydantic-settings | 2.1+ |
| HTTP client | httpx | 0.26+ |
| Retry logic | tenacity | 8.2+ |
| HTML templates | Jinja2 | 3.1+ |
| PDF generation | fpdf2 | 2.7+ |
| Logging | loguru | 0.7+ |
| CLI | typer + rich | 0.9+ |
| Testing | pytest | 7.4+ |
| SIEM | Wazuh | 4.x |
| IDS | Suricata | 7.x |
| Host telemetry | Sysmon | 15.x |
| ATT&CK framework | MITRE ATT&CK | v14.1 |
| Detection rules | Sigma | 1.0 |

---

## Deployment Architecture (Lab Environment)

```
┌─────────────────────────────────────────────┐
│              VMware / VirtualBox             │
│                                             │
│  ┌──────────────────┐  ┌──────────────────┐ │
│  │  Ubuntu Server   │  │  Windows 11 VM   │ │
│  │  (Wazuh Manager) │  │  (Wazuh Agent)   │ │
│  │  192.168.1.10    │  │  192.168.1.20    │ │
│  │                  │  │  + Sysmon        │ │
│  └────────┬─────────┘  └────────┬─────────┘ │
│           │                     │           │
│  ┌────────▼─────────────────────▼─────────┐ │
│  │         Internal Network               │ │
│  │         192.168.1.0/24                 │ │
│  └────────────────────────────────────────┘ │
│           │                                 │
│  ┌────────▼─────────┐                       │
│  │  Kali Linux VM   │                       │
│  │  (Testing/Attack │                       │
│  │   simulation)    │                       │
│  │  192.168.1.30    │                       │
│  └──────────────────┘                       │
└─────────────────────────────────────────────┘
           │
           ▼
   NYX SENTINEL AI
   (runs on Ubuntu Server)
   reads /var/ossec/logs/alerts/alerts.json
```
