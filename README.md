# NYX SENTINEL AI
### AI-Enhanced SOC & Digital Forensics Incident Response Platform

[![CI Pipeline](https://github.com/YOUR_USERNAME/nyx-sentinel-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/nyx-sentinel-ai/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Final-Year Cybersecurity Project** — A Python-based SOC simulation platform that automates alert triage, IOC extraction, threat intelligence enrichment, MITRE ATT&CK mapping, digital evidence collection, and incident report generation.

---

## What NYX SENTINEL AI Does

NYX SENTINEL AI simulates the core workflow of a Security Operations Centre (SOC) analyst:

```
Raw Wazuh Alert JSON
       │
       ▼
┌─────────────────┐
│  1. PARSE       │  Validate and normalise Wazuh alert format (Pydantic v2)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  2. EXTRACT     │  Pull IOCs: IPs, domains, hashes, URLs, CVEs, usernames
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  3. ENRICH      │  VirusTotal v3 + AbuseIPDB v2 reputation lookups
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  4. CLASSIFY    │  MITRE ATT&CK mapping + weighted severity scoring
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  5. COLLECT     │  Forensic evidence collection + SHA-256 manifest
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  6. REPORT      │  Professional HTML + PDF incident reports
└─────────────────┘
```

---

## Project Structure

```
nyx-sentinel-ai/
├── src/nyx_sentinel/
│   ├── config/
│   │   └── settings.py          # Pydantic-settings; no secrets hardcoded
│   ├── parsers/
│   │   ├── models.py            # ParsedAlert, IOC, EvidenceManifest models
│   │   └── alert_parser.py      # Wazuh JSON ingestion + schema validation
│   ├── extractors/
│   │   └── ioc_extractor.py     # Regex-based IOC extraction (ReDoS-safe)
│   ├── enrichment/
│   │   └── threat_intel.py      # Async VirusTotal + AbuseIPDB enrichment
│   ├── forensics/
│   │   └── collector.py         # Evidence collection + SHA-256 hashing
│   ├── analysis/
│   │   └── incident_classifier.py  # MITRE ATT&CK + severity scoring
│   ├── reporting/
│   │   ├── report_generator.py  # HTML + PDF report generation
│   │   └── templates/
│   │       └── incident_report.html.j2   # Dark-theme Jinja2 template
│   └── rules/
│       ├── brute_force.yml
│       ├── suspicious_powershell.yml
│       ├── reconnaissance.yml
│       ├── privilege_escalation.yml
│       └── persistence.yml
├── tests/
│   ├── conftest.py
│   ├── test_alert_parser.py
│   ├── test_ioc_extractor.py
│   ├── test_threat_intel.py
│   ├── test_collector.py
│   ├── test_incident_classifier.py
│   └── test_report_generator.py
├── data/
│   ├── sample_alerts/           # Realistic Wazuh alert JSON samples
│   └── mitre_attack/            # MITRE ATT&CK technique database
├── scripts/
│   └── run_pipeline.py          # Full pipeline CLI runner
├── docs/
│   ├── architecture.md
│   ├── install_guide.md
│   └── demo_steps.md
├── .env.example
└── .github/workflows/ci.yml
```

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/nyx-sentinel-ai.git
cd nyx-sentinel-ai
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# or
venv\Scripts\activate.bat       # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements-dev.txt
pip install -e .
```

### 4. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and add your API keys:

```env
VIRUSTOTAL_API_KEY=your_key_here   # Free at virustotal.com
ABUSEIPDB_API_KEY=your_key_here    # Free at abuseipdb.com
```

> **No API keys?** Use `--stub` mode — no network calls are made.

---

## Running the Pipeline

### Process a single alert (stub mode — safe for demo)

```bash
python scripts/run_pipeline.py data/sample_alerts/brute_force_alert.json --stub
```

### Process all sample alerts with live APIs

```bash
python scripts/run_pipeline.py data/sample_alerts/ --output /tmp/my_reports
```

### Process an alert and collect evidence

```bash
python scripts/run_pipeline.py data/sample_alerts/powershell_alert.json \
    --stub \
    --evidence /var/log/auth.log /var/log/syslog \
    --output /tmp/reports
```

### Run the test suite

```bash
pytest tests/ -v
```

### Run with coverage

```bash
pytest tests/ --cov=src --cov-report=html
```

---

## Sample Alert Types

| File | Technique | Severity |
|------|-----------|----------|
| `brute_force_alert.json` | T1110 — Brute Force | HIGH |
| `powershell_alert.json` | T1059.001 — PowerShell | HIGH |
| `recon_alert.json` | T1046 — Network Discovery | MEDIUM |

---

## Detection Rules (Sigma)

Five Sigma-compatible detection rules are included:

| Rule | MITRE Technique | Wazuh Level |
|------|----------------|-------------|
| `brute_force.yml` | T1110, T1110.001, T1110.003 | 10 |
| `suspicious_powershell.yml` | T1059.001, T1027 | 12 |
| `reconnaissance.yml` | T1046, T1018 | 8 |
| `privilege_escalation.yml` | T1068, T1055, T1134 | 14 |
| `persistence.yml` | T1547.001, T1053.005 | 11 |

---

## Security Design

| Control | Implementation |
|---------|---------------|
| No hardcoded secrets | All API keys via `.env` / environment variables |
| Input validation | Pydantic v2 strict schemas on all external input |
| Path traversal prevention | Whitelist + `Path.resolve()` before any file operation |
| ReDoS protection | Anchored, length-limited regex patterns |
| XSS prevention | All values HTML-escaped via Jinja2 autoescape + `html.escape()` |
| Timeout safety | All HTTP calls have explicit timeouts via httpx |
| Retry safety | Exponential back-off with jitter via tenacity |
| Privilege separation | Approved directory whitelist for evidence collection |
| Hash verification | SHA-256 of every collected evidence file |

---

## Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.11+ |
| Data validation | Pydantic v2, pydantic-settings |
| HTTP client | httpx (async) |
| Retry logic | tenacity |
| HTML templating | Jinja2 |
| PDF generation | fpdf2 |
| Logging | loguru |
| CLI | typer + rich |
| Testing | pytest, pytest-asyncio, pytest-cov, respx |
| SIEM integration | Wazuh |
| IDS integration | Suricata |
| Detection rules | Sigma |
| ATT&CK framework | MITRE ATT&CK v14.1 |

---

## API Keys (Free Tier)

| Service | Free Limit | Sign Up |
|---------|-----------|---------|
| VirusTotal | 4 requests/min | [virustotal.com](https://www.virustotal.com) |
| AbuseIPDB | 1,000 requests/day | [abuseipdb.com](https://www.abuseipdb.com) |

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*NYX SENTINEL AI — Built as a final-year cybersecurity portfolio project.*
