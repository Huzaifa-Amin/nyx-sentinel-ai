# NYX SENTINEL AI — Installation Guide

## Prerequisites

| Requirement | Minimum Version | Notes |
|------------|----------------|-------|
| Python | 3.11 | 3.12 recommended |
| Git | 2.40 | For cloning the repo |
| pip | 23.0 | Ships with Python |
| OS | Ubuntu 22.04 / Windows 10 / macOS 13 | Any modern OS works |

---

## Step 1 — Clone

```bash
git clone https://github.com/YOUR_USERNAME/nyx-sentinel-ai.git
cd nyx-sentinel-ai
```

---

## Step 2 — Virtual Environment

**Linux / macOS**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows (PowerShell)**
```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

---

## Step 3 — Install Python Dependencies

```bash
pip install --upgrade pip
pip install -r requirements-dev.txt
pip install -e .
```

This installs:
- Core runtime dependencies (Pydantic, httpx, Jinja2, fpdf2, etc.)
- Development/test dependencies (pytest, ruff, etc.)
- The `nyx_sentinel` package itself in editable mode

---

## Step 4 — Configure Environment Variables

```bash
cp .env.example .env
```

Open `.env` and fill in your values:

```env
# --- Threat Intelligence (optional but recommended) ---
VIRUSTOTAL_API_KEY=your_vt_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here

# --- Paths ---
EVIDENCE_BASE_DIR=/tmp/nyx_evidence
REPORTS_DIR=/tmp/nyx_reports
```

> **API keys are optional.** Without them, run with `--stub` to use simulated enrichment.

### Getting Free API Keys

**VirusTotal (4 requests/min free)**
1. Go to https://www.virustotal.com
2. Create a free account
3. Go to your profile → API Key
4. Copy the key into `.env`

**AbuseIPDB (1000 checks/day free)**
1. Go to https://www.abuseipdb.com
2. Create a free account
3. Go to Account → API → Create Key
4. Copy the key into `.env`

---

## Step 5 — Verify Installation

```bash
# Run the test suite (should show all green)
pytest tests/ -v

# Run the demo pipeline (no API keys needed)
python scripts/run_pipeline.py data/sample_alerts/brute_force_alert.json --stub
```

If successful, you'll see:
- A full pipeline run printed to the terminal
- An HTML report at `/tmp/nyx_reports/incident_XXXXXXXX.html`
- A PDF report at `/tmp/nyx_reports/incident_XXXXXXXX.pdf`

Open the HTML report in your browser to see the full incident report.

---

## Optional: Wazuh Integration (Ubuntu Server)

To use real Wazuh alerts instead of sample files:

```bash
# Install Wazuh agent (adjust version as needed)
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt-get update && apt-get install wazuh-agent

# Configure to point to your Wazuh Manager
nano /var/ossec/etc/ossec.conf
```

Wazuh stores alerts in JSON format at:
```
/var/ossec/logs/alerts/alerts.json
```

Feed them into NYX SENTINEL AI:
```bash
python scripts/run_pipeline.py /var/ossec/logs/alerts/alerts.json --stub
```

---

## Troubleshooting

| Problem | Solution |
|---------|---------|
| `ModuleNotFoundError: nyx_sentinel` | Run `pip install -e .` from project root |
| `ValidationError: virustotal_api_key` | Add `VIRUSTOTAL_API_KEY=` (blank is OK) to `.env` |
| `Permission denied` on evidence paths | Evidence directories must be in `ALLOWED_EVIDENCE_DIRS` |
| Reports not generated | Check `REPORTS_DIR` is writable |
| Tests failing on import | Ensure `venv` is activated and `pip install -e .` was run |
