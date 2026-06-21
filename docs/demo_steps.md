# NYX SENTINEL AI — Demo Steps

> Use this guide for your final presentation or viva. Each step takes about 1–2 minutes.
> Total demo time: ~10 minutes.

---

## Pre-Demo Checklist

- [ ] Virtual environment activated (`source venv/bin/activate`)
- [ ] Terminal font size increased for visibility
- [ ] Browser open at `/tmp/nyx_reports/` or ready to open
- [ ] `.env` configured (or `--stub` flag ready)

---

## Demo Script

### Step 0 — Show the project structure (1 min)

```bash
# Show the full tree
find . -not -path '*/__pycache__/*' -not -path '*/.git/*' \
       -not -path '*/venv/*' -not -path '*.egg-info*' \
       | sort | head -60
```

**Say:** "This is a Python 3.11 SOC automation platform. Six pipeline modules, five Sigma detection rules, and a full test suite."

---

### Step 1 — Run the test suite (2 min)

```bash
pytest tests/ -v --tb=short
```

**Say:** "All modules have unit and negative tests. I test valid inputs, malformed inputs, path traversal attempts, and HTML injection. 100% of security-critical paths have dedicated negative tests."

---

### Step 2 — Show a real Wazuh alert (30 sec)

```bash
cat data/sample_alerts/brute_force_alert.json | python3 -m json.tool | head -40
```

**Say:** "This is a real Wazuh alert format — event 4625, a Windows failed logon from an external IP. The rule level is 10, MITRE technique T1110 — Brute Force."

---

### Step 3 — Run the full pipeline (2 min)

```bash
python scripts/run_pipeline.py \
    data/sample_alerts/brute_force_alert.json \
    --stub \
    --output /tmp/nyx_reports
```

**Walk through the output stage by stage:**
- "Stage 1 parses and validates the alert schema"
- "Stage 2 extracts IOCs — we get the IP, username, and SHA-256 hash"
- "Stage 3 enriches — stub mode for demo, but this calls VirusTotal in production"
- "Stage 4 classifies — HIGH severity, Credential Brute Force, 72/100 score"
- "Stage 5 evidence — skipped here, I'll show that separately"
- "Stage 6 generates the report — HTML and PDF"

---

### Step 4 — Open the HTML report (2 min)

```bash
# Find the latest report
ls -t /tmp/nyx_reports/*.html | head -1
```

Open in browser. Walk through:
- **Header** — report ID, timestamp, CONFIDENTIAL marker
- **Severity banner** — HIGH badge, score bar, incident type
- **Stats row** — IOC counts, malicious count, confidence
- **Executive summary** — auto-generated paragraph
- **Alert details** — rule, level, agent name, IP
- **MITRE ATT&CK** — tactics and technique tags
- **IOC table** — type, value, VT detection, AbuseIPDB score
- **Recommended actions** — prioritised investigation steps

---

### Step 5 — Run all three sample alerts (1 min)

```bash
python scripts/run_pipeline.py data/sample_alerts/ --stub
```

**Say:** "I can run the full pipeline across all alerts in a directory. Each produces its own HTML and PDF report."

---

### Step 6 — Show a Sigma rule (30 sec)

```bash
cat src/nyx_sentinel/rules/suspicious_powershell.yml
```

**Say:** "These are Sigma-format detection rules — the industry standard. They define what Wazuh or any SIEM should look for, with MITRE ATT&CK tags, false-positive guidance, and response actions."

---

### Step 7 — Show security controls (2 min)

**Path traversal prevention:**
```python
# In Python REPL or show the code
from nyx_sentinel.forensics.collector import _sanitise_incident_id
print(_sanitise_incident_id("../../etc/passwd"))  # → "______etc_passwd"
```

**HTML escaping:**
```python
from nyx_sentinel.reporting.report_generator import _esc
print(_esc('<script>alert("xss")</script>'))
# → &lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;
```

**No hardcoded secrets:**
```bash
grep -r "api_key\s*=" src/ --include="*.py"
# Shows: only Field(default="") — loaded from environment
```

---

## Key Talking Points

### "Why Python?"
- Python is the standard language for SOC automation and threat intel tooling
- The ecosystem (Pydantic, httpx, Jinja2) is mature and well-maintained
- Readable, auditable code is essential for security tools

### "How does the classifier work?"
- Rule-based, fully transparent — no black-box ML
- Weighted score from four components: rule level (40%), malicious IOC ratio (30%), MITRE tactic severity (20%), enrichment signal (10%)
- Every decision is traceable back to input data

### "Why Pydantic v2 for validation?"
- Strict schema validation rejects malformed input before any processing
- All external data is untrusted until validated
- Type safety prevents entire classes of bugs

### "Is this production-ready?"
- No — this is a portfolio/lab project. Production would require: a message queue (Kafka/RabbitMQ), a database (PostgreSQL), a proper secret manager (Vault/AWS Secrets Manager), multi-tenancy, and full audit logging.

### "What's the MITRE ATT&CK coverage?"
- 28 techniques mapped in the database
- Covers all major tactics: Initial Access through Impact
- Rules cover the Top 5 most common enterprise attack patterns

---

## Appendix — Sample Output

```
NYX SENTINEL AI
AI-Enhanced SOC & Digital Forensics Incident Response Platform

Found 1 alert file(s) to process.

──── brute_force_alert.json ────────────────────────────────────────────

  [1/6] Parsing alerts (brute_force_alert.json)
  ✔ Alert 1706000001.112233 — Multiple Windows Logon Failures... [High]

  Processing alert 1706000001.112233

  [2/6] Extracting IOCs
  ✔ 3 IOC(s) extracted

  [3/6] Enriching IOCs (stub mode)
  ✔ 1 IOC(s) flagged as malicious

  [4/6] Classifying incident
  ✔ [High] Credential Brute Force — Score: 72/100
  ✔ MITRE: T1110, T1110.001

  [5/6] Collecting evidence
  ℹ No evidence paths specified — skipping collection

  [6/6] Generating reports
  ✔ HTML report → /tmp/nyx_reports/incident_A3F9B2C1.html
  ✔ PDF report  → /tmp/nyx_reports/incident_A3F9B2C1.pdf

──── Pipeline Complete ──────────────────────────────────────────────────

  ╭──────────────────────────────────────────────────────╮
  │  Report  │  HTML                                     │
  │  1       │  /tmp/nyx_reports/incident_A3F9B2C1.html  │
  ╰──────────────────────────────────────────────────────╯

  ✔ 1 report(s) generated successfully.
```
