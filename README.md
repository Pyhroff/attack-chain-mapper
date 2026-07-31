# Vulnerability Risk Assessment Tool

Automated recon, CVE correlation, and risk-based patch prioritization for security teams.

## What It Does

Given a domain, this tool:
1. **Recon** — discovers subdomains, fingerprints running services (Jenkins, nginx, S3, Docker), and flags common misconfigurations (open S3 buckets, weak DNS records, leaked secrets on GitHub)
2. **Vulnerability Assessment** — matches discovered software versions against the NVD CVE database, filters for high/critical severity, and looks up available patches
3. **Risk Scoring** — combines asset criticality (how important is this system?) with vulnerability severity (how bad is this CVE?) into a single composite risk score per asset
4. **Remediation Roadmap** — generates a week-by-week patching plan prioritized by risk, with estimated downtime and dependency impact

This is a **defensive** tool: it identifies and prioritizes what to fix, not how to exploit it. No PoC lookup, no exploitation logic.

## Why This Matters

A VAPT/AppSec consultant spends a significant chunk of engagement time on recon and triage — figuring out what's exposed, what's actually risky, and what to fix first. This tool automates that triage step, turning a flat list of findings into a prioritized action plan.

## Installation

```bash
git clone https://github.com/Pyhroff/attack-chain-mapper.git
cd attack-chain-mapper
pip install -r requirements.txt
```

Fill in API keys in `config.py` (Shodan and NVD are optional but recommended — the tool degrades gracefully without them, just with less coverage).

## Usage

```bash
# Full pipeline: recon + CVE assessment + risk scoring + dashboard
python main.py example.com --output ./reports --include-roadmap

# Individual stages
python main.py example.com --recon-only
python main.py example.com --cve-only
python main.py example.com --risk-only

# Output format control
python main.py example.com --output-format html   # or json, or both (default)
```

## Output

Running the full pipeline generates:
- `risk_assessment_<domain>_<timestamp>.json` — raw structured data
- `risk_dashboard_<domain>_<timestamp>.html` — visual dashboard (risk matrix, asset table, dependency map, remediation timeline)
- `remediation_roadmap_<domain>_<timestamp>.txt` — plain-text patching plan

## Architecture
