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

You can also use environment file overrides:

```bash
cp .env.example .env
```

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

# Runtime hardening options
python main.py example.com --profile deep --log-format json
python main.py example.com --config-file ./runtime_config.json
python main.py example.com --offline-data ./fixtures/sample_assessment.json
python main.py example.com --env-file ./.env
```

Configuration precedence (highest to lowest):
1. `--config-file` JSON values
2. `.env` / `--env-file` values
3. `--profile` runtime defaults
4. `config.py` defaults

## Output

Running the full pipeline generates:
- `recon_results.json` — recon findings
- `vulnerability_results.json` — CVE mapping with patch intelligence
- `risk_assessment.json` — full risk assessment object
- `executive_summary.json` — concise management summary
- `risk_dashboard.html` — visual dashboard (risk matrix, asset table, dependency map, remediation timeline)
- `remediation_roadmap.txt` — plain-text patching plan (when `--include-roadmap` is set)
- `attack_chain_report.html` — legacy placeholder report

## Architecture

## Phase Status

1. **Phase 1 — Scaffold**: ✅ Done  
   Project structure, CLI entrypoint, config template, utilities.
2. **Phase 2 — Recon Module**: ✅ Done  
   Subdomain discovery, DNS resolution, service fingerprinting, misconfiguration checks.
3. **Phase 3 — Vulnerability Intelligence (defensive)**: ✅ Done  
   NVD querying, CVE filtering, cache/rate limiting, patch guidance, remediation priority.
4. **Phase 4 — Risk Dashboard**: ✅ Done  
   Asset criticality, composite risk scoring, dependency mapping, roadmap, HTML dashboard.
5. **Phase 5 — Automated Tests**: ✅ Done  
   Recon/CVE/Risk unit tests + CLI integration tests.
6. **Phase 6 — Hardening (initial pass)**: ✅ Done  
   Runtime profiles, JSON logging option, config-file overrides, input validation, offline fixture mode.

## When Is This "Done"?

Core MVP + hardening scope is complete (Phases 1-6).  
The previously listed hardening follow-ups are now implemented:
1. `.env` secret loading with precedence rules ✅
2. end-to-end fixture regression test for all output artifacts ✅
3. stricter schema validation for `--offline-data` ✅
