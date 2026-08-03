# Attack Chain Mapper - Detailed User Guide

## Overview

Attack Chain Mapper is a **defensive security operations tool** that helps you:
1. discover exposed assets,
2. map high-risk vulnerabilities,
3. prioritize remediation using business-aware risk scores,
4. generate reports for engineering and leadership.

It does **not** provide exploit or offensive automation.

## Core Features

## 1. Reconnaissance
- Subdomain discovery from:
  - crt.sh certificate transparency data
  - optional Shodan history (if API key present)
  - Google dorking patterns
- DNS A/AAAA resolution and dead-host filtering
- Service fingerprinting:
  - HTTP/HTTPS status, headers, page title
  - SSL certificate metadata
  - technology hints (Jenkins, nginx, AWS S3, Docker Registry)
- Misconfiguration checks:
  - common S3 bucket exposure patterns
  - public GitHub leak signal counts
  - MX/TXT/NS records + SPF/DKIM/DMARC weakness checks

## 2. Vulnerability Intelligence
- Version extraction from fingerprints
- NVD query and normalization (high/critical CVEs only)
- API cooldown for NVD request limits
- File-based query caching
- Patch guidance enrichment and remediation priority scoring

## 3. Risk Assessment & Dashboard
- Asset criticality scoring (customizable)
- Composite risk score:
  - criticality impact
  - maximum CVSS severity
  - vulnerability count
- Risk matrix data + dashboard rendering
- Remediation roadmap grouped by urgency windows
- Dependency-impact mapping (blast-radius context)

## 4. Hardening & Reliability
- Runtime profiles (`quick`, `standard`, `deep`)
- Text or JSON logging
- `.env` and JSON config overrides with precedence
- Offline fixture mode for deterministic testing and demos
- Automated test suite + CI workflow
- Docker execution path

## Installation

```bash
git clone https://github.com/Pyhroff/attack-chain-mapper.git
cd attack-chain-mapper
pip install -r requirements.txt
```

Optional (package entrypoint):

```bash
pip install .
attack-chain-mapper --help
```

## Configuration

### Option A: `.env` file (recommended)

Copy example:

```bash
cp .env.example .env
```

Supported keys:
- `SHODAN_API_KEY`
- `VIRUSTOTAL_API_KEY`
- `NVD_API_KEY`
- `REQUEST_TIMEOUT_SECONDS`
- `RETRY_ATTEMPTS`
- `RETRY_BACKOFF_SECONDS`

### Option B: JSON override file

Example `runtime_config.json`:

```json
{
  "NVD_API_KEY": "your-key",
  "request_timeout_seconds": 8,
  "retry_attempts": 4,
  "retry_backoff_seconds": 2.0,
  "asset_criticality_rules": { "jenkins": 10 },
  "maintenance_windows": { "critical": "Sat 01:00-02:00 UTC" }
}
```

### Precedence (highest to lowest)
1. `--config-file`
2. `--env-file` / `.env`
3. `--profile`
4. defaults in `config.py`

## CLI Usage

## Full run

```bash
python main.py example.com --output ./reports --include-roadmap
```

## Stage-specific modes

```bash
python main.py example.com --recon-only
python main.py example.com --cve-only
python main.py example.com --risk-only --output ./reports
```

## Output control

```bash
python main.py example.com --output-format json
python main.py example.com --output-format html
python main.py example.com --output-format both
```

## Runtime hardening options

```bash
python main.py example.com --profile deep --log-format json
python main.py example.com --config-file ./runtime_config.json
python main.py example.com --env-file ./.env
```

## Offline deterministic mode

```bash
python main.py example.com \
  --offline-data ./tests/fixtures/offline_assessment_fixture.json \
  --output ./reports \
  --output-format both \
  --include-roadmap
```

## Output Artifacts

Generated under `--output` directory:
- `recon_results.json`
- `vulnerability_results.json`
- `risk_assessment.json`
- `executive_summary.json`
- `risk_dashboard.html`
- `remediation_roadmap.txt` (if `--include-roadmap`)
- `attack_chain_report.html` (legacy placeholder)

## CI and Tests

Run locally:

```bash
python -m unittest discover -s tests -v
```

GitHub Actions (`.github/workflows/ci.yml`) runs the same test suite on push/PR.

## Docker Usage

Build:

```bash
docker build -t attack-chain-mapper .
```

Run:

```bash
docker run --rm attack-chain-mapper example.com --recon-only
```

Mount outputs:

```bash
docker run --rm -v ${PWD}/reports:/app/reports attack-chain-mapper example.com --output /app/reports --include-roadmap
```

## Troubleshooting

## `--risk-only` fails
- Ensure `recon_results.json` and `vulnerability_results.json` exist in `--output`.

## API coverage seems low
- Add valid API keys (`NVD_API_KEY`, `SHODAN_API_KEY`) via `.env` or config JSON.

## Slow recon or timeout errors
- Use `--profile deep` or increase timeout via config overrides.

## Invalid offline fixture errors
- Ensure fixture has:
  - `recon_results.domain` (string)
  - `recon_results.fingerprints` (object)
  - optional `vulnerability_results` as object of lists
