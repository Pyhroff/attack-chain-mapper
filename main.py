"""CLI entry point for the attack chain mapper."""

import argparse
import json
from pathlib import Path

from chain.chain_mapper import map_attack_chain
from cve import assess_vulnerabilities
from recon import run_full_recon
from report.html_generator import (
    generate_html_report,
    generate_remediation_roadmap_text,
    generate_risk_dashboard,
)
from risk import assess_risk
from utils import setup_logging


def run_recon_phase(target: str, verbose: bool) -> dict:
    """Recon phase orchestration."""
    recon_results = run_full_recon(target)
    return recon_results


def run_cve_phase(recon_data: dict, verbose: bool) -> dict:
    """Vulnerability intelligence orchestration."""
    cves = assess_vulnerabilities(recon_data)
    print("Phase 2 completed")
    return cves


def run_chain_phase(recon_data: dict, cve_data: dict, verbose: bool) -> list:
    """Placeholder attack chain mapping orchestration."""
    chains = map_attack_chain(recon_data, cve_data, verbose=verbose)
    print("Phase 3 completed")
    return chains


def run_report_phase(target: str, chains: list, output_path: str, verbose: bool) -> Path:
    """Placeholder reporting orchestration."""
    output = generate_html_report(target, chains, output_path, verbose=verbose)
    print("Phase 4 completed")
    return output


def _write_json(data: dict, path: Path) -> Path:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="attack-chain-mapper",
        description="Map potential attack chains for a target domain.",
    )
    parser.add_argument("target", help="Target domain (e.g. example.com)")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging output",
    )
    parser.add_argument(
        "--output",
        default="reports",
        help="Output directory for generated artifacts",
    )
    parser.add_argument(
        "--recon-only",
        action="store_true",
        help="Run only the recon phase and print JSON findings",
    )
    parser.add_argument(
        "--cve-only",
        action="store_true",
        help="Run recon + vulnerability assessment and print CVE JSON findings",
    )
    parser.add_argument(
        "--risk-only",
        action="store_true",
        help="Run risk assessment using saved recon/vulnerability JSON (skip recon and CVE phases)",
    )
    parser.add_argument(
        "--include-roadmap",
        action="store_true",
        help="Generate remediation roadmap text output",
    )
    parser.add_argument(
        "--output-format",
        choices=["json", "html", "both"],
        default="both",
        help="Risk assessment output format",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    setup_logging(args.verbose)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    recon_json_path = output_dir / "recon_results.json"
    vuln_json_path = output_dir / "vulnerability_results.json"
    risk_json_path = output_dir / "risk_assessment.json"
    risk_html_path = output_dir / "risk_dashboard.html"
    roadmap_text_path = output_dir / "remediation_roadmap.txt"

    if args.risk_only:
        if not recon_json_path.exists() or not vuln_json_path.exists():
            raise FileNotFoundError(
                "risk-only mode requires existing recon_results.json and vulnerability_results.json in output directory"
            )
        recon_data = json.loads(recon_json_path.read_text(encoding="utf-8"))
        cve_data = json.loads(vuln_json_path.read_text(encoding="utf-8"))
        risk_data = assess_risk(
            recon_data,
            cve_data,
            include_roadmap=args.include_roadmap,
        )

        if args.output_format in {"json", "both"}:
            _write_json(risk_data, risk_json_path)
        if args.output_format in {"html", "both"}:
            generate_risk_dashboard(risk_data["dashboard"], str(risk_html_path))
        if args.include_roadmap:
            generate_remediation_roadmap_text(
                risk_data["dashboard"].get("remediation_roadmap", {}),
                str(roadmap_text_path),
            )
        print(f"Risk assessment artifacts written to: {output_dir}")
        return 0

    recon_data = run_recon_phase(args.target, args.verbose)
    _write_json(recon_data, recon_json_path)
    if args.recon_only:
        print(json.dumps(recon_data, indent=2))
        return 0

    print("Phase 1 completed")
    cve_data = run_cve_phase(recon_data, args.verbose)
    _write_json(cve_data, vuln_json_path)
    if args.cve_only:
        print(json.dumps(cve_data, indent=2))
        return 0

    risk_data = assess_risk(
        recon_data,
        cve_data,
        include_roadmap=args.include_roadmap,
    )
    if args.output_format in {"json", "both"}:
        _write_json(risk_data, risk_json_path)
    if args.output_format in {"html", "both"}:
        generate_risk_dashboard(risk_data["dashboard"], str(risk_html_path))
    if args.include_roadmap:
        generate_remediation_roadmap_text(
            risk_data["dashboard"].get("remediation_roadmap", {}),
            str(roadmap_text_path),
        )

    chains = run_chain_phase(recon_data, cve_data, args.verbose)
    report_path = run_report_phase(args.target, chains, str(output_dir / "attack_chain_report.html"), args.verbose)

    print(f"Artifacts written to: {output_dir}")
    print(f"Legacy chain report: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
