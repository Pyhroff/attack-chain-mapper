"""CLI entry point for the attack chain mapper."""

import argparse
import json
from pathlib import Path

from chain.chain_mapper import map_attack_chain
from cve.cve_matcher import match_cves
from recon import run_full_recon
from report.html_generator import generate_html_report
from utils import setup_logging


def run_recon_phase(target: str, verbose: bool) -> dict:
    """Recon phase orchestration."""
    recon_results = run_full_recon(target)
    return recon_results


def run_cve_phase(recon_data: dict, verbose: bool) -> list:
    """Placeholder CVE matching orchestration."""
    cves = match_cves(recon_data, verbose=verbose)
    print("Phase 2 completed")
    return cves


def run_chain_phase(recon_data: dict, cve_data: list, verbose: bool) -> list:
    """Placeholder attack chain mapping orchestration."""
    chains = map_attack_chain(recon_data, cve_data, verbose=verbose)
    print("Phase 3 completed")
    return chains


def run_report_phase(target: str, chains: list, output_path: str, verbose: bool) -> Path:
    """Placeholder reporting orchestration."""
    output = generate_html_report(target, chains, output_path, verbose=verbose)
    print("Phase 4 completed")
    return output


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
        default="attack_chain_report.html",
        help="Output HTML report path",
    )
    parser.add_argument(
        "--recon-only",
        action="store_true",
        help="Run only the recon phase and print JSON findings",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    setup_logging(args.verbose)

    recon_data = run_recon_phase(args.target, args.verbose)
    if args.recon_only:
        print(json.dumps(recon_data, indent=2))
        return 0

    print("Phase 1 completed")
    cve_data = run_cve_phase(recon_data, args.verbose)
    chains = run_chain_phase(recon_data, cve_data, args.verbose)
    report_path = run_report_phase(args.target, chains, args.output, args.verbose)

    print(f"Report written to: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
