"""Backward-compatible wrapper around defensive vulnerability assessment."""

from cve import assess_vulnerabilities


def match_cves(recon_data: dict, verbose: bool = False) -> dict:
    return assess_vulnerabilities(recon_data)
