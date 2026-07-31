"""Reconnaissance package orchestration."""

import logging

from .fingerprinting import fingerprint_service
from .misconfig_scanner import check_dns_records, check_github_leaks, check_s3_buckets
from .subdomain_enum import find_subdomains, resolve_subdomains

logger = logging.getLogger(__name__)


def run_full_recon(domain: str) -> dict:
    """Run complete recon workflow and return aggregated findings."""
    logger.info("Starting full recon for %s", domain)

    subdomains = find_subdomains(domain)
    resolved = resolve_subdomains(subdomains)

    fingerprints: dict[str, list[dict]] = {}
    for subdomain, ips in resolved.items():
        host_findings: list[dict] = []
        for ip in ips:
            host_findings.append(fingerprint_service(subdomain, ip))
        fingerprints[subdomain] = host_findings

    misconfigs = [
        {"check": "s3_buckets", "result": check_s3_buckets(domain)},
        {"check": "github_leaks", "result": check_github_leaks(domain)},
        {"check": "dns_records", "result": check_dns_records(domain)},
    ]
    logger.info("Recon completed for %s", domain)
    return {
        "domain": domain,
        "subdomains": subdomains,
        "resolved_subdomains": resolved,
        "fingerprints": fingerprints,
        "misconfigS": misconfigs,
    }
