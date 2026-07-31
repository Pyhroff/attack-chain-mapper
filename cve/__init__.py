"""CVE and vulnerability assessment orchestration."""

from __future__ import annotations

import logging

from .vulnerability_manager import (
    ASSET_CRITICALITY_DEFAULTS,
    extract_versions,
    fetch_patch_info,
    generate_remediation_guidance,
    query_nvd_api,
    score_remediation_priority,
)

logger = logging.getLogger(__name__)


def assess_vulnerabilities(recon_results: dict) -> dict:
    """Build prioritized vulnerability intelligence by software component."""
    fingerprints = recon_results.get("fingerprints", {})
    versions = extract_versions(fingerprints)

    findings_by_software: dict[str, list[dict]] = {}
    for software, version in versions.items():
        logger.info("Assessing CVEs for %s %s", software, version)
        cves = query_nvd_api(software, version)
        software_findings: list[dict] = []
        asset_criticality = ASSET_CRITICALITY_DEFAULTS.get(software, "medium")

        for cve in cves:
            patch_info = fetch_patch_info(software, version, cve["cve_id"], cve_data=cve)
            priority = score_remediation_priority(cve, patch_info, asset_criticality)
            remediation = generate_remediation_guidance(cve, patch_info)
            software_findings.append(
                {
                    **cve,
                    "patch_version": patch_info.get("patched_version"),
                    "patch_date": patch_info.get("patch_date"),
                    "patch_source": patch_info.get("source"),
                    "priority": priority["priority"],
                    "priority_reasoning": priority["reasoning"],
                    "remediation": remediation,
                }
            )

        software_findings.sort(key=lambda item: (item.get("priority", 0), item.get("cvss", 0.0)), reverse=True)
        findings_by_software[software] = software_findings

    return findings_by_software
