"""Risk assessment orchestration module."""

from __future__ import annotations

import logging

from .asset_profiler import (
    assess_attack_surface,
    calculate_asset_risk_score,
    map_asset_dependencies,
    score_asset_criticality,
)
from .risk_matrix import build_risk_matrix, generate_risk_dashboard_data

logger = logging.getLogger(__name__)


def _software_to_assets(recon_results: dict) -> dict:
    mapping = {}
    for asset, findings in recon_results.get("fingerprints", {}).items():
        software_names = set()
        for finding in findings:
            for tech in finding.get("tech_stack", []):
                software_names.add(str(tech.get("technology", "")).lower())
            for transport in ("http", "https"):
                headers = (finding.get(transport) or {}).get("headers", {})
                server = str(headers.get("Server", "")).lower()
                if "nginx" in server:
                    software_names.add("nginx")
                if headers.get("X-Jenkins"):
                    software_names.add("jenkins")
        mapping[asset] = software_names
    return mapping


def assess_risk(
    recon_results: dict,
    vuln_results: dict,
    criticality_overrides: dict | None = None,
    include_roadmap: bool = True,
) -> dict:
    """Run full risk assessment and return composite object."""
    logger.info("Starting risk assessment for %s", recon_results.get("domain"))
    software_map = _software_to_assets(recon_results)

    asset_rows = []
    remediation_data_by_asset = {}
    for asset, findings in recon_results.get("fingerprints", {}).items():
        is_external = not (asset.endswith(".internal") or asset.endswith(".local"))
        environment = "prod"
        lower_asset = asset.lower()
        if "staging" in lower_asset:
            environment = "staging"
        elif "test" in lower_asset:
            environment = "test"
        elif "dev" in lower_asset:
            environment = "dev"

        tech_stack = []
        has_http = False
        has_https = False
        for finding in findings:
            has_http = has_http or bool((finding.get("http") or {}).get("status_code") is not None)
            has_https = has_https or bool((finding.get("https") or {}).get("status_code") is not None)
            tech_stack.extend(finding.get("tech_stack", []))

        asset_data = {
            "asset": asset,
            "tech_stack": tech_stack,
            "is_external": is_external,
            "is_customer_facing": "api" in lower_asset,
            "environment": environment,
        }
        criticality = score_asset_criticality(asset_data, overrides=criticality_overrides)

        asset_vulns = []
        for software in software_map.get(asset, set()):
            asset_vulns.extend(vuln_results.get(software, []))
        asset_vulns.sort(key=lambda item: (item.get("priority", 0), item.get("cvss", 0.0)), reverse=True)
        remediation_data_by_asset[asset] = asset_vulns

        risk = calculate_asset_risk_score(criticality, asset_vulns)
        asset_row = {
            "asset": asset,
            "service_type": criticality.get("service_type"),
            "criticality": criticality["criticality"],
            "criticality_reasoning": criticality["reasoning"],
            "risk_score": risk["risk_score"],
            "risk_level": risk["risk_level"],
            "vulnerability_count": risk["cve_count"],
            "max_cvss": risk["max_cvss"],
            "has_http": has_http,
            "has_https": has_https,
            "vulnerabilities": asset_vulns,
        }
        logger.info(
            "Asset %s scored risk %.2f (%s) with %d vulnerabilities",
            asset_row["asset"],
            asset_row["risk_score"],
            asset_row["risk_level"],
            asset_row["vulnerability_count"],
        )
        asset_rows.append(asset_row)

    asset_rows.sort(key=lambda item: item["risk_score"], reverse=True)
    dependencies = map_asset_dependencies(recon_results)
    attack_surface = assess_attack_surface(asset_rows, recon_results=recon_results)
    matrix = build_risk_matrix(asset_rows)
    dashboard = generate_risk_dashboard_data(
        recon_results,
        vuln_results,
        {
            "assets": asset_rows,
            "dependencies": dependencies,
            "attack_surface": attack_surface,
            "remediation_data_by_asset": remediation_data_by_asset,
        },
    )

    result = {
        "domain": recon_results.get("domain"),
        "assets": asset_rows,
        "risk_matrix": matrix,
        "dependencies": dependencies,
        "attack_surface": attack_surface,
        "dashboard": dashboard,
        "remediation_data_by_asset": remediation_data_by_asset,
    }
    if not include_roadmap:
        result["dashboard"]["remediation_roadmap"] = {}
    logger.info("Risk assessment complete for %s", recon_results.get("domain"))
    return result

