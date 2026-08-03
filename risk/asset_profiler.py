"""Asset profiling, risk scoring, and prioritization helpers."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from config import ASSET_CRITICALITY_RULES, MAINTENANCE_WINDOWS

logger = logging.getLogger(__name__)


def _classify_service_type(asset_data: dict) -> str:
    labels = []
    for tech in asset_data.get("tech_stack", []):
        name = str(tech.get("technology", "")).lower()
        if name:
            labels.append(name)
    asset_name = str(asset_data.get("asset", "")).lower()
    labels.append(asset_name)
    blob = " ".join(labels)
    if "jenkins" in blob:
        return "jenkins"
    if "nginx" in blob:
        return "nginx"
    if "docker" in blob:
        return "docker"
    if "s3" in blob:
        return "s3"
    if "mail" in blob or "smtp" in blob:
        return "email"
    if "api" in blob:
        return "api"
    if "db" in blob or "database" in blob or "mysql" in blob or "postgres" in blob:
        return "database"
    return "generic"


def score_asset_criticality(asset_data: dict, overrides: dict | None = None) -> dict:
    """Score asset importance from type, exposure, and environment."""
    rules = dict(ASSET_CRITICALITY_RULES)
    if overrides:
        rules.update(overrides)

    asset = asset_data.get("asset", "unknown-asset")
    service_type = _classify_service_type(asset_data)
    is_external = bool(asset_data.get("is_external", True))
    environment = str(asset_data.get("environment", "prod")).lower()
    is_customer_facing = bool(asset_data.get("is_customer_facing", False))

    base = 5
    reasoning = [f"service type: {service_type}"]

    for key, score in rules.items():
        if key in service_type or key in str(asset).lower():
            base = max(base, int(score))
            reasoning.append(f"rule match: {key}={score}")

    if service_type == "api" and is_customer_facing:
        base = max(base, 8)
        reasoning.append("customer-facing API")
    if service_type == "jenkins" and is_external:
        base = max(base, 9)
        reasoning.append("external-facing CI/CD")
    if service_type == "database":
        base = max(base, 9)
        reasoning.append("business-critical data plane")
    if service_type == "email":
        base = max(base, 10)
        reasoning.append("business continuity service")
    if environment in {"test", "staging", "dev"}:
        base = min(base, 4 if environment in {"test", "staging"} else 2)
        reasoning.append(f"non-production environment: {environment}")
    if not is_external:
        base = max(1, base - 1)
        reasoning.append("internal-only exposure")

    criticality = max(1, min(10, int(base)))
    logger.info("Asset criticality score for %s: %s/10 (%s)", asset, criticality, "; ".join(reasoning))
    return {"asset": asset, "criticality": criticality, "reasoning": ", ".join(reasoning), "service_type": service_type}


def calculate_asset_risk_score(asset_criticality: dict, vulnerabilities: list[dict]) -> dict:
    """Compute composite risk score from criticality, severity, and vulnerability volume."""
    asset = asset_criticality["asset"]
    criticality_score = float(asset_criticality["criticality"])
    cve_count = len(vulnerabilities)
    max_cvss = max((float(item.get("cvss", 0.0)) for item in vulnerabilities), default=0.0)

    # Transparent weighting:
    # 0.4 criticality (business impact) + 0.4 max CVSS (technical severity) + 0.2 count (breadth of exposure)
    risk_score = (criticality_score * 0.4) + (max_cvss * 0.4) + (cve_count * 0.2)
    capped_score = min(10.0, risk_score)

    if capped_score >= 8.0:
        risk_level = "CRITICAL"
    elif capped_score >= 6.0:
        risk_level = "HIGH"
    elif capped_score >= 4.0:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    logger.info(
        "Risk score for %s: %.2f (%s) [criticality=%.1f, max_cvss=%.1f, cve_count=%d]",
        asset,
        capped_score,
        risk_level,
        criticality_score,
        max_cvss,
        cve_count,
    )
    return {
        "asset": asset,
        "risk_score": round(capped_score, 2),
        "risk_level": risk_level,
        "max_cvss": round(max_cvss, 2),
        "cve_count": cve_count,
    }


def _estimate_downtime(service_type: str) -> str:
    if service_type == "jenkins":
        return "30 minutes"
    if service_type in {"database", "email"}:
        return "2 hours"
    if service_type in {"nginx", "api"}:
        return "5-15 minutes"
    if service_type == "s3":
        return "No downtime (policy/config change)"
    return "30-60 minutes"


def generate_remediation_roadmap(assets_with_risk: list[dict], remediation_data: dict) -> dict:
    """Create week-based remediation plan grouped by risk level."""
    roadmap = {
        "week_1_2": {"label": "CRITICAL - Immediate Action Required", "items": []},
        "week_3_4": {"label": "HIGH - Schedule Within 2 Weeks", "items": []},
        "week_5_6": {"label": "MEDIUM - Plan and Execute", "items": []},
    }

    for asset in assets_with_risk:
        asset_name = asset["asset"]
        risk_score = float(asset["risk_score"])
        service_type = asset.get("service_type", "generic")
        cves = remediation_data.get(asset_name, [])
        top_cve = cves[0] if cves else {}
        patch_version = top_cve.get("patch_version") or "Not available"
        current_version = top_cve.get("version") or "Unknown"
        downtime = _estimate_downtime(service_type)

        if risk_score > 8.0:
            bucket = "week_1_2"
            maintenance = MAINTENANCE_WINDOWS.get("critical", "Immediate emergency patch window")
        elif risk_score >= 6.0:
            bucket = "week_3_4"
            maintenance = MAINTENANCE_WINDOWS.get("high", "Next available maintenance window")
        else:
            bucket = "week_5_6"
            maintenance = MAINTENANCE_WINDOWS.get("medium", "Planned maintenance cycle")

        roadmap[bucket]["items"].append(
            {
                "asset": asset_name,
                "service_type": service_type,
                "current_version": current_version,
                "patch_version": patch_version,
                "urgency": asset["risk_level"],
                "top_cve": top_cve.get("cve_id"),
                "top_cvss": top_cve.get("cvss"),
                "downtime": downtime,
                "maintenance_window": maintenance,
            }
        )

    return roadmap


def map_asset_dependencies(recon_data: dict) -> dict:
    """Infer downstream dependencies from asset type and role."""
    dependencies = {}
    fingerprints = recon_data.get("fingerprints", {})
    for asset in fingerprints.keys():
        blob = asset.lower()
        downstream = []
        impact = "MEDIUM"
        if "jenkins" in blob:
            downstream = [
                "docker-registry.example.com",
                "aws-account (via CI/CD keys)",
                "github-repo (via access tokens)",
            ]
            impact = "CRITICAL (controls deployment pipeline)"
        elif "api" in blob:
            downstream = ["backend-database", "customer-mobile-apps", "partner-integrations"]
            impact = "HIGH (customer-facing transaction path)"
        elif "db" in blob or "database" in blob:
            downstream = ["reporting-systems", "analytics-platform", "core business apps"]
            impact = "CRITICAL (data integrity and availability)"
        elif "s3" in blob:
            downstream = ["static-web-content", "backup-retrieval-jobs"]
            impact = "MEDIUM (data exposure and integrity risk)"
        else:
            downstream = ["adjacent services discovered in recon scope"]
            impact = "MEDIUM (lateral movement potential)"

        dependencies[asset] = {
            "criticality": impact.split(" ")[0],
            "downstream_impact": downstream,
            "impact_level": impact,
        }
    logger.info("Dependency map built for %d assets", len(dependencies))
    return dependencies


def assess_attack_surface(asset_list: list[dict], recon_results: dict | None = None) -> dict:
    """Summarize attack surface exposure and vulnerability coverage."""
    total_assets = len(asset_list)
    exposed_services = 0
    vulnerable_assets = 0
    critical_vulns = 0
    total_vuln_instances = 0

    for asset in asset_list:
        if asset.get("has_http") or asset.get("has_https"):
            exposed_services += 1
        cves = asset.get("vulnerabilities", [])
        if cves:
            vulnerable_assets += 1
            total_vuln_instances += len(cves)
        critical_vulns += sum(1 for cve in cves if float(cve.get("cvss", 0.0)) >= 8.0)

    coverage = f"{(vulnerable_assets / total_assets * 100):.0f}% of assets have vulnerabilities" if total_assets else "0% of assets have vulnerabilities"

    baseline_assets = 0
    if recon_results:
        baseline_assets = int(recon_results.get("previous_total_assets", 0))
    if baseline_assets > 0:
        delta = total_assets - baseline_assets
        pct = (delta / baseline_assets) * 100
        if pct > 1:
            trend = f"GROWING ({pct:.0f}% increase vs previous snapshot)"
        elif pct < -1:
            trend = f"SHRINKING ({abs(pct):.0f}% decrease vs previous snapshot)"
        else:
            trend = "STABLE"
    else:
        trend = "STABLE (no prior baseline available)"

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "total_assets": total_assets,
        "exposed_services": exposed_services,
        "vulnerable_assets": vulnerable_assets,
        "critical_vulns": critical_vulns,
        "total_vulnerabilities": total_vuln_instances,
        "attack_surface_trend": trend,
        "coverage": coverage,
    }
    logger.info("Attack surface summary: %s", summary)
    return summary
