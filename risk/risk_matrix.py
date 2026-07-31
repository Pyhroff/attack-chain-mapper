"""Risk matrix and dashboard aggregation helpers."""

from __future__ import annotations

import logging

from .asset_profiler import generate_remediation_roadmap

logger = logging.getLogger(__name__)


def _zone_for_point(criticality: float, severity: float) -> str:
    if criticality >= 8 and severity >= 8:
        return "RED"
    if (criticality < 8 and severity >= 8) or (criticality >= 8 and severity < 8):
        return "YELLOW"
    return "GREEN"


def build_risk_matrix(assets_with_scores: list[dict]) -> dict:
    """Build a 2D matrix representation and an ASCII visualization."""
    points = []
    zones = {"RED": [], "YELLOW": [], "GREEN": []}
    buckets = {"low": [0, 0, 0], "medium": [0, 0, 0], "high": [0, 0, 0]}

    for asset in assets_with_scores:
        criticality = float(asset.get("criticality", 0))
        severity = float(asset.get("max_cvss", 0))
        zone = _zone_for_point(criticality, severity)
        point = {
            "asset": asset["asset"],
            "x_criticality": criticality,
            "y_severity": severity,
            "risk_score": asset.get("risk_score"),
            "risk_level": asset.get("risk_level"),
            "zone": zone,
        }
        points.append(point)
        zones[zone].append(asset["asset"])

        if severity >= 9:
            row = "high"
        elif severity >= 7:
            row = "medium"
        else:
            row = "low"

        if criticality <= 4:
            col = 0
        elif criticality <= 7:
            col = 1
        else:
            col = 2
        buckets[row][col] += 1

    ascii_output = "\n".join(
        [
            "RISK MATRIX: Asset Severity vs Criticality",
            "",
            f"Severity CRITICAL (9+)  [{buckets['high'][0]:<2}] [{buckets['high'][1]:<2}] [{buckets['high'][2]:<2}]",
            f"Severity HIGH (7-9)     [{buckets['medium'][0]:<2}] [{buckets['medium'][1]:<2}] [{buckets['medium'][2]:<2}]",
            f"Severity MEDIUM/LOW     [{buckets['low'][0]:<2}] [{buckets['low'][1]:<2}] [{buckets['low'][2]:<2}]",
            "                        2-4   5-7   8-10 (Criticality)",
        ]
    )

    matrix = {
        "points": points,
        "zones": zones,
        "quadrants": {
            "top_right": "CRITICAL: Patch immediately",
            "top_left": "HIGH: Schedule patching",
            "bottom_right": "HIGH CRITICALITY / LOW SEVERITY: Monitor",
            "bottom_left": "LOW: Defer with review",
        },
        "ascii": ascii_output,
    }
    logger.info("Risk matrix built with %d points", len(points))
    return matrix


def generate_risk_dashboard_data(recon_results: dict, vuln_results: dict, risk_bundle: dict) -> dict:
    """Aggregate all risk intelligence into a dashboard-ready structure."""
    assets = risk_bundle.get("assets", [])
    assets_sorted = sorted(assets, key=lambda item: item.get("risk_score", 0.0), reverse=True)
    top_five = assets_sorted[:5]
    remediation_data = risk_bundle.get("remediation_data_by_asset", {})
    roadmap = generate_remediation_roadmap(assets_sorted, remediation_data)

    dashboard = {
        "domain": recon_results.get("domain"),
        "summary": risk_bundle.get("attack_surface", {}),
        "risk_matrix": build_risk_matrix(assets_sorted),
        "remediation_roadmap": roadmap,
        "dependencies": risk_bundle.get("dependencies", {}),
        "asset_inventory": assets_sorted,
        "top_5_patch_assets": top_five,
        "vulnerability_results": vuln_results,
    }
    logger.info("Dashboard data assembled for %s", dashboard.get("domain"))
    return dashboard

