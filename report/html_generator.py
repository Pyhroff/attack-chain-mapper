"""HTML report and dashboard generators."""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Template


def generate_html_report(target: str, chains: list, output_path: str, verbose: bool = False) -> Path:
    if verbose:
        print(f"[report] Generating HTML report for {target}")

    html = [
        "<html><head><title>Attack Chain Report</title></head><body>",
        f"<h1>Attack Chain Report: {target}</h1>",
        "<ul>",
    ]
    for chain in chains:
        html.append(f"<li>{chain.get('description', 'No description')}</li>")
    html.extend(["</ul>", "</body></html>"])

    output = Path(output_path)
    output.write_text("\n".join(html), encoding="utf-8")
    return output


def generate_risk_dashboard(dashboard_data: dict, output_path: str) -> Path:
    template_path = Path(__file__).resolve().parent / "dashboard_template.html"
    template = Template(template_path.read_text(encoding="utf-8"))
    rendered = template.render(
        domain=dashboard_data.get("domain"),
        summary=dashboard_data.get("summary", {}),
        risk_matrix=dashboard_data.get("risk_matrix", {}),
        remediation_roadmap=dashboard_data.get("remediation_roadmap", {}),
        dependencies=dashboard_data.get("dependencies", {}),
        asset_inventory=dashboard_data.get("asset_inventory", []),
        top_5_patch_assets=dashboard_data.get("top_5_patch_assets", []),
        dashboard_json=json.dumps(dashboard_data, indent=2),
    )

    output = Path(output_path)
    output.write_text(rendered, encoding="utf-8")
    return output


def generate_remediation_roadmap_text(roadmap: dict, output_path: str) -> Path:
    lines = []
    for week_key, details in roadmap.items():
        title = details.get("label", week_key)
        lines.append(f"{week_key.upper()} ({title})")
        lines.append("-" * 72)
        for item in details.get("items", []):
            lines.append(f"Asset: {item.get('asset')}")
            lines.append(
                f"Current: {item.get('current_version')} -> Patch: {item.get('patch_version')}"
            )
            lines.append(
                f"Urgency: {item.get('urgency')} | Top CVE: {item.get('top_cve')} | CVSS: {item.get('top_cvss')}"
            )
            lines.append(
                f"Downtime: {item.get('downtime')} | Window: {item.get('maintenance_window')}"
            )
            lines.append("")
        lines.append("")

    output = Path(output_path)
    output.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
    return output
