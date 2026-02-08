"""
Reporting utilities for threat models.

Provides functions for generating reports and visualizations.
"""

from ..core.models import ThreatModel


def generate_markdown_report(threat_model: ThreatModel) -> str:
    """Generate markdown report from threat model."""
    lines = [
        f"# Threat Model: {threat_model.system.name}",
        "",
        f"**System Type:** {threat_model.system.type.value}",
        f"**Framework:** {threat_model.system.threat_modeling_framework.value}",
        f"**Created:** {threat_model.metadata.created}",
        f"**Updated:** {threat_model.metadata.updated}",
        "",
        "## Components",
        "",
    ]

    for component in threat_model.system.components:
        lines.append(f"- **{component.name}** ({component.type.value})")
        if component.description:
            lines.append(f"  - {component.description}")

    lines.extend(["", "## Threats", ""])

    if not threat_model.threats:
        lines.append("*No threats identified yet.*")
    else:
        for threat in threat_model.threats:
            lines.append(f"### {threat.category}: {threat.title}")
            if threat.description:
                lines.append(f"{threat.description}")
            if threat.severity:
                lines.append(f"**Severity:** {threat.severity.value}")
            lines.append("")

    return "\n".join(lines)


def generate_mermaid_diagram(threat_model: ThreatModel) -> str:
    """Generate Mermaid diagram from threat model."""
    lines = ["graph TD"]

    # Add components as nodes
    for component in threat_model.system.components:
        node_id = component.id.replace("-", "_").replace(" ", "_")
        label = component.name.replace('"', "'")
        lines.append(f'    {node_id}["{label}"]')

    # Add data flows as edges
    for df in threat_model.system.data_flows:
        from_id = df.from_component.replace("-", "_").replace(" ", "_")
        to_id = df.to_component.replace("-", "_").replace(" ", "_")
        lines.append(f"    {from_id} --> {to_id}")

    return "\n".join(lines)
