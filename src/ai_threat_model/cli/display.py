"""
Display utilities for threat models.

Provides helper functions for displaying threat models in human-readable format.
"""

from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..core.models import DataFlow, SystemModel, Threat, ThreatModel

console = Console()


def display_threat_model(threat_model: ThreatModel) -> None:
    """Display threat model in human-readable format."""
    _display_header(threat_model)
    _display_metadata(threat_model)
    _display_components(threat_model)
    _display_data_flows(threat_model)
    _display_threats(threat_model)
    _display_summary(threat_model)


def _display_header(threat_model: ThreatModel) -> None:
    """Display threat model header."""
    console.print()
    console.print(
        Panel(
            f"[bold cyan]{threat_model.system.name}[/bold cyan]",
            title="Threat Model",
            border_style="cyan",
        )
    )


def _display_metadata(threat_model: ThreatModel) -> None:
    """Display threat model metadata."""
    meta_table = Table.grid(padding=(0, 2))
    meta_table.add_row("[bold]System Type:[/bold]", threat_model.system.type.value)
    meta_table.add_row(
        "[bold]Framework:[/bold]", threat_model.system.threat_modeling_framework.value
    )
    if threat_model.metadata.author:
        meta_table.add_row("[bold]Author:[/bold]", threat_model.metadata.author)
    if threat_model.metadata.created:
        meta_table.add_row("[bold]Created:[/bold]", str(threat_model.metadata.created)[:19])
    if threat_model.metadata.updated:
        meta_table.add_row("[bold]Updated:[/bold]", str(threat_model.metadata.updated)[:19])
    console.print(meta_table)
    console.print()


def _display_components(threat_model: ThreatModel) -> None:
    """Display components table."""
    if not threat_model.system.components:
        return

    components_table = Table(title="Components", show_header=True, header_style="bold magenta")
    components_table.add_column("ID", style="cyan", width=20)
    components_table.add_column("Name", style="green", width=30)
    components_table.add_column("Type", style="yellow", width=20)
    components_table.add_column("Trust Level", style="blue", width=15)

    for component in threat_model.system.components:
        components_table.add_row(
            component.id,
            component.name,
            component.type.value,
            component.trust_level.value,
        )

    console.print(components_table)
    console.print()


def _display_data_flows(threat_model: ThreatModel) -> None:
    """Display data flows table."""
    if not threat_model.system.data_flows:
        return

    flows_table = Table(title="Data Flows", show_header=True, header_style="bold magenta")
    flows_table.add_column("From", style="cyan", width=20)
    flows_table.add_column("To", style="cyan", width=20)
    flows_table.add_column("Data Type", style="yellow", width=20)
    flows_table.add_column("Classification", style="blue", width=15)
    flows_table.add_column("Encrypted", style="green", width=10)

    for df in threat_model.system.data_flows:
        from_name, to_name = _get_data_flow_names(df, threat_model.system)
        flows_table.add_row(
            from_name,
            to_name,
            df.data_type or "N/A",
            df.classification.value,
            "✓" if df.encrypted else "✗",
        )

    console.print(flows_table)
    console.print()


def _display_threats(threat_model: ThreatModel) -> None:
    """Display threats table and detailed panels."""
    if not threat_model.threats:
        console.print("[yellow]No threats identified yet. Run 'analyze' to detect threats.[/yellow]")
        console.print()
        return

    _display_threats_table(threat_model)
    _display_threat_details(threat_model)


def _display_threats_table(threat_model: ThreatModel) -> None:
    """Display threats summary table."""
    threats_table = Table(title="Threats", show_header=True, header_style="bold red")
    threats_table.add_column("Category", style="magenta", width=15)
    threats_table.add_column("Title", style="green", width=40)
    threats_table.add_column("Severity", style="yellow", width=12)
    threats_table.add_column("Affected Items", style="cyan", width=50)

    for threat in threat_model.threats:
        severity_str = threat.severity.value if threat.severity else "N/A"
        affected_str = _format_affected_items(threat, threat_model.system)
        threats_table.add_row(threat.category, threat.title, severity_str, affected_str)

    console.print(threats_table)
    console.print()


def _display_threat_details(threat_model: ThreatModel) -> None:
    """Display detailed threat information panels."""
    for threat in threat_model.threats[:5]:  # Show first 5 in detail
        panel_content = _build_threat_panel_content(threat, threat_model.system)
        # Always show panel if there's any content, or if we have basic threat info
        if panel_content or threat.category or threat.title:
            severity_color = _get_severity_color(threat.severity.value if threat.severity else "medium")
            # If no content, at least show category and title
            if not panel_content:
                panel_content = [f"[bold]Category:[/bold] {threat.category}"]
            console.print(
                Panel(
                    "\n".join(panel_content),
                    title=f"{threat.category}: {threat.title}",
                    border_style=severity_color,
                )
            )

    if len(threat_model.threats) > 5:
        console.print(f"\n[dim]... and {len(threat_model.threats) - 5} more threats[/dim]")


def _display_summary(threat_model: ThreatModel) -> None:
    """Display summary information."""
    summary = Table.grid(padding=(0, 2))
    summary.add_row(
        "[bold]Summary:[/bold]",
        f"{len(threat_model.system.components)} components, "
        f"{len(threat_model.system.data_flows)} data flows, "
        f"{len(threat_model.threats)} threats",
    )
    console.print(summary)
    console.print()


def _get_data_flow_names(data_flow: DataFlow, system: SystemModel) -> tuple[str, str]:
    """Get component names for a data flow."""
    from_comp = system.get_component(data_flow.from_component)
    to_comp = system.get_component(data_flow.to_component)
    from_name = from_comp.name if from_comp else data_flow.from_component
    to_name = to_comp.name if to_comp else data_flow.to_component
    return from_name, to_name


def _format_affected_items(threat: Threat, system: SystemModel) -> str:
    """Format affected items list for display."""
    affected_items = []

    # Add affected components
    if threat.affected_components:
        comp_names = [
            system.get_component(cid).name if system.get_component(cid) else cid
            for cid in threat.affected_components
        ]
        affected_items.extend([f"Component: {name}" for name in comp_names])

    # Add affected data flows
    if threat.affected_data_flows:
        for df_id in threat.affected_data_flows:
            df_found = _find_data_flow_by_id(df_id, system)
            if df_found:
                from_name, to_name = _get_data_flow_names(df_found, system)
                affected_items.append(f"Flow: {from_name} → {to_name}")
            else:
                affected_items.append(f"Flow: {df_id}")

    # Format for display
    if affected_items:
        affected_str = ", ".join(affected_items[:3])
        if len(affected_items) > 3:
            affected_str += f" (+{len(affected_items) - 3} more)"
        return affected_str
    return "None specified"


def _find_data_flow_by_id(df_id: str, system: SystemModel) -> DataFlow | None:
    """Find data flow by ID string."""
    for df in system.data_flows:
        df_str = f"{df.from_component}->{df.to_component}"
        if df_id == df_str or df_id in df_str:
            return df
    return None


def _build_threat_panel_content(threat: Threat, system: SystemModel) -> List[str]:
    """Build content for threat detail panel."""
    content = []

    if threat.description:
        content.append(f"[bold]Description:[/bold] {threat.description}")

    # Affected Components
    if threat.affected_components:
        comp_names = [
            system.get_component(cid).name if system.get_component(cid) else cid
            for cid in threat.affected_components
        ]
        content.append(f"[bold]Affected Components:[/bold] {', '.join(comp_names)}")

    # Affected Data Flows
    if threat.affected_data_flows:
        flow_descriptions = []
        for df_id in threat.affected_data_flows:
            df_found = _find_data_flow_by_id(df_id, system)
            if df_found:
                from_name, to_name = _get_data_flow_names(df_found, system)
                flow_descriptions.append(f"{from_name} → {to_name}")
            else:
                flow_descriptions.append(df_id)
        content.append(f"[bold]Affected Data Flows:[/bold] {', '.join(flow_descriptions)}")

    # Attack Vectors
    if threat.attack_vectors:
        content.append(f"[bold]Attack Vectors:[/bold] {', '.join(threat.attack_vectors[:3])}")

    # Mitigations
    if threat.mitigations:
        mitigations_list = [f"- {m.description}" for m in threat.mitigations[:3]]
        content.append(
            f"[bold]Mitigations ({len(threat.mitigations)}):[/bold]\n" + "\n".join(mitigations_list)
        )

    return content


def _get_severity_color(severity: str) -> str:
    """Get color for severity level."""
    color_map = {
        "critical": "red",
        "high": "yellow",
        "medium": "blue",
        "low": "green",
    }
    return color_map.get(severity, "white")
