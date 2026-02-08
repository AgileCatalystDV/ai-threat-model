"""
CLI interface for AI Threat Model tool.

Provides command-line interface for threat modeling operations.
"""

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from ..core.models import (
    ComponentType,
    Metadata,
    SystemModel,
    SystemType,
    ThreatModel,
    ThreatModelingFramework,
)
from ..plugins import load_plugins
from ..plugins.registry import PluginRegistry
from .display import display_threat_model
from .reporting import generate_markdown_report, generate_mermaid_diagram

# Load plugins at startup
load_plugins()

app = typer.Typer(
    name="ai-threat-model",
    help="Open-source threat modeling tool for AI-native systems",
    add_completion=False,
)
console = Console()


@app.command()
def init(
    name: str = typer.Argument(..., help="Name of the threat model file (without extension)"),
    system_type: SystemType = typer.Option(
        SystemType.LLM_APP, "--type", "-t", help="System type"
    ),
    framework: ThreatModelingFramework = typer.Option(
        ThreatModelingFramework.OWASP_LLM_TOP10_2025,
        "--framework",
        "-f",
        help="Threat modeling framework",
    ),
    output_dir: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output directory (default: current directory)"
    ),
) -> None:
    """Initialize a new threat model."""
    output_path = output_dir or Path.cwd()
    file_path = output_path / f"{name}.tm.json"

    if file_path.exists():
        console.print(f"[red]Error: File {file_path} already exists[/red]")
        raise typer.Exit(1)

    # Create basic threat model
    threat_model = ThreatModel(
        metadata=Metadata(
            version="1.0.0",
            description=f"Threat model for {name}",
        ),
        system=SystemModel(
            name=name,
            type=system_type,
            threat_modeling_framework=framework,
        ),
    )

    threat_model.save(str(file_path))
    console.print(f"[green]✓[/green] Created threat model: {file_path}")
    console.print(f"  System type: {system_type.value}")
    console.print(f"  Framework: {framework.value}")


@app.command()
def analyze(
    file_path: Path = typer.Argument(..., help="Path to threat model file"),
) -> None:
    """Analyze threat model and detect threats."""
    if not file_path.exists():
        console.print(f"[red]Error: File {file_path} does not exist[/red]")
        raise typer.Exit(1)

    try:
        threat_model = ThreatModel.load(str(file_path))
    except Exception as e:
        console.print(f"[red]Error loading threat model: {e}[/red]")
        raise typer.Exit(1)

    # Get plugin for system type
    plugin = PluginRegistry.get_plugin(threat_model.system.type)
    if not plugin:
        console.print(
            f"[yellow]Warning: No plugin found for system type {threat_model.system.type.value}[/yellow]"
        )
        console.print("Threats will not be automatically detected.")
        raise typer.Exit(0)

    # Detect threats
    console.print(f"[cyan]Analyzing system: {threat_model.system.name}[/cyan]")
    threats = plugin.detect_threats(threat_model.system)

    # Update threat model
    threat_model.threats = threats
    threat_model.save(str(file_path))

    # Display results
    console.print(f"\n[green]✓[/green] Analysis complete")
    console.print(f"  Components analyzed: {len(threat_model.system.components)}")
    console.print(f"  Data flows analyzed: {len(threat_model.system.data_flows)}")
    console.print(f"  Threats detected: {len(threats)}")

    if threats:
        table = Table(title="Detected Threats")
        table.add_column("ID", style="cyan")
        table.add_column("Category", style="magenta")
        table.add_column("Title", style="green")
        table.add_column("Severity", style="yellow")

        for threat in threats[:10]:  # Show first 10
            table.add_row(
                threat.id[:8],
                threat.category,
                threat.title,
                threat.severity.value if threat.severity else "N/A",
            )

        console.print()
        console.print(table)

        if len(threats) > 10:
            console.print(f"\n... and {len(threats) - 10} more threats")


@app.command()
def report(
    file_path: Path = typer.Argument(..., help="Path to threat model file"),
    format: str = typer.Option("markdown", "--format", "-f", help="Report format (markdown, json)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file"),
) -> None:
    """Generate threat model report."""
    if not file_path.exists():
        console.print(f"[red]Error: File {file_path} does not exist[/red]")
        raise typer.Exit(1)

    try:
        threat_model = ThreatModel.load(str(file_path))
    except Exception as e:
        console.print(f"[red]Error loading threat model: {e}[/red]")
        raise typer.Exit(1)

    if format == "markdown":
        report_content = generate_markdown_report(threat_model)
    elif format == "json":
        report_content = json.dumps(
            threat_model.model_dump(mode="json", by_alias=True), indent=2
        )
    else:
        console.print(f"[red]Error: Unknown format {format}[/red]")
        raise typer.Exit(1)

    if output:
        output.write_text(report_content, encoding="utf-8")
        console.print(f"[green]✓[/green] Report saved to {output}")
    else:
        console.print(report_content)


@app.command()
def validate(
    file_path: Path = typer.Argument(..., help="Path to threat model file"),
) -> None:
    """Validate threat model file."""
    if not file_path.exists():
        console.print(f"[red]Error: File {file_path} does not exist[/red]")
        raise typer.Exit(1)

    try:
        threat_model = ThreatModel.load(str(file_path))
    except Exception as e:
        console.print(f"[red]Error loading threat model: {e}[/red]")
        raise typer.Exit(1)

    # Validate threat model
    errors = threat_model.validate()

    if errors:
        console.print("[red]✗ Validation failed[/red]")
        for error in errors:
            console.print(f"  [red]•[/red] {error}")
        raise typer.Exit(1)
    else:
        console.print("[green]✓[/green] Threat model is valid")


@app.command()
def view(
    file_path: Path = typer.Argument(..., help="Path to threat model file"),
) -> None:
    """Display threat model in human-readable format."""
    if not file_path.exists():
        console.print(f"[red]Error: File {file_path} does not exist[/red]")
        raise typer.Exit(1)

    try:
        threat_model = ThreatModel.load(str(file_path))
    except Exception as e:
        console.print(f"[red]Error loading threat model: {e}[/red]")
        raise typer.Exit(1)

    display_threat_model(threat_model)


@app.command()
def visualize(
    file_path: Path = typer.Argument(..., help="Path to threat model file"),
    format: str = typer.Option("mermaid", "--format", "-f", help="Visualization format (mermaid)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file"),
) -> None:
    """Generate visualization of threat model."""
    if not file_path.exists():
        console.print(f"[red]Error: File {file_path} does not exist[/red]")
        raise typer.Exit(1)

    try:
        threat_model = ThreatModel.load(str(file_path))
    except Exception as e:
        console.print(f"[red]Error loading threat model: {e}[/red]")
        raise typer.Exit(1)

    if format == "mermaid":
        diagram = generate_mermaid_diagram(threat_model)
    else:
        console.print(f"[red]Error: Unknown format {format}[/red]")
        raise typer.Exit(1)

    if output:
        output.write_text(diagram, encoding="utf-8")
        console.print(f"[green]✓[/green] Diagram saved to {output}")
    else:
        console.print(diagram)




def main() -> None:
    """Main entry point for CLI."""
    app()


if __name__ == "__main__":
    main()
