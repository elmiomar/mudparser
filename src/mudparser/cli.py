"""
Command-line interface for MudParser.

Provides commands for parsing, validating, and exporting MUD profiles.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.tree import Tree

from mudparser import __version__
from mudparser.exceptions import (
    MUDFileNotFoundError,
    MUDNetworkError,
    MUDParserError,
    MUDSchemaError,
    MUDValidationError,
)
from mudparser.exporters import ExportFormat
from mudparser.parser import MUDParser
from mudparser.validator import MUDValidator, ValidationSeverity

app = typer.Typer(
    name="mudparser",
    help="Parse, validate, and export MUD (Manufacturer Usage Description) profiles.",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        rprint(f"[bold blue]mudparser[/bold blue] version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version", "-v",
            callback=version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = None,
) -> None:
    """
    MudParser - Parse, validate, and export MUD profiles.

    MUD (Manufacturer Usage Description) profiles define network access
    policies for IoT devices as specified in RFC 8520.
    """
    pass


@app.command()
def validate(
    file_path: Annotated[
        Path,
        typer.Argument(
            help="Path to the MUD profile JSON file.",
            exists=True,
            readable=True,
        ),
    ],
    strict: Annotated[
        bool,
        typer.Option("--strict", "-s", help="Treat warnings as errors."),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output results as JSON."),
    ] = False,
) -> None:
    """
    Validate a MUD profile for RFC 8520 compliance.

    Checks for structural issues, cross-reference problems, and best practices.
    """
    try:
        parser = MUDParser.from_file(file_path)
        validator = MUDValidator(strict=strict)
        result = validator.validate(parser.profile)

        if json_output:
            rprint(json.dumps(result.to_dict(), indent=2))
            raise typer.Exit(0 if result.is_valid else 1)

        if result.is_valid:
            console.print(
                Panel(
                    f"[green]Profile is valid[/green]\n"
                    f"Errors: {result.error_count} | Warnings: {result.warning_count}",
                    title="Validation Result",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel(
                    f"[red]Profile validation failed[/red]\n"
                    f"Errors: {result.error_count} | Warnings: {result.warning_count}",
                    title="Validation Result",
                    border_style="red",
                )
            )

        if result.issues:
            table = Table(title="Validation Issues")
            table.add_column("Severity", style="bold")
            table.add_column("Message")
            table.add_column("Path", style="dim")

            for issue in result.issues:
                severity_color = {
                    ValidationSeverity.ERROR: "red",
                    ValidationSeverity.WARNING: "yellow",
                    ValidationSeverity.INFO: "blue",
                }.get(issue.severity, "white")

                table.add_row(
                    f"[{severity_color}]{issue.severity.value.upper()}[/{severity_color}]",
                    issue.message,
                    issue.path or "-",
                )

            console.print(table)

        raise typer.Exit(0 if result.is_valid else 1)

    except MUDParserError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def info(
    file_path: Annotated[
        Path,
        typer.Argument(
            help="Path to the MUD profile JSON file.",
            exists=True,
            readable=True,
        ),
    ],
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output as JSON."),
    ] = False,
) -> None:
    """
    Display information about a MUD profile.

    Shows device metadata, policy summary, and referenced resources.
    """
    try:
        parser = MUDParser.from_file(file_path)
        summary = parser.get_summary()

        if json_output:
            rprint(json.dumps(summary, indent=2, default=str))
            raise typer.Exit()

        # Header panel
        console.print(
            Panel(
                f"[bold]{summary['systeminfo'] or 'Unknown Device'}[/bold]\n"
                f"URL: {summary['url']}",
                title="MUD Profile",
                border_style="blue",
            )
        )

        # Metadata table
        table = Table(title="Profile Metadata")
        table.add_column("Property", style="cyan")
        table.add_column("Value")

        table.add_row("MUD Version", str(summary["version"]))
        table.add_row("Last Update", summary["last_update"])
        table.add_row("Cache Validity", f"{summary['cache_validity_hours']} hours")
        table.add_row("Supported", "Yes" if summary["is_supported"] else "No")
        if summary["manufacturer"]:
            table.add_row("Manufacturer", summary["manufacturer"])
        if summary["model"]:
            table.add_row("Model", summary["model"])

        console.print(table)

        # Rules summary
        rules_table = Table(title="Access Control Summary")
        rules_table.add_column("Direction", style="cyan")
        rules_table.add_column("ACLs")
        rules_table.add_column("Rules")

        rules_table.add_row(
            "From Device (Outbound)",
            str(summary["from_device_acls"]),
            str(summary["from_device_rules"]),
        )
        rules_table.add_row(
            "To Device (Inbound)",
            str(summary["to_device_acls"]),
            str(summary["to_device_rules"]),
        )
        rules_table.add_row(
            "[bold]Total[/bold]",
            str(summary["from_device_acls"] + summary["to_device_acls"]),
            str(summary["total_rules"]),
        )

        console.print(rules_table)

        # DNS names
        if summary["dns_names"]:
            console.print("\n[bold]Referenced DNS Names:[/bold]")
            for name in sorted(summary["dns_names"]):
                console.print(f"  - {name}")

        # Ports
        if summary["ports"]["tcp"] or summary["ports"]["udp"]:
            console.print("\n[bold]Referenced Ports:[/bold]")
            if summary["ports"]["tcp"]:
                console.print(f"  TCP: {', '.join(map(str, sorted(summary['ports']['tcp'])))}")
            if summary["ports"]["udp"]:
                console.print(f"  UDP: {', '.join(map(str, sorted(summary['ports']['udp'])))}")

    except MUDParserError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def rules(
    file_path: Annotated[
        Path,
        typer.Argument(
            help="Path to the MUD profile JSON file.",
            exists=True,
            readable=True,
        ),
    ],
) -> None:
    """
    Display all rules in a MUD profile in human-readable format.
    """
    try:
        parser = MUDParser.from_file(file_path)
        parser.print_rules()

    except MUDParserError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def export(
    file_path: Annotated[
        Path,
        typer.Argument(
            help="Path to the MUD profile JSON file.",
            exists=True,
            readable=True,
        ),
    ],
    format: Annotated[
        str,
        typer.Option(
            "--format", "-f",
            help="Export format (json, yaml, iptables, nftables, cisco, pfsense).",
        ),
    ] = "json",
    device_ip: Annotated[
        Optional[str],
        typer.Option(
            "--device-ip", "-d",
            help="Device IP address (required for firewall formats).",
        ),
    ] = None,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output", "-o",
            help="Output file path (stdout if not specified).",
        ),
    ] = None,
) -> None:
    """
    Export a MUD profile to various formats.

    Supports JSON, YAML, and firewall rule formats (iptables, nftables,
    Cisco ACL, pfSense).
    """
    try:
        # Validate format
        try:
            export_format = ExportFormat(format.lower())
        except ValueError:
            valid_formats = ", ".join(f.value for f in ExportFormat)
            console.print(f"[red]Error:[/red] Invalid format '{format}'")
            console.print(f"Valid formats: {valid_formats}")
            raise typer.Exit(1)

        # Check device_ip requirement
        firewall_formats = {
            ExportFormat.IPTABLES,
            ExportFormat.NFTABLES,
            ExportFormat.PFSENSE,
        }
        if export_format in firewall_formats and not device_ip:
            console.print(
                f"[red]Error:[/red] --device-ip is required for {format} format"
            )
            raise typer.Exit(1)

        parser = MUDParser.from_file(file_path)

        # Build export kwargs
        kwargs: dict = {}
        if device_ip:
            kwargs["device_ip"] = device_ip

        result = parser.export.export(export_format, **kwargs)

        if output:
            output.write_text(result)
            console.print(f"[green]Exported to {output}[/green]")
        else:
            # Syntax highlight for certain formats
            if export_format == ExportFormat.JSON:
                syntax = Syntax(result, "json", theme="monokai")
                console.print(syntax)
            elif export_format == ExportFormat.YAML:
                syntax = Syntax(result, "yaml", theme="monokai")
                console.print(syntax)
            else:
                console.print(result)

    except MUDParserError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def fetch(
    url: Annotated[
        str,
        typer.Argument(help="URL of the MUD profile to fetch."),
    ],
    validate_profile: Annotated[
        bool,
        typer.Option("--validate", "-v", help="Validate the fetched profile."),
    ] = False,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output", "-o",
            help="Save the fetched profile to a file.",
        ),
    ] = None,
) -> None:
    """
    Fetch a MUD profile from a URL.

    Downloads and optionally validates a MUD profile from a remote server.
    """
    try:
        with console.status(f"Fetching {url}..."):
            parser = MUDParser.from_url(url)

        console.print(f"[green]Successfully fetched profile from {url}[/green]")

        if validate_profile:
            validator = MUDValidator()
            result = validator.validate(parser.profile)

            if result.is_valid:
                console.print("[green]Profile is valid[/green]")
            else:
                console.print(
                    f"[red]Validation failed with {result.error_count} errors[/red]"
                )
                for issue in result.errors:
                    console.print(f"  - {issue.message}")

        if output:
            output.write_text(parser.to_json())
            console.print(f"[green]Saved to {output}[/green]")
        else:
            summary = parser.get_summary()
            console.print(f"\nDevice: {summary['systeminfo']}")
            console.print(f"Rules: {summary['total_rules']}")

    except MUDNetworkError as e:
        console.print(f"[red]Network error:[/red] {e.message}")
        if e.status_code:
            console.print(f"HTTP status: {e.status_code}")
        raise typer.Exit(1)
    except MUDParserError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def diff(
    file1: Annotated[
        Path,
        typer.Argument(
            help="First MUD profile file.",
            exists=True,
            readable=True,
        ),
    ],
    file2: Annotated[
        Path,
        typer.Argument(
            help="Second MUD profile file.",
            exists=True,
            readable=True,
        ),
    ],
) -> None:
    """
    Compare two MUD profiles and show differences.
    """
    try:
        parser1 = MUDParser.from_file(file1)
        parser2 = MUDParser.from_file(file2)

        console.print(
            Panel(
                f"[bold]Comparing MUD Profiles[/bold]\n"
                f"File 1: {file1}\n"
                f"File 2: {file2}",
                border_style="blue",
            )
        )

        # Compare metadata
        table = Table(title="Metadata Comparison")
        table.add_column("Property", style="cyan")
        table.add_column("File 1")
        table.add_column("File 2")
        table.add_column("Match")

        def compare_value(v1: str, v2: str) -> str:
            return "[green]Yes[/green]" if v1 == v2 else "[red]No[/red]"

        mud1, mud2 = parser1.mud, parser2.mud

        table.add_row(
            "System Info",
            mud1.systeminfo or "-",
            mud2.systeminfo or "-",
            compare_value(mud1.systeminfo or "", mud2.systeminfo or ""),
        )
        table.add_row(
            "MUD URL",
            str(mud1.mud_url),
            str(mud2.mud_url),
            compare_value(str(mud1.mud_url), str(mud2.mud_url)),
        )
        table.add_row(
            "Version",
            str(mud1.mud_version),
            str(mud2.mud_version),
            compare_value(str(mud1.mud_version), str(mud2.mud_version)),
        )

        console.print(table)

        # Compare rules
        rules_table = Table(title="Rules Comparison")
        rules_table.add_column("Metric", style="cyan")
        rules_table.add_column("File 1")
        rules_table.add_column("File 2")
        rules_table.add_column("Diff")

        s1 = parser1.get_summary()
        s2 = parser2.get_summary()

        def diff_value(v1: int, v2: int) -> str:
            d = v2 - v1
            if d > 0:
                return f"[green]+{d}[/green]"
            elif d < 0:
                return f"[red]{d}[/red]"
            return "[dim]0[/dim]"

        rules_table.add_row(
            "Total Rules",
            str(s1["total_rules"]),
            str(s2["total_rules"]),
            diff_value(s1["total_rules"], s2["total_rules"]),
        )
        rules_table.add_row(
            "From-Device Rules",
            str(s1["from_device_rules"]),
            str(s2["from_device_rules"]),
            diff_value(s1["from_device_rules"], s2["from_device_rules"]),
        )
        rules_table.add_row(
            "To-Device Rules",
            str(s1["to_device_rules"]),
            str(s2["to_device_rules"]),
            diff_value(s1["to_device_rules"], s2["to_device_rules"]),
        )

        console.print(rules_table)

        # DNS name differences
        dns1 = set(s1["dns_names"])
        dns2 = set(s2["dns_names"])

        added_dns = dns2 - dns1
        removed_dns = dns1 - dns2

        if added_dns or removed_dns:
            console.print("\n[bold]DNS Name Changes:[/bold]")
            for name in sorted(added_dns):
                console.print(f"  [green]+ {name}[/green]")
            for name in sorted(removed_dns):
                console.print(f"  [red]- {name}[/red]")

    except MUDParserError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def demo() -> None:
    """
    Launch the interactive Streamlit demo application.

    Requires the 'demo' optional dependencies to be installed:
        pip install mudparser[demo]
    """
    try:
        import subprocess
        import shutil

        # Check if streamlit is available
        if not shutil.which("streamlit"):
            console.print(
                "[red]Error:[/red] Streamlit is not installed.\n"
                "Install demo dependencies with: pip install mudparser[demo]"
            )
            raise typer.Exit(1)

        # Find the demo app
        # __file__ = src/mudparser/cli.py
        # Go up to project root: src/mudparser -> src -> project_root
        demo_path = Path(__file__).parent.parent.parent / "demo" / "streamlit_app.py"

        if not demo_path.exists():
            console.print(f"[red]Error:[/red] Demo app not found at {demo_path}")
            raise typer.Exit(1)

        console.print("[blue]Launching Streamlit demo...[/blue]")
        subprocess.run(["streamlit", "run", str(demo_path)])

    except ImportError:
        console.print(
            "[red]Error:[/red] Demo dependencies not installed.\n"
            "Install with: pip install mudparser[demo]"
        )
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
