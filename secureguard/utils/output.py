"""Output formatting utilities."""

import json
from enum import Enum
from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from secureguard.utils.severity import Severity


class OutputFormat(str, Enum):
    """Output format options."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


def format_output(findings: List[Dict[str, Any]], format: OutputFormat) -> str:
    """Format findings in the specified output format.

    Args:
        findings: List of finding dictionaries
        format: Desired output format

    Returns:
        Formatted output string
    """
    if format == OutputFormat.JSON:
        return format_json(findings)
    elif format == OutputFormat.SARIF:
        return format_sarif(findings)
    else:
        return format_table(findings)


def format_json(findings: List[Dict[str, Any]]) -> str:
    """Format findings as JSON."""
    return json.dumps({
        "findings": findings,
        "total": len(findings),
        "summary": _get_summary(findings)
    }, indent=2)


def format_sarif(findings: List[Dict[str, Any]]) -> str:
    """Format findings as SARIF (Static Analysis Results Interchange Format)."""
    results = []

    for finding in findings:
        rule_id = finding.get("id", "UNKNOWN")
        message = finding.get("message", finding.get("description", "No description"))
        severity = finding.get("severity", "INFO")

        result = {
            "ruleId": rule_id,
            "level": _severity_to_sarif_level(severity),
            "message": {
                "text": message
            }
        }

        # Add location if available
        if "file" in finding:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding["file"]
                    }
                }
            }]

            if "line" in finding:
                result["locations"][0]["physicalLocation"]["region"] = {
                    "startLine": finding["line"]
                }

        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SecureGuard",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/yourusername/secureguard"
                }
            },
            "results": results
        }]
    }

    return json.dumps(sarif, indent=2)


def format_table(findings: List[Dict[str, Any]]) -> str:
    """Format findings as a rich table."""
    if not findings:
        return "[green]✓ No security issues found![/green]"

    console = Console()
    table = Table(title="Security Findings", show_header=True, header_style="bold magenta")

    table.add_column("Severity", style="bold", width=10)
    table.add_column("Type", width=15)
    table.add_column("ID/CVE", width=20)
    table.add_column("Description", width=50)
    table.add_column("Location", width=30)

    # Sort by severity
    sorted_findings = sorted(
        findings,
        key=lambda x: Severity(x.get("severity", "INFO")),
        reverse=True
    )

    for finding in sorted_findings:
        severity = finding.get("severity", "INFO")
        finding_type = finding.get("type", "UNKNOWN")
        finding_id = finding.get("id", finding.get("cve", "N/A"))
        description = finding.get("description", finding.get("message", "No description"))

        # Build location string
        location_parts = []
        if "package" in finding:
            location_parts.append(f"{finding['package']}")
            if "version" in finding:
                location_parts.append(f"@{finding['version']}")
        elif "file" in finding:
            location_parts.append(finding["file"])
            if "line" in finding:
                location_parts.append(f":{finding['line']}")
        elif "resource" in finding:
            location_parts.append(finding["resource"])

        location = "".join(location_parts) or "N/A"

        # Truncate description if too long
        if len(description) > 47:
            description = description[:44] + "..."

        # Color code severity
        severity_style = _get_severity_style(severity)

        table.add_row(
            f"[{severity_style}]{severity}[/{severity_style}]",
            finding_type,
            finding_id,
            description,
            location
        )

    # Capture table output
    with console.capture() as capture:
        console.print(table)
        console.print(f"\n[bold]Summary:[/bold] {_format_summary(_get_summary(findings))}")

    return capture.get()


def _get_summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Get summary count by severity."""
    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    for finding in findings:
        severity = finding.get("severity", "INFO")
        if severity in summary:
            summary[severity] += 1

    return summary


def _format_summary(summary: Dict[str, int]) -> str:
    """Format summary for display."""
    parts = []
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = summary.get(severity, 0)
        if count > 0:
            style = _get_severity_style(severity)
            parts.append(f"[{style}]{count} {severity}[/{style}]")

    return ", ".join(parts) if parts else "No issues"


def _get_severity_style(severity: str) -> str:
    """Get rich style for severity."""
    styles = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "cyan"
    }
    return styles.get(severity, "white")


def _severity_to_sarif_level(severity: str) -> str:
    """Convert severity to SARIF level."""
    mapping = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note"
    }
    return mapping.get(severity, "note")
