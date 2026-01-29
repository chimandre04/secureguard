"""CLI commands for compliance automation."""

import click
import json
from pathlib import Path
from typing import Optional

from secureguard.compliance.core.framework import FrameworkLoader
from secureguard.compliance.core.mapper import ComplianceMapper
from secureguard.compliance.core.gap_analyzer import GapAnalyzer
from secureguard.compliance.reports.json_generator import JSONReportGenerator
from secureguard.compliance.reports.html_generator import HTMLReportGenerator


@click.group(name="compliance")
def compliance_group():
    """Compliance automation and audit commands."""
    pass


@compliance_group.command(name="frameworks")
def list_frameworks():
    """List all available compliance frameworks."""
    loader = FrameworkLoader()
    frameworks = loader.list_available_frameworks()

    if not frameworks:
        click.echo("No frameworks available.")
        return

    click.echo("Available compliance frameworks:")
    click.echo()

    for fw_id in frameworks:
        try:
            framework = loader.load(fw_id)
            control_count = framework.get_control_count()
            click.echo(f"  {fw_id:15} - {framework.name} (v{framework.version}) - {control_count} controls")
        except Exception as e:
            click.echo(f"  {fw_id:15} - Error loading framework: {e}")

    click.echo()


@compliance_group.command(name="show-framework")
@click.option("--id", "-i", "framework_id", required=True, help="Framework ID")
def show_framework(framework_id: str):
    """Show detailed information about a compliance framework."""
    try:
        loader = FrameworkLoader()
        framework = loader.load(framework_id)

        click.echo(f"\n{framework.name} (v{framework.version})")
        click.echo("=" * 80)
        click.echo(f"\nDescription: {framework.description}")
        click.echo(f"\nTotal Controls: {framework.get_control_count()}")
        click.echo(f"\nDomains: {len(framework.domains)}")

        for domain in framework.domains:
            click.echo(f"\n  {domain.id} - {domain.name}")
            click.echo(f"  Controls: {domain.get_control_count()}")

            for control in domain.controls[:3]:  # Show first 3 controls
                click.echo(f"    - {control.id}: {control.title} ({control.severity})")

            if domain.get_control_count() > 3:
                click.echo(f"    ... and {domain.get_control_count() - 3} more")

        click.echo()

    except FileNotFoundError:
        click.echo(f"Error: Framework '{framework_id}' not found.", err=True)
        return 1
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        return 1


@compliance_group.command(name="scan")
@click.option("--framework", "-f", required=True, help="Compliance framework (soc2, nist_csf, pci_dss, iso27001)")
@click.option("--findings", "-F", type=click.Path(exists=True), required=True, help="Path to findings JSON file")
@click.option("--format", "-o", type=click.Choice(["html", "json"]), default="html", help="Output format")
@click.option("--output", "-O", type=click.Path(), help="Output file path")
def scan_compliance(framework: str, findings: str, format: str, output: Optional[str]):
    """Run compliance assessment against security findings.

    Analyze security findings from SecureGuard scanners and generate
    a compliance report showing gaps and recommendations.

    Example:
        secureguard compliance scan --framework soc2 --findings findings.json --format html --output report.html
    """
    try:
        # Load framework
        click.echo(f"Loading framework: {framework}...")
        loader = FrameworkLoader()
        fw = loader.load(framework)

        # Load findings
        click.echo(f"Loading findings from: {findings}...")
        with open(findings, "r") as f:
            findings_data = json.load(f)

        # Handle different finding formats
        if isinstance(findings_data, dict):
            # If it's a dict with a 'findings' key
            findings_list = findings_data.get("findings", [findings_data])
        elif isinstance(findings_data, list):
            findings_list = findings_data
        else:
            findings_list = [findings_data]

        click.echo(f"Analyzing {len(findings_list)} findings...")

        # Create mapper and analyzer
        mapper = ComplianceMapper(fw)
        analyzer = GapAnalyzer(fw, mapper)

        # Perform gap analysis
        click.echo("Performing gap analysis...")
        report = analyzer.analyze(findings_list)

        # Generate report
        click.echo(f"Generating {format.upper()} report...")

        if format == "json":
            generator = JSONReportGenerator()
            output_content = generator.generate(report)
        elif format == "html":
            generator = HTMLReportGenerator()
            output_content = generator.generate(report)
        else:
            click.echo(f"Unsupported format: {format}", err=True)
            return 1

        # Output report
        if output:
            output_path = Path(output)
            output_path.write_text(output_content)
            click.echo(f"\n✓ Report saved to: {output}")
        else:
            click.echo("\n" + output_content)

        # Print summary
        click.echo("\n" + "=" * 80)
        click.echo("COMPLIANCE SUMMARY")
        click.echo("=" * 80)
        click.echo(f"Framework:        {fw.name}")
        click.echo(f"Overall Score:    {report.overall_score:.2f}%")
        click.echo(f"Overall Status:   {report.overall_status.upper()}")
        click.echo(f"Total Controls:   {len(report.gaps)}")
        click.echo(f"  Compliant:      {report.get_compliant_count()}")
        click.echo(f"  Partial:        {report.get_partial_count()}")
        click.echo(f"  Non-Compliant:  {report.get_non_compliant_count()}")
        click.echo(f"  Not Tested:     {report.get_not_tested_count()}")
        click.echo("=" * 80 + "\n")

        # Exit with error code if not compliant
        if report.overall_status == "non_compliant":
            return 1

    except FileNotFoundError as e:
        click.echo(f"Error: File not found - {e}", err=True)
        return 1
    except json.JSONDecodeError as e:
        click.echo(f"Error: Invalid JSON in findings file - {e}", err=True)
        return 1
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        import traceback
        traceback.print_exc()
        return 1


@compliance_group.command(name="gaps")
@click.option("--framework", "-f", required=True, help="Compliance framework")
@click.option("--findings", "-F", type=click.Path(exists=True), required=True, help="Path to findings JSON file")
@click.option("--format", "-o", type=click.Choice(["table", "json"]), default="table", help="Output format")
@click.option("--severity", "-s", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]), help="Filter by severity")
@click.option("--status", type=click.Choice(["compliant", "partial", "non_compliant", "not_tested"]), help="Filter by status")
def analyze_gaps(framework: str, findings: str, format: str, severity: Optional[str], status: Optional[str]):
    """Analyze compliance gaps and show detailed results.

    Example:
        secureguard compliance gaps --framework soc2 --findings findings.json --status non_compliant
    """
    try:
        # Load framework
        loader = FrameworkLoader()
        fw = loader.load(framework)

        # Load findings
        with open(findings, "r") as f:
            findings_data = json.load(f)

        if isinstance(findings_data, dict):
            findings_list = findings_data.get("findings", [findings_data])
        elif isinstance(findings_data, list):
            findings_list = findings_data
        else:
            findings_list = [findings_data]

        # Analyze
        mapper = ComplianceMapper(fw)
        analyzer = GapAnalyzer(fw, mapper)
        report = analyzer.analyze(findings_list)

        # Filter gaps
        filtered_gaps = report.gaps

        if status:
            filtered_gaps = [g for g in filtered_gaps if g.status == status]

        if severity:
            from secureguard.utils.severity import Severity
            sev = Severity[severity.upper()]
            filtered_gaps = [g for g in filtered_gaps if g.risk_level == sev]

        # Output
        if format == "json":
            gaps_data = [gap.to_dict() for gap in filtered_gaps]
            click.echo(json.dumps(gaps_data, indent=2))
        else:
            # Table format
            click.echo("\n" + "=" * 100)
            click.echo(f"{'Control ID':<15} {'Title':<40} {'Status':<15} {'Coverage':<10} {'Findings':<10}")
            click.echo("=" * 100)

            for gap in filtered_gaps:
                click.echo(
                    f"{gap.control.id:<15} "
                    f"{gap.control.title[:38]:<40} "
                    f"{gap.status:<15} "
                    f"{gap.coverage:>6.1f}%   "
                    f"{len(gap.findings):>5}"
                )

            click.echo("=" * 100)
            click.echo(f"\nTotal gaps: {len(filtered_gaps)}\n")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        return 1


@compliance_group.command(name="map")
@click.option("--findings", "-F", type=click.Path(exists=True), required=True, help="Path to findings JSON file")
@click.option("--framework", "-f", required=True, help="Compliance framework")
def map_findings(findings: str, framework: str):
    """Map security findings to compliance controls.

    Example:
        secureguard compliance map --findings findings.json --framework soc2
    """
    try:
        # Load framework
        loader = FrameworkLoader()
        fw = loader.load(framework)

        # Load findings
        with open(findings, "r") as f:
            findings_data = json.load(f)

        if isinstance(findings_data, dict):
            findings_list = findings_data.get("findings", [findings_data])
        elif isinstance(findings_data, list):
            findings_list = findings_data
        else:
            findings_list = [findings_data]

        # Map findings
        mapper = ComplianceMapper(fw)
        mapped = mapper.map_findings(findings_list)

        # Get coverage stats
        coverage = mapper.get_mapping_coverage(findings_list)

        # Output results
        click.echo("\n" + "=" * 80)
        click.echo("FINDING TO CONTROL MAPPING")
        click.echo("=" * 80)

        for control_id, control_findings in sorted(mapped.items()):
            click.echo(f"\n{control_id}: {len(control_findings)} findings")
            for finding in control_findings[:3]:  # Show first 3
                check_id = mapper._extract_check_id(finding)
                severity = finding.get('severity', 'N/A')
                click.echo(f"  - [{severity}] {check_id}: {finding.get('description', 'No description')[:60]}")

            if len(control_findings) > 3:
                click.echo(f"  ... and {len(control_findings) - 3} more findings")

        # Print coverage stats
        click.echo("\n" + "=" * 80)
        click.echo("MAPPING COVERAGE")
        click.echo("=" * 80)
        click.echo(f"Total Findings:      {coverage['total_findings']}")
        click.echo(f"Mapped Findings:     {coverage['mapped_findings']}")
        click.echo(f"Unmapped Findings:   {coverage['unmapped_findings']}")
        click.echo(f"Coverage:            {coverage['coverage_percent']}%")
        click.echo(f"Unique Check IDs:    {coverage['unique_check_ids']}")
        click.echo(f"Mapped Controls:     {coverage['mapped_controls']}")
        click.echo("=" * 80 + "\n")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        return 1


# Export all commands
__all__ = [
    "compliance_group",
    "list_frameworks",
    "show_framework",
    "scan_compliance",
    "analyze_gaps",
    "map_findings",
]
