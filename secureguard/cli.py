"""Command-line interface for SecureGuard."""

import sys
import click
from pathlib import Path

from secureguard.scanners.deps_scanner import DependencyScanner
from secureguard.analyzers.terraform import TerraformAnalyzer
from secureguard.analyzers.cloudformation import CloudFormationAnalyzer
from secureguard.utils.severity import Severity
from secureguard.utils.output import format_output, OutputFormat
from secureguard.compliance.cli_commands import compliance_group
from secureguard.remediation.cli_commands import fix_group


@click.group()
@click.version_option(version="0.1.0")
def main():
    """SecureGuard - Comprehensive Security Scanning Platform

    Detect vulnerabilities across your entire development lifecycle.
    """
    pass


# Add compliance command group
main.add_command(compliance_group)

# Add fix/remediation command group
main.add_command(fix_group)


@main.group()
def scan():
    """Scan for security vulnerabilities and misconfigurations."""
    pass


@scan.command(name="deps")
@click.option(
    "--file",
    "-f",
    required=True,
    type=click.Path(exists=True),
    help="Package manifest file to scan (requirements.txt, package.json, etc.)"
)
@click.option(
    "--format",
    type=click.Choice(["table", "json", "sarif"], case_sensitive=False),
    default="table",
    help="Output format"
)
@click.option(
    "--severity",
    type=click.Choice(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
    default="INFO",
    help="Minimum severity to report"
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Write output to file instead of stdout"
)
def scan_deps(file, format, severity, output):
    """Scan package dependencies for known vulnerabilities.

    Examples:

        secureguard scan deps --file requirements.txt

        secureguard scan deps --file package.json --format json

        secureguard scan deps --file requirements.txt --severity HIGH
    """
    try:
        # Initialize scanner
        scanner = DependencyScanner(
            severity_threshold=Severity(severity.upper())
        )

        # Scan file
        click.echo(f"Scanning {file} for vulnerabilities...")
        findings = scanner.scan_file(file)

        # Format output
        output_format = OutputFormat(format.lower())
        result = format_output(findings, output_format)

        # Write output
        if output:
            Path(output).write_text(result)
            click.echo(f"Results written to {output}")
        else:
            click.echo(result)

        # Exit with error code if vulnerabilities found
        if findings:
            sys.exit(1)

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@scan.command(name="iac")
@click.option(
    "--path",
    "-p",
    required=True,
    type=click.Path(exists=True),
    help="Path to directory or file containing IaC templates"
)
@click.option(
    "--type",
    type=click.Choice(["terraform", "cloudformation", "all"], case_sensitive=False),
    default="all",
    help="Type of IaC to analyze"
)
@click.option(
    "--format",
    type=click.Choice(["table", "json", "sarif"], case_sensitive=False),
    default="table",
    help="Output format"
)
@click.option(
    "--severity",
    type=click.Choice(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
    default="INFO",
    help="Minimum severity to report"
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Write output to file instead of stdout"
)
def scan_iac(path, type, format, severity, output):
    """Analyze Infrastructure as Code for security misconfigurations.

    Examples:

        secureguard scan iac --path ./terraform

        secureguard scan iac --path ./cloudformation --type cloudformation

        secureguard scan iac --path . --severity HIGH --format json
    """
    try:
        path_obj = Path(path)
        severity_threshold = Severity(severity.upper())
        all_findings = []

        # Determine what to scan
        if type.lower() in ["terraform", "all"]:
            click.echo("Analyzing Terraform templates...")
            tf_analyzer = TerraformAnalyzer(severity_threshold=severity_threshold)

            if path_obj.is_file():
                findings = tf_analyzer.analyze_file(str(path_obj))
            else:
                findings = tf_analyzer.analyze_directory(str(path_obj))

            all_findings.extend(findings)

        if type.lower() in ["cloudformation", "all"]:
            click.echo("Analyzing CloudFormation templates...")
            cf_analyzer = CloudFormationAnalyzer(severity_threshold=severity_threshold)

            if path_obj.is_file():
                findings = cf_analyzer.analyze_file(str(path_obj))
            else:
                findings = cf_analyzer.analyze_directory(str(path_obj))

            all_findings.extend(findings)

        # Format output
        output_format = OutputFormat(format.lower())
        result = format_output(all_findings, output_format)

        # Write output
        if output:
            Path(output).write_text(result)
            click.echo(f"Results written to {output}")
        else:
            click.echo(result)

        # Exit with error code if issues found
        if all_findings:
            sys.exit(1)

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
def init():
    """Initialize SecureGuard configuration.

    Creates a .secureguard.yml configuration file in the current directory.
    """
    config_template = """# SecureGuard Configuration
version: 1

# Dependency scanning settings
dependencies:
  severity_threshold: MEDIUM
  exclude_packages: []

# IaC analysis settings
iac:
  severity_threshold: MEDIUM
  terraform:
    enabled: true
  cloudformation:
    enabled: true

# Runtime sensor settings
sensor:
  block_attacks: false
  severity_threshold: MEDIUM
  webhook_url: null
"""

    config_path = Path(".secureguard.yml")

    if config_path.exists():
        click.confirm(
            "Configuration file already exists. Overwrite?",
            abort=True
        )

    config_path.write_text(config_template)
    click.echo(f"Created configuration file: {config_path}")


@main.command()
@click.option(
    "--file",
    "-f",
    required=True,
    type=click.Path(exists=True),
    help="File to check"
)
def check_file(file):
    """Quick security check on a single file.

    Automatically detects file type and runs appropriate scanner.
    """
    file_path = Path(file)

    # Try dependency scanner
    scanner = DependencyScanner()
    if file_path.name in scanner.SUPPORTED_FILES:
        click.echo(f"Detected as dependency file. Scanning...")
        findings = scanner.scan_file(str(file_path))
        result = format_output(findings, OutputFormat.TABLE)
        click.echo(result)
        return

    # Try IaC analyzers
    if file_path.suffix in [".tf", ".json"]:
        click.echo("Detected as Terraform file. Analyzing...")
        analyzer = TerraformAnalyzer()
        findings = analyzer.analyze_file(str(file_path))
        result = format_output(findings, OutputFormat.TABLE)
        click.echo(result)
        return

    if file_path.suffix in [".yaml", ".yml", ".json"]:
        try:
            click.echo("Attempting CloudFormation analysis...")
            analyzer = CloudFormationAnalyzer()
            findings = analyzer.analyze_file(str(file_path))
            if findings:
                result = format_output(findings, OutputFormat.TABLE)
                click.echo(result)
                return
        except Exception:
            pass

    click.echo(f"Unable to detect file type for {file}")


@main.command()
def info():
    """Display information about SecureGuard."""
    info_text = """
SecureGuard v0.1.0
==================

A comprehensive security scanning platform for developers.

Features:
  • Dependency Vulnerability Scanner
    - Scans package manifests for known CVEs
    - Supports Python, JavaScript, Java, and more
    - Uses OSV database for up-to-date vulnerability data

  • Infrastructure as Code Analyzer
    - Analyzes Terraform and CloudFormation templates
    - Detects security misconfigurations
    - Provides remediation guidance

  • Runtime Security Sensor
    - Real-time attack detection for web applications
    - Middleware for FastAPI and Flask
    - Detects SQL injection, XSS, path traversal, and more

Documentation: https://github.com/yourusername/secureguard
Report Issues: https://github.com/yourusername/secureguard/issues
"""
    click.echo(info_text)


if __name__ == "__main__":
    main()
