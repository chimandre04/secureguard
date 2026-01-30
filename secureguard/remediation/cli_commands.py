"""CLI commands for automated remediation."""

import click
import json
from pathlib import Path
from typing import Optional

from secureguard.remediation.orchestrator import RemediationOrchestrator


@click.group(name="fix")
def fix_group():
    """Automated fixing of security vulnerabilities and compliance issues."""
    pass


@fix_group.command(name="security")
@click.option("--findings", "-f", type=click.Path(exists=True), required=True, help="Path to findings JSON file")
@click.option("--mode", "-m", type=click.Choice(["interactive", "auto"]), default="interactive", help="Fix mode")
@click.option("--dry-run", "-d", is_flag=True, help="Preview fixes without applying them")
@click.option("--strategy", "-s", type=click.Choice(["rule_based", "llm_powered", "hybrid"]), default="hybrid", help="Fix strategy")
@click.option("--no-backup", is_flag=True, help="Disable automatic backups")
@click.option("--auto-commit", is_flag=True, help="Automatically create git commits")
@click.option("--api-key", type=str, help="Anthropic API key for LLM fixes (or set ANTHROPIC_API_KEY env var)")
@click.option("--max-fixes", type=int, help="Maximum number of fixes to apply")
@click.option("--output", "-o", type=click.Path(), help="Export results to JSON file")
def fix_security(
    findings: str,
    mode: str,
    dry_run: bool,
    strategy: str,
    no_backup: bool,
    auto_commit: bool,
    api_key: Optional[str],
    max_fixes: Optional[int],
    output: Optional[str]
):
    """Automatically fix security vulnerabilities.

    Examples:

        # Interactive mode (default) - review each fix
        secureguard fix security --findings findings.json

        # Automatic mode - apply all fixes without prompts
        secureguard fix security --findings findings.json --mode auto

        # Dry run - preview fixes without applying
        secureguard fix security --findings findings.json --dry-run

        # Use only rule-based fixes (no LLM)
        secureguard fix security --findings findings.json --strategy rule_based

        # Use LLM-powered fixes with auto-commit
        secureguard fix security --findings findings.json --strategy llm_powered --auto-commit
    """
    try:
        # Load findings
        click.echo(f"Loading findings from: {findings}")
        with open(findings, "r") as f:
            findings_data = json.load(f)

        # Handle different finding formats
        if isinstance(findings_data, dict):
            findings_list = findings_data.get("findings", [findings_data])
        elif isinstance(findings_data, list):
            findings_list = findings_data
        else:
            findings_list = [findings_data]

        click.echo(f"Found {len(findings_list)} security issue(s)")

        # Show mode information
        if dry_run:
            click.echo("\n⚠️  DRY RUN MODE - No changes will be made\n")

        # Initialize orchestrator
        use_llm = strategy in ["llm_powered", "hybrid"]

        orchestrator = RemediationOrchestrator(
            dry_run=dry_run,
            auto_backup=not no_backup,
            use_llm=use_llm,
            llm_api_key=api_key,
            auto_commit=auto_commit,
            strategy=strategy
        )

        # Apply fixes
        interactive = (mode == "interactive" and not dry_run)

        results = orchestrator.fix_findings(
            findings_list,
            interactive=interactive,
            max_fixes=max_fixes
        )

        # Export results if requested
        if output:
            orchestrator.export_results(results, output)

        # Exit with error code if any fixes failed
        failed_count = sum(1 for r in results if r.status.value == "failed")
        if failed_count > 0:
            return 1

    except FileNotFoundError:
        click.echo(f"Error: Findings file not found: {findings}", err=True)
        return 1
    except json.JSONDecodeError as e:
        click.echo(f"Error: Invalid JSON in findings file: {e}", err=True)
        return 1
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        import traceback
        traceback.print_exc()
        return 1


@fix_group.command(name="compliance")
@click.option("--framework", "-F", required=True, help="Compliance framework (soc2, nist_csf, etc.)")
@click.option("--findings", "-f", type=click.Path(exists=True), required=True, help="Path to findings JSON file")
@click.option("--controls", "-c", help="Comma-separated list of control IDs to fix")
@click.option("--mode", "-m", type=click.Choice(["interactive", "auto"]), default="interactive", help="Fix mode")
@click.option("--dry-run", "-d", is_flag=True, help="Preview fixes without applying them")
@click.option("--strategy", "-s", type=click.Choice(["rule_based", "llm_powered", "hybrid"]), default="hybrid", help="Fix strategy")
@click.option("--no-backup", is_flag=True, help="Disable automatic backups")
@click.option("--auto-commit", is_flag=True, help="Automatically create git commits")
@click.option("--api-key", type=str, help="Anthropic API key for LLM fixes")
@click.option("--output", "-o", type=click.Path(), help="Export results to JSON file")
def fix_compliance(
    framework: str,
    findings: str,
    controls: Optional[str],
    mode: str,
    dry_run: bool,
    strategy: str,
    no_backup: bool,
    auto_commit: bool,
    api_key: Optional[str],
    output: Optional[str]
):
    """Automatically fix compliance violations.

    Examples:

        # Fix all compliance issues for SOC 2
        secureguard fix compliance --framework soc2 --findings findings.json

        # Fix specific controls only
        secureguard fix compliance --framework soc2 --findings findings.json --controls CC6.1,CC6.6

        # Automatic mode with git commits
        secureguard fix compliance --framework soc2 --findings findings.json --mode auto --auto-commit
    """
    try:
        from secureguard.compliance.core.framework import FrameworkLoader
        from secureguard.compliance.core.mapper import ComplianceMapper

        # Load framework
        click.echo(f"Loading framework: {framework}")
        loader = FrameworkLoader()
        fw = loader.load(framework)

        # Load findings
        click.echo(f"Loading findings from: {findings}")
        with open(findings, "r") as f:
            findings_data = json.load(f)

        if isinstance(findings_data, dict):
            findings_list = findings_data.get("findings", [findings_data])
        elif isinstance(findings_data, list):
            findings_list = findings_data
        else:
            findings_list = [findings_data]

        # Map findings to controls
        mapper = ComplianceMapper(fw)
        mapped_findings = mapper.map_findings(findings_list)

        # Filter by specific controls if requested
        if controls:
            control_ids = [c.strip() for c in controls.split(",")]
            filtered_findings = []
            for control_id in control_ids:
                if control_id in mapped_findings:
                    filtered_findings.extend(mapped_findings[control_id])
            findings_list = filtered_findings

        click.echo(f"Found {len(findings_list)} compliance violation(s) to fix")

        if not findings_list:
            click.echo("No findings to fix.")
            return 0

        # Initialize orchestrator
        use_llm = strategy in ["llm_powered", "hybrid"]

        orchestrator = RemediationOrchestrator(
            dry_run=dry_run,
            auto_backup=not no_backup,
            use_llm=use_llm,
            llm_api_key=api_key,
            auto_commit=auto_commit,
            strategy=strategy
        )

        # Apply fixes
        interactive = (mode == "interactive" and not dry_run)

        results = orchestrator.fix_findings(
            findings_list,
            interactive=interactive
        )

        # Export results if requested
        if output:
            orchestrator.export_results(results, output)

        # Exit with error code if any fixes failed
        failed_count = sum(1 for r in results if r.status.value == "failed")
        if failed_count > 0:
            return 1

    except FileNotFoundError as e:
        click.echo(f"Error: File not found: {e}", err=True)
        return 1
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        import traceback
        traceback.print_exc()
        return 1


@fix_group.command(name="single")
@click.option("--file", "-f", type=click.Path(exists=True), required=True, help="File to fix")
@click.option("--finding-id", "-i", required=True, help="Finding ID to fix")
@click.option("--description", "-d", required=True, help="Description of the security issue")
@click.option("--severity", "-s", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]), default="HIGH")
@click.option("--strategy", type=click.Choice(["rule_based", "llm_powered"]), default="llm_powered")
@click.option("--dry-run", is_flag=True, help="Preview fix without applying")
@click.option("--api-key", type=str, help="Anthropic API key for LLM fixes")
def fix_single(
    file: str,
    finding_id: str,
    description: str,
    severity: str,
    strategy: str,
    dry_run: bool,
    api_key: Optional[str]
):
    """Fix a single security issue in a file.

    Useful for fixing custom security issues not detected by scanners.

    Example:

        secureguard fix single \\
          --file src/app.py \\
          --finding-id CUSTOM_001 \\
          --description "SQL injection vulnerability in user input" \\
          --severity HIGH
    """
    try:
        # Create a finding dictionary
        finding = {
            "id": finding_id,
            "file": file,
            "description": description,
            "severity": severity,
            "type": "CUSTOM_FINDING",
        }

        click.echo(f"\nFinding: {finding_id}")
        click.echo(f"File: {file}")
        click.echo(f"Severity: {severity}")
        click.echo(f"Description: {description}\n")

        # Initialize orchestrator
        use_llm = (strategy == "llm_powered")

        orchestrator = RemediationOrchestrator(
            dry_run=dry_run,
            auto_backup=True,
            use_llm=use_llm,
            llm_api_key=api_key,
            auto_commit=False,
            strategy=strategy
        )

        # Generate fix
        file_content = Path(file).read_text()
        context = {"file_path": file, "content": file_content}

        fix = orchestrator.generate_fix(finding, context)

        if not fix:
            click.echo("Error: Could not generate fix for this finding.", err=True)
            return 1

        # Show preview
        click.echo("Proposed fix:")
        click.echo("="*80)
        fixer = orchestrator._get_fixer_for_fix(fix)
        if fixer:
            diff = fixer.get_fix_preview(fix)
            click.echo(diff[:2000])
            if len(diff) > 2000:
                click.echo(f"\n... (showing first 2000 of {len(diff)} characters)")

        if dry_run:
            click.echo("\nDry run mode - fix not applied")
            return 0

        # Confirm
        if click.confirm("\nApply this fix?"):
            result = orchestrator._apply_fix_with_git(fix, finding)
            if result.status.value == "success":
                click.echo(f"\n✓ {result.message}")
                return 0
            else:
                click.echo(f"\n✗ {result.message}", err=True)
                return 1
        else:
            click.echo("Fix not applied.")
            return 0

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        import traceback
        traceback.print_exc()
        return 1


# Export all commands
__all__ = ["fix_group", "fix_security", "fix_compliance", "fix_single"]
