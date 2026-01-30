"""Remediation orchestrator - coordinates all fixers."""

from typing import Dict, Any, List, Optional
from pathlib import Path
import json

from secureguard.remediation.fixers.base import BaseFixer, Fix, FixResult, FixStrategy, FixStatus
from secureguard.remediation.fixers.dependency_fixer import DependencyFixer
from secureguard.remediation.fixers.terraform_fixer import TerraformFixer
from secureguard.remediation.fixers.llm_fixer import LLMFixer
from secureguard.remediation.safety.git_integration import GitIntegration


class RemediationOrchestrator:
    """Orchestrates automated remediation of security findings."""

    def __init__(
        self,
        dry_run: bool = False,
        auto_backup: bool = True,
        use_llm: bool = True,
        llm_api_key: Optional[str] = None,
        auto_commit: bool = False,
        strategy: str = "hybrid"
    ):
        """Initialize remediation orchestrator.

        Args:
            dry_run: If True, don't actually modify files
            auto_backup: If True, create backups before modifying
            use_llm: If True, enable LLM-powered fixes
            llm_api_key: API key for LLM (optional)
            auto_commit: If True, automatically create git commits
            strategy: Fix strategy - "rule_based", "llm_powered", or "hybrid"
        """
        self.dry_run = dry_run
        self.auto_backup = auto_backup
        self.use_llm = use_llm
        self.auto_commit = auto_commit
        self.strategy = strategy

        # Initialize fixers
        self.fixers: List[BaseFixer] = [
            DependencyFixer(dry_run=dry_run, auto_backup=auto_backup),
            TerraformFixer(dry_run=dry_run, auto_backup=auto_backup),
        ]

        # Add LLM fixer if enabled
        if use_llm:
            try:
                llm_fixer = LLMFixer(api_key=llm_api_key, dry_run=dry_run, auto_backup=auto_backup)
                if llm_fixer.enabled:
                    self.fixers.append(llm_fixer)
            except Exception as e:
                print(f"Warning: Could not initialize LLM fixer: {e}")

        # Initialize git integration
        self.git = GitIntegration() if auto_commit else None

    def fix_findings(
        self,
        findings: List[Dict[str, Any]],
        interactive: bool = True,
        max_fixes: Optional[int] = None
    ) -> List[FixResult]:
        """Fix multiple security findings.

        Args:
            findings: List of security findings
            interactive: If True, ask for confirmation before each fix
            max_fixes: Maximum number of fixes to apply (None = unlimited)

        Returns:
            List of FixResult objects
        """
        results = []
        fixes_applied = 0

        # Group findings by file for efficiency
        findings_by_file = self._group_findings_by_file(findings)

        for file_path, file_findings in findings_by_file.items():
            print(f"\n{'='*80}")
            print(f"Processing file: {file_path}")
            print(f"Found {len(file_findings)} issue(s)")
            print(f"{'='*80}\n")

            # Read file content once
            try:
                file_content = Path(file_path).read_text()
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
                continue

            context = {
                "file_path": file_path,
                "content": file_content,
            }

            for finding in file_findings:
                if max_fixes and fixes_applied >= max_fixes:
                    print(f"\nReached maximum fixes limit ({max_fixes})")
                    break

                # Generate fix
                fix = self.generate_fix(finding, context)

                if not fix:
                    result = FixResult(
                        fix=None,
                        status=FixStatus.SKIPPED,
                        message=f"No fixer available for {finding.get('id', 'unknown')}"
                    )
                    results.append(result)
                    continue

                # Show fix preview
                self._show_fix_preview(fix, finding)

                # Get confirmation if interactive
                if interactive:
                    response = input("\nApply this fix? [y/N/s(kip all)/q(uit)]: ").lower().strip()

                    if response == 'q':
                        print("Quitting remediation.")
                        return results
                    elif response == 's':
                        print("Skipping remaining fixes.")
                        break
                    elif response != 'y':
                        result = FixResult(
                            fix=fix,
                            status=FixStatus.SKIPPED,
                            message="User declined to apply fix"
                        )
                        results.append(result)
                        continue

                # Apply fix
                result = self._apply_fix_with_git(fix, finding)
                results.append(result)

                if result.status == FixStatus.SUCCESS:
                    fixes_applied += 1
                    # Update file content for subsequent fixes
                    context["content"] = fix.fixed_content

        # Print summary
        self._print_summary(results)

        return results

    def generate_fix(
        self,
        finding: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[Fix]:
        """Generate a fix for a single finding.

        Args:
            finding: Security finding
            context: Optional context (file content, etc.)

        Returns:
            Fix object or None
        """
        # Try fixers in order based on strategy
        if self.strategy == "rule_based":
            fixers = [f for f in self.fixers if not isinstance(f, LLMFixer)]
        elif self.strategy == "llm_powered":
            fixers = [f for f in self.fixers if isinstance(f, LLMFixer)]
        else:  # hybrid
            # Try rule-based first, then LLM
            fixers = self.fixers

        for fixer in fixers:
            if fixer.can_fix(finding):
                fix = fixer.generate_fix(finding, context)
                if fix:
                    return fix

        return None

    def _apply_fix_with_git(self, fix: Fix, finding: Dict[str, Any]) -> FixResult:
        """Apply fix and optionally create git commit.

        Args:
            fix: The fix to apply
            finding: Original finding

        Returns:
            FixResult
        """
        # Get the appropriate fixer
        fixer = self._get_fixer_for_fix(fix)

        if not fixer:
            return FixResult(
                fix=fix,
                status=FixStatus.FAILED,
                message="No fixer found for this fix"
            )

        # Apply the fix
        result = fixer.apply_fix(fix)

        # Create git commit if successful and auto_commit enabled
        if result.status == FixStatus.SUCCESS and self.auto_commit and self.git:
            try:
                commit_message = f"fix: {fix.description}\n\nFinding ID: {fix.finding_id}\nStrategy: {fix.strategy.value}\nConfidence: {fix.confidence:.2f}"

                self.git.create_commit(
                    files=[fix.file_path],
                    message=commit_message
                )
                result.message += " (committed to git)"
            except Exception as e:
                result.message += f" (git commit failed: {e})"

        return result

    def _get_fixer_for_fix(self, fix: Fix) -> Optional[BaseFixer]:
        """Get the fixer that can handle this fix.

        Args:
            fix: The fix object

        Returns:
            BaseFixer instance or None
        """
        if fix.strategy == FixStrategy.LLM_POWERED:
            return next((f for f in self.fixers if isinstance(f, LLMFixer)), None)
        else:
            # Return first non-LLM fixer
            return next((f for f in self.fixers if not isinstance(f, LLMFixer)), None)

    def _group_findings_by_file(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by file path.

        Args:
            findings: List of findings

        Returns:
            Dictionary mapping file paths to findings
        """
        grouped = {}
        for finding in findings:
            file_path = finding.get("file")
            if file_path:
                if file_path not in grouped:
                    grouped[file_path] = []
                grouped[file_path].append(finding)
        return grouped

    def _show_fix_preview(self, fix: Fix, finding: Dict[str, Any]):
        """Show a preview of the fix.

        Args:
            fix: The fix to preview
            finding: Original finding
        """
        print(f"\n{'-'*80}")
        print(f"Finding: {finding.get('id', 'unknown')} - {finding.get('title', 'Security Issue')}")
        print(f"Severity: {finding.get('severity', 'UNKNOWN')}")
        print(f"File: {fix.file_path}")
        print(f"Strategy: {fix.strategy.value}")
        print(f"Confidence: {fix.confidence:.0%}")
        print(f"\n{fix.description}")
        print(f"\n{'-'*80}")
        print("Proposed changes:")
        print(f"{'-'*80}")

        # Show diff
        diff = self._get_fixer_for_fix(fix).get_fix_preview(fix) if self._get_fixer_for_fix(fix) else "No preview available"
        print(diff[:2000])  # Limit preview length

        if len(diff) > 2000:
            print(f"\n... (showing first 2000 characters of {len(diff)} total)")

    def _print_summary(self, results: List[FixResult]):
        """Print summary of remediation results.

        Args:
            results: List of fix results
        """
        success_count = sum(1 for r in results if r.status == FixStatus.SUCCESS)
        failed_count = sum(1 for r in results if r.status == FixStatus.FAILED)
        skipped_count = sum(1 for r in results if r.status == FixStatus.SKIPPED)

        print(f"\n{'='*80}")
        print("REMEDIATION SUMMARY")
        print(f"{'='*80}")
        print(f"Total findings: {len(results)}")
        print(f"  ✓ Successfully fixed: {success_count}")
        print(f"  ✗ Failed: {failed_count}")
        print(f"  - Skipped: {skipped_count}")
        print(f"{'='*80}\n")

        if failed_count > 0:
            print("Failed fixes:")
            for result in results:
                if result.status == FixStatus.FAILED:
                    print(f"  - {result.fix.file_path if result.fix else 'unknown'}: {result.message}")

    def export_results(self, results: List[FixResult], output_path: str):
        """Export remediation results to JSON.

        Args:
            results: List of fix results
            output_path: Path to output JSON file
        """
        export_data = {
            "total_findings": len(results),
            "successful_fixes": sum(1 for r in results if r.status == FixStatus.SUCCESS),
            "failed_fixes": sum(1 for r in results if r.status == FixStatus.FAILED),
            "skipped_fixes": sum(1 for r in results if r.status == FixStatus.SKIPPED),
            "results": [
                {
                    "file": result.fix.file_path if result.fix else None,
                    "finding_id": result.fix.finding_id if result.fix else None,
                    "status": result.status.value,
                    "message": result.message,
                    "strategy": result.fix.strategy.value if result.fix else None,
                    "confidence": result.fix.confidence if result.fix else None,
                }
                for result in results
            ]
        }

        with open(output_path, "w") as f:
            json.dump(export_data, f, indent=2)

        print(f"Results exported to: {output_path}")
