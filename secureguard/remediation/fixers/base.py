"""Base fixer class for all remediation fixers."""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from pathlib import Path
from dataclasses import dataclass
from enum import Enum


class FixStrategy(Enum):
    """Fix strategy types."""
    RULE_BASED = "rule_based"      # Simple template-based fixes
    LLM_POWERED = "llm_powered"     # AI-generated fixes
    HYBRID = "hybrid"                # Combination of both


class FixStatus(Enum):
    """Status of a fix attempt."""
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    NEEDS_REVIEW = "needs_review"


@dataclass
class Fix:
    """Represents a code fix."""
    finding_id: str
    file_path: str
    original_content: str
    fixed_content: str
    description: str
    strategy: FixStrategy
    confidence: float  # 0.0 - 1.0
    metadata: Dict[str, Any]


@dataclass
class FixResult:
    """Result of applying a fix."""
    fix: Fix
    status: FixStatus
    message: str
    backup_path: Optional[str] = None
    validation_errors: List[str] = None


class BaseFixer(ABC):
    """Base class for all fixers."""

    def __init__(self, dry_run: bool = False, auto_backup: bool = True):
        """Initialize fixer.

        Args:
            dry_run: If True, don't actually modify files
            auto_backup: If True, create backups before modifying files
        """
        self.dry_run = dry_run
        self.auto_backup = auto_backup

    @abstractmethod
    def can_fix(self, finding: Dict[str, Any]) -> bool:
        """Check if this fixer can handle the given finding.

        Args:
            finding: Security finding dictionary

        Returns:
            True if this fixer can handle the finding
        """
        pass

    @abstractmethod
    def generate_fix(self, finding: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Optional[Fix]:
        """Generate a fix for the given finding.

        Args:
            finding: Security finding dictionary
            context: Optional context (file content, related findings, etc.)

        Returns:
            Fix object or None if unable to generate fix
        """
        pass

    @abstractmethod
    def validate_fix(self, fix: Fix) -> tuple[bool, List[str]]:
        """Validate that a fix is correct and safe to apply.

        Args:
            fix: The fix to validate

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        pass

    def apply_fix(self, fix: Fix) -> FixResult:
        """Apply a fix to the file.

        Args:
            fix: The fix to apply

        Returns:
            FixResult with status and details
        """
        if self.dry_run:
            return FixResult(
                fix=fix,
                status=FixStatus.SKIPPED,
                message="Dry run mode - fix not applied"
            )

        # Validate fix first
        is_valid, errors = self.validate_fix(fix)
        if not is_valid:
            return FixResult(
                fix=fix,
                status=FixStatus.FAILED,
                message="Fix validation failed",
                validation_errors=errors
            )

        # Create backup if enabled
        backup_path = None
        if self.auto_backup:
            backup_path = self._create_backup(fix.file_path)

        try:
            # Apply the fix
            file_path = Path(fix.file_path)
            file_path.write_text(fix.fixed_content)

            return FixResult(
                fix=fix,
                status=FixStatus.SUCCESS,
                message=f"Successfully applied fix to {fix.file_path}",
                backup_path=backup_path
            )

        except Exception as e:
            # Restore from backup if available
            if backup_path:
                self._restore_backup(backup_path, fix.file_path)

            return FixResult(
                fix=fix,
                status=FixStatus.FAILED,
                message=f"Failed to apply fix: {str(e)}",
                backup_path=backup_path
            )

    def _create_backup(self, file_path: str) -> str:
        """Create a backup of the file.

        Args:
            file_path: Path to file to backup

        Returns:
            Path to backup file
        """
        from datetime import datetime
        import shutil

        path = Path(file_path)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = path.parent / f"{path.name}.backup.{timestamp}"

        shutil.copy2(file_path, backup_path)
        return str(backup_path)

    def _restore_backup(self, backup_path: str, original_path: str):
        """Restore a file from backup.

        Args:
            backup_path: Path to backup file
            original_path: Path to restore to
        """
        import shutil
        shutil.copy2(backup_path, original_path)

    def get_file_content(self, file_path: str) -> str:
        """Read file content.

        Args:
            file_path: Path to file

        Returns:
            File content as string
        """
        return Path(file_path).read_text()

    def get_fix_preview(self, fix: Fix) -> str:
        """Generate a preview of the fix showing diff.

        Args:
            fix: The fix to preview

        Returns:
            Formatted diff string
        """
        import difflib

        original_lines = fix.original_content.splitlines(keepends=True)
        fixed_lines = fix.fixed_content.splitlines(keepends=True)

        diff = difflib.unified_diff(
            original_lines,
            fixed_lines,
            fromfile=f"{fix.file_path} (original)",
            tofile=f"{fix.file_path} (fixed)",
            lineterm=""
        )

        return "".join(diff)
