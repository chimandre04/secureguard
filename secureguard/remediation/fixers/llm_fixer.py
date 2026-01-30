"""LLM-powered fixer for complex security issues."""

from typing import Dict, Any, List, Optional
from pathlib import Path

from secureguard.remediation.fixers.base import BaseFixer, Fix, FixStrategy
from secureguard.remediation.llm.claude_client import ClaudeClient


class LLMFixer(BaseFixer):
    """Uses LLM (Claude) to generate fixes for complex security issues."""

    def __init__(self, api_key: Optional[str] = None, **kwargs):
        """Initialize LLM fixer.

        Args:
            api_key: Anthropic API key (optional, defaults to env var)
            **kwargs: Additional arguments for BaseFixer
        """
        super().__init__(**kwargs)
        try:
            self.client = ClaudeClient(api_key=api_key)
            self.enabled = True
        except (ValueError, ImportError) as e:
            print(f"Warning: LLM fixer disabled - {e}")
            self.client = None
            self.enabled = False

    def can_fix(self, finding: Dict[str, Any]) -> bool:
        """Check if LLM fixer is available and can handle this finding.

        Args:
            finding: Security finding dictionary

        Returns:
            True if LLM is enabled (can fix anything in theory)
        """
        # LLM can theoretically fix any finding, but we'll use it as fallback
        return self.enabled

    def generate_fix(self, finding: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Optional[Fix]:
        """Generate AI-powered fix for security finding.

        Args:
            finding: Security finding
            context: Optional context with file content

        Returns:
            Fix object or None
        """
        if not self.enabled:
            return None

        file_path = finding.get("file")
        if not file_path:
            return None

        # Get file content
        if context and "content" in context:
            original_content = context["content"]
        else:
            try:
                original_content = self.get_file_content(file_path)
            except Exception as e:
                print(f"Error reading file {file_path}: {e}")
                return None

        # Generate fix using Claude
        result = self.client.generate_fix(finding, original_content, context)

        if not result:
            return None

        fixed_content = result.get("fixed_content")
        if not fixed_content:
            return None

        return Fix(
            finding_id=finding.get("id", "unknown"),
            file_path=file_path,
            original_content=original_content,
            fixed_content=fixed_content,
            description=result.get("explanation", finding.get("remediation", "AI-generated fix")),
            strategy=FixStrategy.LLM_POWERED,
            confidence=result.get("confidence", 0.7),
            metadata={
                "model": self.client.model,
                "changes_made": result.get("changes_made", []),
                "finding_type": finding.get("type"),
            }
        )

    def validate_fix(self, fix: Fix) -> tuple[bool, List[str]]:
        """Validate LLM-generated fix.

        Uses AI to validate the fix for correctness.

        Args:
            fix: The fix to validate

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Basic validation
        if fix.original_content == fix.fixed_content:
            errors.append("Fix did not modify the file")

        if not self.enabled:
            # Can't validate with AI if LLM is disabled
            return (len(errors) == 0, errors)

        # Use AI to validate the fix
        finding = {
            "id": fix.finding_id,
            "description": fix.description,
            "type": fix.metadata.get("finding_type"),
        }

        validation_result = self.client.validate_fix_with_ai(
            fix.original_content,
            fix.fixed_content,
            finding
        )

        if not validation_result.get("is_valid", True):
            errors.extend(validation_result.get("issues", []))

        # Add AI suggestions as warnings (not errors)
        suggestions = validation_result.get("suggestions", [])
        if suggestions:
            fix.metadata["ai_suggestions"] = suggestions

        return (len(errors) == 0, errors)
