"""Fixer for dependency vulnerabilities."""

import re
from typing import Dict, Any, List, Optional
from pathlib import Path

from secureguard.remediation.fixers.base import BaseFixer, Fix, FixStrategy


class DependencyFixer(BaseFixer):
    """Fixes dependency vulnerabilities by updating package versions."""

    def __init__(self, **kwargs):
        """Initialize dependency fixer."""
        super().__init__(**kwargs)

    def can_fix(self, finding: Dict[str, Any]) -> bool:
        """Check if this is a dependency vulnerability.

        Args:
            finding: Security finding dictionary

        Returns:
            True if this is a dependency vulnerability
        """
        return finding.get("type") == "DEPENDENCY_VULNERABILITY"

    def generate_fix(self, finding: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Optional[Fix]:
        """Generate fix for dependency vulnerability.

        Args:
            finding: Security finding with package, version, and fix info
            context: Optional context with file path and content

        Returns:
            Fix object or None
        """
        package = finding.get("package")
        current_version = finding.get("version")
        fix_version = finding.get("fix_version") or finding.get("patched_version")

        if not all([package, current_version]):
            return None

        # Get file path and content
        file_path = context.get("file_path") if context else finding.get("file")
        if not file_path:
            return None

        original_content = context.get("content") if context else self.get_file_content(file_path)

        # Determine file type and generate fix
        file_name = Path(file_path).name

        if file_name == "requirements.txt":
            fixed_content = self._fix_requirements_txt(original_content, package, current_version, fix_version)
        elif file_name == "package.json":
            fixed_content = self._fix_package_json(original_content, package, current_version, fix_version)
        elif file_name == "Pipfile":
            fixed_content = self._fix_pipfile(original_content, package, current_version, fix_version)
        elif file_name == "pyproject.toml":
            fixed_content = self._fix_pyproject_toml(original_content, package, current_version, fix_version)
        elif file_name == "pom.xml":
            fixed_content = self._fix_pom_xml(original_content, package, current_version, fix_version)
        elif file_name == "Gemfile":
            fixed_content = self._fix_gemfile(original_content, package, current_version, fix_version)
        else:
            return None

        if not fixed_content or fixed_content == original_content:
            return None

        description = f"Update {package} from {current_version} to {fix_version or 'latest secure version'}"
        if finding.get("description"):
            description += f" (fixes: {finding['description']})"

        return Fix(
            finding_id=finding.get("id", finding.get("cve_id", "unknown")),
            file_path=file_path,
            original_content=original_content,
            fixed_content=fixed_content,
            description=description,
            strategy=FixStrategy.RULE_BASED,
            confidence=0.9 if fix_version else 0.7,
            metadata={
                "package": package,
                "old_version": current_version,
                "new_version": fix_version,
                "cve_id": finding.get("cve_id"),
            }
        )

    def validate_fix(self, fix: Fix) -> tuple[bool, List[str]]:
        """Validate dependency fix.

        Args:
            fix: The fix to validate

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Check that the fix actually changed something
        if fix.original_content == fix.fixed_content:
            errors.append("Fix did not modify the file")

        # Check that the package is still present (not accidentally removed)
        package = fix.metadata.get("package")
        if package and package not in fix.fixed_content:
            errors.append(f"Package '{package}' not found in fixed content")

        # Check for syntax errors (basic validation)
        file_name = Path(fix.file_path).name
        if file_name == "package.json":
            import json
            try:
                json.loads(fix.fixed_content)
            except json.JSONDecodeError as e:
                errors.append(f"Invalid JSON syntax: {e}")

        return (len(errors) == 0, errors)

    def _fix_requirements_txt(self, content: str, package: str, old_version: str, new_version: Optional[str]) -> str:
        """Fix requirements.txt file.

        Args:
            content: File content
            package: Package name
            old_version: Current version
            new_version: Version to upgrade to

        Returns:
            Fixed content
        """
        lines = content.split("\n")
        fixed_lines = []

        for line in lines:
            # Match package lines (package==version or package>=version, etc.)
            if re.match(rf"^{re.escape(package)}\s*[=><~!]", line, re.IGNORECASE):
                if new_version:
                    # Replace with specific version
                    fixed_line = f"{package}>={new_version}"
                else:
                    # Just remove version constraint to get latest
                    fixed_line = package

                fixed_lines.append(fixed_line)
            else:
                fixed_lines.append(line)

        return "\n".join(fixed_lines)

    def _fix_package_json(self, content: str, package: str, old_version: str, new_version: Optional[str]) -> str:
        """Fix package.json file.

        Args:
            content: File content
            package: Package name
            old_version: Current version
            new_version: Version to upgrade to

        Returns:
            Fixed content
        """
        import json

        try:
            data = json.loads(content)

            # Update in dependencies
            if "dependencies" in data and package in data["dependencies"]:
                data["dependencies"][package] = f"^{new_version}" if new_version else "*"

            # Update in devDependencies
            if "devDependencies" in data and package in data["devDependencies"]:
                data["devDependencies"][package] = f"^{new_version}" if new_version else "*"

            return json.dumps(data, indent=2)

        except json.JSONDecodeError:
            return content

    def _fix_pipfile(self, content: str, package: str, old_version: str, new_version: Optional[str]) -> str:
        """Fix Pipfile.

        Args:
            content: File content
            package: Package name
            old_version: Current version
            new_version: Version to upgrade to

        Returns:
            Fixed content
        """
        lines = content.split("\n")
        fixed_lines = []

        for line in lines:
            # Match package lines in Pipfile format: package = "==version"
            if re.match(rf'^{re.escape(package)}\s*=', line, re.IGNORECASE):
                if new_version:
                    fixed_line = f'{package} = ">={new_version}"'
                else:
                    fixed_line = f'{package} = "*"'
                fixed_lines.append(fixed_line)
            else:
                fixed_lines.append(line)

        return "\n".join(fixed_lines)

    def _fix_pyproject_toml(self, content: str, package: str, old_version: str, new_version: Optional[str]) -> str:
        """Fix pyproject.toml file.

        Args:
            content: File content
            package: Package name
            old_version: Current version
            new_version: Version to upgrade to

        Returns:
            Fixed content
        """
        lines = content.split("\n")
        fixed_lines = []

        for line in lines:
            # Match package lines in TOML format: "package==version" or "package>=version"
            if f'"{package}' in line or f"'{package}" in line:
                if new_version:
                    # Replace version constraint
                    fixed_line = re.sub(
                        rf'"{re.escape(package)}[^"]*"',
                        f'"{package}>={new_version}"',
                        line
                    )
                    fixed_line = re.sub(
                        rf"'{re.escape(package)}[^']*'",
                        f"'{package}>={new_version}'",
                        fixed_line
                    )
                else:
                    # Remove version constraint
                    fixed_line = re.sub(
                        rf'"{re.escape(package)}[^"]*"',
                        f'"{package}"',
                        line
                    )
                    fixed_line = re.sub(
                        rf"'{re.escape(package)}[^']*'",
                        f"'{package}'",
                        fixed_line
                    )
                fixed_lines.append(fixed_line)
            else:
                fixed_lines.append(line)

        return "\n".join(fixed_lines)

    def _fix_pom_xml(self, content: str, package: str, old_version: str, new_version: Optional[str]) -> str:
        """Fix pom.xml file.

        Args:
            content: File content
            package: Package name (groupId:artifactId format)
            old_version: Current version
            new_version: Version to upgrade to

        Returns:
            Fixed content
        """
        if ":" in package:
            group_id, artifact_id = package.split(":", 1)
        else:
            artifact_id = package
            group_id = None

        if new_version and old_version in content:
            # Simple version replacement in <version> tags
            content = content.replace(
                f"<version>{old_version}</version>",
                f"<version>{new_version}</version>"
            )

        return content

    def _fix_gemfile(self, content: str, package: str, old_version: str, new_version: Optional[str]) -> str:
        """Fix Gemfile.

        Args:
            content: File content
            package: Package name (gem name)
            old_version: Current version
            new_version: Version to upgrade to

        Returns:
            Fixed content
        """
        lines = content.split("\n")
        fixed_lines = []

        for line in lines:
            # Match gem lines: gem 'package', 'version'
            if re.match(rf"^\s*gem\s+['\"]{ re.escape(package)}['\"]", line, re.IGNORECASE):
                if new_version:
                    fixed_line = f"gem '{package}', '>= {new_version}'"
                else:
                    fixed_line = f"gem '{package}'"
                fixed_lines.append(fixed_line)
            else:
                fixed_lines.append(line)

        return "\n".join(fixed_lines)
