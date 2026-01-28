"""Dependency vulnerability scanner using OSV database."""

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import requests
from packaging.version import parse as parse_version, Version

from secureguard.utils.severity import Severity, calculate_severity


class DependencyScanner:
    """Scans package dependencies for known vulnerabilities."""

    OSV_API_URL = "https://api.osv.dev/v1/query"
    OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

    SUPPORTED_FILES = {
        "requirements.txt": "pip",
        "Pipfile": "pip",
        "pyproject.toml": "pip",
        "poetry.lock": "pip",
        "package.json": "npm",
        "package-lock.json": "npm",
        "yarn.lock": "npm",
        "pom.xml": "maven",
        "build.gradle": "gradle",
        "Gemfile": "gem",
        "go.mod": "go",
        "Cargo.toml": "cargo",
    }

    def __init__(self, severity_threshold: Optional[Severity] = None):
        """Initialize scanner.

        Args:
            severity_threshold: Only report vulnerabilities at or above this severity
        """
        self.severity_threshold = severity_threshold or Severity.INFO

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a package file for vulnerabilities.

        Args:
            file_path: Path to package manifest file

        Returns:
            List of vulnerability findings
        """
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Detect package ecosystem
        ecosystem = self._detect_ecosystem(path.name)
        if not ecosystem:
            raise ValueError(f"Unsupported file type: {path.name}")

        # Parse dependencies
        dependencies = self._parse_dependencies(path, ecosystem)

        if not dependencies:
            return []

        # Query OSV for vulnerabilities
        vulnerabilities = self._query_osv_batch(dependencies, ecosystem)

        # Filter by severity
        filtered = [
            v for v in vulnerabilities
            if Severity(v["severity"]) >= self.severity_threshold
        ]

        return filtered

    def _detect_ecosystem(self, filename: str) -> Optional[str]:
        """Detect package ecosystem from filename."""
        return self.SUPPORTED_FILES.get(filename)

    def _parse_dependencies(
        self, file_path: Path, ecosystem: str
    ) -> List[Tuple[str, Optional[str]]]:
        """Parse dependencies from file.

        Args:
            file_path: Path to package file
            ecosystem: Package ecosystem (pip, npm, etc.)

        Returns:
            List of (package_name, version) tuples
        """
        if ecosystem == "pip":
            return self._parse_python_dependencies(file_path)
        elif ecosystem == "npm":
            return self._parse_npm_dependencies(file_path)
        elif ecosystem == "maven":
            return self._parse_maven_dependencies(file_path)
        else:
            return []

    def _parse_python_dependencies(
        self, file_path: Path
    ) -> List[Tuple[str, Optional[str]]]:
        """Parse Python dependencies."""
        dependencies = []

        if file_path.name == "requirements.txt":
            # Parse requirements.txt format
            with open(file_path, "r") as f:
                for line in f:
                    line = line.strip()

                    # Skip comments and empty lines
                    if not line or line.startswith("#"):
                        continue

                    # Skip -e editable installs and other pip options
                    if line.startswith("-"):
                        continue

                    # Parse package specification
                    # Supports: package==1.0.0, package>=1.0.0, package~=1.0.0, etc.
                    match = re.match(r"([a-zA-Z0-9_-]+)([><=~!]+)?(.+)?", line)
                    if match:
                        name = match.group(1)
                        operator = match.group(2)
                        version = match.group(3)

                        # Only include specific versions for exact matches
                        if operator == "==" and version:
                            dependencies.append((name, version.strip()))
                        else:
                            dependencies.append((name, None))

        elif file_path.name == "pyproject.toml":
            # Parse pyproject.toml (basic support)
            import re
            content = file_path.read_text()

            # Find dependencies section
            deps_match = re.search(
                r'\[tool\.poetry\.dependencies\](.+?)(?:\[|$)',
                content,
                re.DOTALL
            )

            if deps_match:
                deps_section = deps_match.group(1)
                # Parse lines like: package = "^1.0.0"
                for line in deps_section.split('\n'):
                    match = re.match(r'([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"', line.strip())
                    if match:
                        name = match.group(1)
                        version_spec = match.group(2)

                        # Extract version number
                        version_match = re.search(r'[\d.]+', version_spec)
                        if version_match:
                            dependencies.append((name, version_match.group(0)))
                        else:
                            dependencies.append((name, None))

        return dependencies

    def _parse_npm_dependencies(
        self, file_path: Path
    ) -> List[Tuple[str, Optional[str]]]:
        """Parse NPM dependencies."""
        dependencies = []

        if file_path.name == "package.json":
            with open(file_path, "r") as f:
                data = json.load(f)

            # Combine dependencies and devDependencies
            all_deps = {}
            all_deps.update(data.get("dependencies", {}))
            all_deps.update(data.get("devDependencies", {}))

            for name, version_spec in all_deps.items():
                # Extract version number from npm version spec
                # Remove ^, ~, >=, etc.
                version = re.sub(r'[^0-9.]', '', version_spec)
                if version:
                    dependencies.append((name, version))
                else:
                    dependencies.append((name, None))

        elif file_path.name == "package-lock.json":
            with open(file_path, "r") as f:
                data = json.load(f)

            packages = data.get("packages", {})
            for package_path, package_info in packages.items():
                if not package_path:  # Skip root
                    continue

                name = package_info.get("name")
                if not name:
                    # Extract from path
                    name = package_path.split("/")[-1]

                version = package_info.get("version")
                if version:
                    dependencies.append((name, version))

        return dependencies

    def _parse_maven_dependencies(
        self, file_path: Path
    ) -> List[Tuple[str, Optional[str]]]:
        """Parse Maven dependencies from pom.xml."""
        dependencies = []

        content = file_path.read_text()

        # Basic XML parsing for dependencies
        # Format: <groupId>group</groupId><artifactId>artifact</artifactId><version>1.0</version>
        dep_blocks = re.findall(
            r'<dependency>(.+?)</dependency>',
            content,
            re.DOTALL
        )

        for block in dep_blocks:
            group_match = re.search(r'<groupId>(.+?)</groupId>', block)
            artifact_match = re.search(r'<artifactId>(.+?)</artifactId>', block)
            version_match = re.search(r'<version>(.+?)</version>', block)

            if group_match and artifact_match:
                # Maven packages are identified as groupId:artifactId
                name = f"{group_match.group(1)}:{artifact_match.group(1)}"
                version = version_match.group(1) if version_match else None

                dependencies.append((name, version))

        return dependencies

    def _query_osv_batch(
        self, dependencies: List[Tuple[str, Optional[str]]], ecosystem: str
    ) -> List[Dict[str, Any]]:
        """Query OSV API for vulnerabilities in batch.

        Args:
            dependencies: List of (package, version) tuples
            ecosystem: Package ecosystem

        Returns:
            List of vulnerability findings
        """
        if not dependencies:
            return []

        # Map ecosystem names to OSV ecosystem identifiers
        ecosystem_map = {
            "pip": "PyPI",
            "npm": "npm",
            "maven": "Maven",
            "gem": "RubyGems",
            "go": "Go",
            "cargo": "crates.io",
        }

        osv_ecosystem = ecosystem_map.get(ecosystem, ecosystem)

        # Build batch query
        queries = []
        for package, version in dependencies:
            query = {
                "package": {
                    "name": package,
                    "ecosystem": osv_ecosystem
                }
            }

            if version:
                query["version"] = version

            queries.append(query)

        # Query OSV API
        try:
            response = requests.post(
                self.OSV_BATCH_URL,
                json={"queries": queries},
                timeout=30
            )
            response.raise_for_status()
            results = response.json()
        except requests.RequestException as e:
            print(f"Warning: Failed to query OSV API: {e}")
            return []

        # Process results
        findings = []
        for i, result in enumerate(results.get("results", [])):
            package, version = dependencies[i]

            for vuln in result.get("vulns", []):
                finding = self._process_vulnerability(vuln, package, version)
                if finding:
                    findings.append(finding)

        return findings

    def _process_vulnerability(
        self, vuln: Dict[str, Any], package: str, version: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """Process a vulnerability from OSV response.

        Args:
            vuln: Vulnerability data from OSV
            package: Package name
            version: Package version

        Returns:
            Processed finding dictionary
        """
        vuln_id = vuln.get("id", "UNKNOWN")
        summary = vuln.get("summary", "No summary available")
        details = vuln.get("details", "")

        # Extract CVSS score if available
        cvss_score = None
        severity_str = None

        if "severity" in vuln:
            for severity_item in vuln["severity"]:
                if severity_item.get("type") == "CVSS_V3":
                    score_str = severity_item.get("score", "")
                    # Parse CVSS score (format: "CVSS:3.1/AV:N/AC:L/.../S:8.5")
                    score_match = re.search(r'S:(\d+\.?\d*)', score_str)
                    if score_match:
                        cvss_score = float(score_match.group(1))

        # Get database-specific severity
        if "database_specific" in vuln:
            severity_str = vuln["database_specific"].get("severity")

        # Calculate severity
        severity = calculate_severity(cvss_score, severity_str)

        # Extract affected versions and fixed versions
        affected_ranges = []
        fixed_versions = []

        for affected in vuln.get("affected", []):
            for range_info in affected.get("ranges", []):
                affected_ranges.append(range_info)

            fixed_versions.extend(affected.get("versions", []))

        # Get references
        references = [ref.get("url") for ref in vuln.get("references", [])]

        finding = {
            "type": "DEPENDENCY_VULNERABILITY",
            "id": vuln_id,
            "cve": vuln_id if vuln_id.startswith("CVE-") else None,
            "severity": severity.value,
            "package": package,
            "version": version or "unknown",
            "description": summary,
            "details": details,
            "cvss_score": cvss_score,
            "references": references[:3],  # Limit to first 3 references
            "fixed_versions": fixed_versions[:3] if fixed_versions else ["Update to latest version"],
        }

        return finding
