"""Terraform security analyzer."""

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from secureguard.utils.severity import Severity


class TerraformAnalyzer:
    """Analyzes Terraform files for security misconfigurations."""

    def __init__(self, severity_threshold: Optional[Severity] = None):
        """Initialize analyzer.

        Args:
            severity_threshold: Only report findings at or above this severity
        """
        self.severity_threshold = severity_threshold or Severity.INFO
        self.rules = self._load_rules()

    def analyze_directory(self, directory_path: str) -> List[Dict[str, Any]]:
        """Analyze all Terraform files in a directory.

        Args:
            directory_path: Path to directory containing Terraform files

        Returns:
            List of security findings
        """
        path = Path(directory_path)

        if not path.exists():
            raise FileNotFoundError(f"Directory not found: {directory_path}")

        # Find all .tf and .tf.json files
        tf_files = list(path.rglob("*.tf")) + list(path.rglob("*.tf.json"))

        all_findings = []
        for tf_file in tf_files:
            findings = self.analyze_file(str(tf_file))
            all_findings.extend(findings)

        return all_findings

    def analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Analyze a single Terraform file.

        Args:
            file_path: Path to Terraform file

        Returns:
            List of security findings
        """
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        content = path.read_text()

        # Parse Terraform based on file type
        if path.suffix == ".json":
            resources = self._parse_tf_json(content)
        else:
            resources = self._parse_tf_hcl(content)

        # Run security rules
        findings = []
        for resource in resources:
            for rule in self.rules:
                finding = rule["check"](resource, str(path))
                if finding and Severity(finding["severity"]) >= self.severity_threshold:
                    findings.append(finding)

        return findings

    def _parse_tf_json(self, content: str) -> List[Dict[str, Any]]:
        """Parse Terraform JSON format."""
        resources = []

        try:
            data = json.loads(content)

            for resource_type, resource_blocks in data.get("resource", {}).items():
                for resource_name, resource_config in resource_blocks.items():
                    resources.append({
                        "type": resource_type,
                        "name": resource_name,
                        "config": resource_config
                    })

        except json.JSONDecodeError:
            pass

        return resources

    def _parse_tf_hcl(self, content: str) -> List[Dict[str, Any]]:
        """Parse Terraform HCL format (basic parsing)."""
        resources = []

        # Basic HCL parsing - find resource blocks
        # Format: resource "type" "name" { ... }
        pattern = r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}'

        for match in re.finditer(pattern, content, re.DOTALL):
            resource_type = match.group(1)
            resource_name = match.group(2)
            resource_body = match.group(3)

            # Parse basic key-value pairs
            config = {}
            for line in resource_body.split('\n'):
                kv_match = re.match(r'\s*(\w+)\s*=\s*(.+)', line.strip())
                if kv_match:
                    key = kv_match.group(1)
                    value = kv_match.group(2).strip().strip('"')

                    # Convert booleans
                    if value.lower() == "true":
                        value = True
                    elif value.lower() == "false":
                        value = False

                    config[key] = value

            resources.append({
                "type": resource_type,
                "name": resource_name,
                "config": config,
                "raw": resource_body
            })

        return resources

    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load security rules for Terraform."""
        return [
            {
                "id": "TF001",
                "name": "S3 Bucket Public Access",
                "check": self._check_s3_public_access
            },
            {
                "id": "TF002",
                "name": "S3 Bucket Encryption",
                "check": self._check_s3_encryption
            },
            {
                "id": "TF003",
                "name": "RDS Instance Encryption",
                "check": self._check_rds_encryption
            },
            {
                "id": "TF004",
                "name": "RDS Instance Public Access",
                "check": self._check_rds_public_access
            },
            {
                "id": "TF005",
                "name": "Security Group Unrestricted Ingress",
                "check": self._check_sg_unrestricted_ingress
            },
            {
                "id": "TF006",
                "name": "IAM Policy Overly Permissive",
                "check": self._check_iam_wildcard
            },
            {
                "id": "TF007",
                "name": "CloudWatch Logging Disabled",
                "check": self._check_cloudwatch_logging
            },
            {
                "id": "TF008",
                "name": "EBS Volume Encryption",
                "check": self._check_ebs_encryption
            },
            {
                "id": "TF009",
                "name": "ALB/ELB Access Logging",
                "check": self._check_lb_logging
            },
            {
                "id": "TF010",
                "name": "Database Backup Disabled",
                "check": self._check_db_backup
            },
        ]

    def _check_s3_public_access(
        self, resource: Dict[str, Any], file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Check for publicly accessible S3 buckets."""
        if resource["type"] != "aws_s3_bucket":
            return None

        config = resource["config"]

        # Check ACL
        acl = config.get("acl", "")
        if acl in ["public-read", "public-read-write"]:
            return {
                "type": "IAC_MISCONFIGURATION",
                "id": "TF001",
                "severity": Severity.CRITICAL.value,
                "resource": f"{resource['type']}.{resource['name']}",
                "file": file_path,
                "description": f"S3 bucket '{resource['name']}' has public ACL '{acl}'",
                "remediation": "Change ACL to 'private' or use bucket policies for granular access",
            }

        return None

    def _check_s3_encryption(
        self, resource: Dict[str, Any], file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Check for S3 bucket encryption."""
        if resource["type"] != "aws_s3_bucket":
            return None

        config = resource["config"]
        raw = resource.get("raw", "")

        # Check for server_side_encryption_configuration
        has_encryption = "server_side_encryption_configuration" in raw

        if not has_encryption:
            return {
                "type": "IAC_MISCONFIGURATION",
                "id": "TF002",
                "severity": Severity.HIGH.value,
                "resource": f"{resource['type']}.{resource['name']}",
                "file": file_path,
                "description": f"S3 bucket '{resource['name']}' does not have encryption enabled",
                "remediation": "Enable server-side encryption (SSE-S3 or SSE-KMS)",
            }

        return None

    def _check_rds_encryption(
        self, resource: Dict[str, Any], file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Check for RDS instance encryption."""
        if resource["type"] not in ["aws_db_instance", "aws_rds_cluster"]:
            return None

        config = resource["config"]
        storage_encrypted = config.get("storage_encrypted", False)

        if not storage_encrypted:
            return {
                "type": "IAC_MISCONFIGURATION",
                "id": "TF003",
                "severity": Severity.HIGH.value,
                "resource": f"{resource['type']}.{resource['name']}",
                "file": file_path,
                "description": f"RDS instance '{resource['name']}' does not have storage encryption enabled",
                "remediation": "Set storage_encrypted = true",
            }

        return None

    def _check_rds_public_access(
        self, resource: Dict[str, Any], file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Check for publicly accessible RDS instances."""
        if resource["type"] != "aws_db_instance":
            return None

        config = resource["config"]
        publicly_accessible = config.get("publicly_accessible", False)

        if publicly_accessible:
            return {
                "type": "IAC_MISCONFIGURATION",
                "id": "TF004",
                "severity": Severity.CRITICAL.value,
                "resource": f"{resource['type']}.{resource['name']}",
                "file": file_path,
                "description": f"RDS instance '{resource['name']}' is publicly accessible",
                "remediation": "Set publicly_accessible = false",
            }

        return None

    def _check_sg_unrestricted_ingress(
        self, resource: Dict[str, Any], file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Check for security groups with unrestricted ingress."""
        if resource["type"] != "aws_security_group":
            return None

        raw = resource.get("raw", "")

        # Check for 0.0.0.0/0 in ingress rules
        if "0.0.0.0/0" in raw and "ingress" in raw:
            return {
                "type": "IAC_MISCONFIGURATION",
                "id": "TF005",
                "severity": Severity.HIGH.value,
                "resource": f"{resource['type']}.{resource['name']}",
                "file": file_path,
                "description": f"Security group '{resource['name']}' allows unrestricted ingress (0.0.0.0/0)",
                "remediation": "Restrict ingress to specific IP ranges or security groups",
            }

        return None

    def _check_iam_wildcard(
        self, resource: Dict[str, Any], file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Check for overly permissive IAM policies."""
        if resource["type"] not in ["aws_iam_policy", "aws_iam_role_policy"]:
            return None

        raw = resource.get("raw", "")

        # Check for wildcard actions or resources
        has_wildcard_action = '"Action": "*"' in raw or '"Action":"*"' in raw
        has_wildcard_resource = '"Resource": "*"' in raw or '"Resource":"*"' in raw

        if has_wildcard_action and has_wildcard_resource:
            return {
                "type": "IAC_MISCONFIGURATION",
                "id": "TF006",
                "severity": Severity.HIGH.value,
                "resource": f"{resource['type']}.{resource['name']}",
                "file": file_path,
                "description": f"IAM policy '{resource['name']}' uses wildcard for both Action and Resource",
                "remediation": "Follow principle of least privilege - specify explicit actions and resources",
            }

        return None

    def _check_cloudwatch_logging(
        self, resource: Dict[str, Any], file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Check for CloudWatch logging configuration."""
        loggable_types = [
            "aws_lambda_function",
            "aws_api_gateway_stage",
            "aws_cloudtrail"
        ]

        if resource["type"] not in loggable_types:
            return None

        raw = resource.get("raw", "")

        # Check for logging configuration
        has_logging = any([
            "cloudwatch" in raw.lower(),
            "log_group" in raw,
            "logging" in raw
        ])

        if not has_logging:
            return {
                "type": "IAC_MISCONFIGURATION",
                "id": "TF007",
                "severity": Severity.MEDIUM.value,
                "resource": f"{resource['type']}.{resource['name']}",
                "file": file_path,
                "description": f"Resource '{resource['name']}' does not have CloudWatch logging enabled",
                "remediation": "Enable CloudWatch logging for security monitoring and audit trails",
            }

        return None

    def _check_ebs_encryption(
        self, resource: Dict[str, Any], file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Check for EBS volume encryption."""
        if resource["type"] != "aws_ebs_volume":
            return None

        config = resource["config"]
        encrypted = config.get("encrypted", False)

        if not encrypted:
            return {
                "type": "IAC_MISCONFIGURATION",
                "id": "TF008",
                "severity": Severity.HIGH.value,
                "resource": f"{resource['type']}.{resource['name']}",
                "file": file_path,
                "description": f"EBS volume '{resource['name']}' is not encrypted",
                "remediation": "Set encrypted = true",
            }

        return None

    def _check_lb_logging(
        self, resource: Dict[str, Any], file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Check for load balancer access logging."""
        if resource["type"] not in ["aws_lb", "aws_elb", "aws_alb"]:
            return None

        raw = resource.get("raw", "")

        # Check for access_logs configuration
        has_logging = "access_logs" in raw

        if not has_logging:
            return {
                "type": "IAC_MISCONFIGURATION",
                "id": "TF009",
                "severity": Severity.MEDIUM.value,
                "resource": f"{resource['type']}.{resource['name']}",
                "file": file_path,
                "description": f"Load balancer '{resource['name']}' does not have access logging enabled",
                "remediation": "Enable access logs for security monitoring",
            }

        return None

    def _check_db_backup(
        self, resource: Dict[str, Any], file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Check for database backup configuration."""
        if resource["type"] != "aws_db_instance":
            return None

        config = resource["config"]
        backup_retention = config.get("backup_retention_period", 0)

        try:
            backup_retention = int(backup_retention)
        except (ValueError, TypeError):
            backup_retention = 0

        if backup_retention == 0:
            return {
                "type": "IAC_MISCONFIGURATION",
                "id": "TF010",
                "severity": Severity.MEDIUM.value,
                "resource": f"{resource['type']}.{resource['name']}",
                "file": file_path,
                "description": f"RDS instance '{resource['name']}' has no backup retention configured",
                "remediation": "Set backup_retention_period to at least 7 days",
            }

        return None
