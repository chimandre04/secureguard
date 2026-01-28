"""CloudFormation security analyzer."""

import json
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional

from secureguard.utils.severity import Severity


class CloudFormationAnalyzer:
    """Analyzes CloudFormation templates for security misconfigurations."""

    def __init__(self, severity_threshold: Optional[Severity] = None):
        """Initialize analyzer.

        Args:
            severity_threshold: Only report findings at or above this severity
        """
        self.severity_threshold = severity_threshold or Severity.INFO
        self.rules = self._load_rules()

    def analyze_directory(self, directory_path: str) -> List[Dict[str, Any]]:
        """Analyze all CloudFormation templates in a directory.

        Args:
            directory_path: Path to directory containing CloudFormation templates

        Returns:
            List of security findings
        """
        path = Path(directory_path)

        if not path.exists():
            raise FileNotFoundError(f"Directory not found: {directory_path}")

        # Find CloudFormation templates (.yaml, .yml, .json)
        cf_files = (
            list(path.rglob("*.yaml")) +
            list(path.rglob("*.yml")) +
            list(path.rglob("*.json"))
        )

        all_findings = []
        for cf_file in cf_files:
            try:
                findings = self.analyze_file(str(cf_file))
                all_findings.extend(findings)
            except Exception:
                # Skip files that aren't CloudFormation templates
                continue

        return all_findings

    def analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Analyze a single CloudFormation template.

        Args:
            file_path: Path to CloudFormation template

        Returns:
            List of security findings
        """
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        content = path.read_text()

        # Parse template
        template = self._parse_template(content, path.suffix)

        # Verify it's a CloudFormation template
        if not template or "Resources" not in template:
            return []

        # Extract resources
        resources = []
        for resource_name, resource_config in template["Resources"].items():
            resources.append({
                "name": resource_name,
                "type": resource_config.get("Type", ""),
                "properties": resource_config.get("Properties", {}),
                "raw": resource_config
            })

        # Run security rules
        findings = []
        for resource in resources:
            for rule in self.rules:
                finding = rule["check"](resource, str(path))
                if finding and Severity(finding["severity"]) >= self.severity_threshold:
                    findings.append(finding)

        return findings

    def _parse_template(
        self, content: str, file_extension: str
    ) -> Optional[Dict[str, Any]]:
        """Parse CloudFormation template."""
        try:
            if file_extension == ".json":
                return json.loads(content)
            else:
                return yaml.safe_load(content)
        except Exception:
            return None

    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load security rules for CloudFormation."""
        return [
            {
                "id": "CF001",
                "name": "S3 Bucket Public Access",
                "check": self._check_s3_public_access
            },
            {
                "id": "CF002",
                "name": "S3 Bucket Encryption",
                "check": self._check_s3_encryption
            },
            {
                "id": "CF003",
                "name": "RDS Instance Encryption",
                "check": self._check_rds_encryption
            },
            {
                "id": "CF004",
                "name": "RDS Instance Public Access",
                "check": self._check_rds_public_access
            },
            {
                "id": "CF005",
                "name": "Security Group Unrestricted Access",
                "check": self._check_sg_unrestricted
            },
            {
                "id": "CF006",
                "name": "IAM Policy Wildcard Permissions",
                "check": self._check_iam_wildcard
            },
            {
                "id": "CF007",
                "name": "CloudTrail Logging",
                "check": self._check_cloudtrail
            },
            {
                "id": "CF008",
                "name": "EBS Volume Encryption",
                "check": self._check_ebs_encryption
            },
            {
                "id": "CF009",
                "name": "Lambda Function Tracing",
                "check": self._check_lambda_tracing
            },
            {
                "id": "CF010",
                "name": "API Gateway Logging",
                "check": self._check_apigateway_logging
            },
        ]

    def _check_s3_public_access(
        self, resource: Dict[str, Any], file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Check for publicly accessible S3 buckets."""
        if resource["type"] != "AWS::S3::Bucket":
            return None

        properties = resource["properties"]

        # Check PublicAccessBlockConfiguration
        public_access_config = properties.get("PublicAccessBlockConfiguration", {})
        block_public_acls = public_access_config.get("BlockPublicAcls", False)
        block_public_policy = public_access_config.get("BlockPublicPolicy", False)

        # Check AccessControl
        access_control = properties.get("AccessControl", "")

        if access_control in ["PublicRead", "PublicReadWrite"]:
            return {
                "type": "IAC_MISCONFIGURATION",
                "id": "CF001",
                "severity": Severity.CRITICAL.value,
                "resource": f"{resource['type']}.{resource['name']}",
                "file": file_path,
                "description": f"S3 bucket '{resource['name']}' has public access control '{access_control}'",
                "remediation": "Set AccessControl to 'Private' and configure PublicAccessBlockConfiguration",
            }

        if not (block_public_acls and block_public_policy):
            return {
                "type": "IAC_MISCONFIGURATION",
                "id": "CF001",
                "severity": Severity.HIGH.value,
                "resource": f"{resource['type']}.{resource['name']}",
                "file": file_path,
                "description": f"S3 bucket '{resource['name']}' does not block all public access",
                "remediation": "Enable all PublicAccessBlockConfiguration settings",
            }

        return None

    def _check_s3_encryption(
        self, resource: Dict[str, Any], file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Check for S3 bucket encryption."""
        if resource["type"] != "AWS::S3::Bucket":
            return None

        properties = resource["properties"]
        has_encryption = "BucketEncryption" in properties

        if not has_encryption:
            return {
                "type": "IAC_MISCONFIGURATION",
                "id": "CF002",
                "severity": Severity.HIGH.value,
                "resource": f"{resource['type']}.{resource['name']}",
                "file": file_path,
                "description": f"S3 bucket '{resource['name']}' does not have encryption configured",
                "remediation": "Configure BucketEncryption with SSE-S3 or SSE-KMS",
            }

        return None

    def _check_rds_encryption(
        self, resource: Dict[str, Any], file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Check for RDS instance encryption."""
        if resource["type"] not in ["AWS::RDS::DBInstance", "AWS::RDS::DBCluster"]:
            return None

        properties = resource["properties"]
        storage_encrypted = properties.get("StorageEncrypted", False)

        if not storage_encrypted:
            return {
                "type": "IAC_MISCONFIGURATION",
                "id": "CF003",
                "severity": Severity.HIGH.value,
                "resource": f"{resource['type']}.{resource['name']}",
                "file": file_path,
                "description": f"RDS instance '{resource['name']}' does not have storage encryption enabled",
                "remediation": "Set StorageEncrypted: true",
            }

        return None

    def _check_rds_public_access(
        self, resource: Dict[str, Any], file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Check for publicly accessible RDS instances."""
        if resource["type"] != "AWS::RDS::DBInstance":
            return None

        properties = resource["properties"]
        publicly_accessible = properties.get("PubliclyAccessible", False)

        if publicly_accessible:
            return {
                "type": "IAC_MISCONFIGURATION",
                "id": "CF004",
                "severity": Severity.CRITICAL.value,
                "resource": f"{resource['type']}.{resource['name']}",
                "file": file_path,
                "description": f"RDS instance '{resource['name']}' is publicly accessible",
                "remediation": "Set PubliclyAccessible: false",
            }

        return None

    def _check_sg_unrestricted(
        self, resource: Dict[str, Any], file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Check for security groups with unrestricted access."""
        if resource["type"] != "AWS::EC2::SecurityGroup":
            return None

        properties = resource["properties"]
        ingress_rules = properties.get("SecurityGroupIngress", [])

        for rule in ingress_rules:
            cidr = rule.get("CidrIp", "")
            if cidr == "0.0.0.0/0":
                from_port = rule.get("FromPort", "")
                to_port = rule.get("ToPort", "")

                return {
                    "type": "IAC_MISCONFIGURATION",
                    "id": "CF005",
                    "severity": Severity.HIGH.value,
                    "resource": f"{resource['type']}.{resource['name']}",
                    "file": file_path,
                    "description": f"Security group '{resource['name']}' allows unrestricted ingress from 0.0.0.0/0 on ports {from_port}-{to_port}",
                    "remediation": "Restrict ingress to specific IP ranges",
                }

        return None

    def _check_iam_wildcard(
        self, resource: Dict[str, Any], file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Check for overly permissive IAM policies."""
        if resource["type"] not in ["AWS::IAM::Policy", "AWS::IAM::Role", "AWS::IAM::ManagedPolicy"]:
            return None

        properties = resource["properties"]

        # Check PolicyDocument
        policy_doc = properties.get("PolicyDocument", {})
        if isinstance(policy_doc, dict):
            statements = policy_doc.get("Statement", [])

            for statement in statements:
                if isinstance(statement, dict):
                    action = statement.get("Action", [])
                    resource_val = statement.get("Resource", [])

                    # Convert to list for uniform checking
                    if isinstance(action, str):
                        action = [action]
                    if isinstance(resource_val, str):
                        resource_val = [resource_val]

                    has_wildcard_action = "*" in action
                    has_wildcard_resource = "*" in resource_val

                    if has_wildcard_action and has_wildcard_resource:
                        return {
                            "type": "IAC_MISCONFIGURATION",
                            "id": "CF006",
                            "severity": Severity.HIGH.value,
                            "resource": f"{resource['type']}.{resource['name']}",
                            "file": file_path,
                            "description": f"IAM resource '{resource['name']}' has wildcard permissions for both Action and Resource",
                            "remediation": "Follow principle of least privilege - specify explicit actions and resources",
                        }

        return None

    def _check_cloudtrail(
        self, resource: Dict[str, Any], file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Check for CloudTrail configuration."""
        if resource["type"] != "AWS::CloudTrail::Trail":
            return None

        properties = resource["properties"]
        is_logging = properties.get("IsLogging", True)

        if not is_logging:
            return {
                "type": "IAC_MISCONFIGURATION",
                "id": "CF007",
                "severity": Severity.HIGH.value,
                "resource": f"{resource['type']}.{resource['name']}",
                "file": file_path,
                "description": f"CloudTrail '{resource['name']}' has logging disabled",
                "remediation": "Set IsLogging: true",
            }

        return None

    def _check_ebs_encryption(
        self, resource: Dict[str, Any], file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Check for EBS volume encryption."""
        if resource["type"] != "AWS::EC2::Volume":
            return None

        properties = resource["properties"]
        encrypted = properties.get("Encrypted", False)

        if not encrypted:
            return {
                "type": "IAC_MISCONFIGURATION",
                "id": "CF008",
                "severity": Severity.HIGH.value,
                "resource": f"{resource['type']}.{resource['name']}",
                "file": file_path,
                "description": f"EBS volume '{resource['name']}' is not encrypted",
                "remediation": "Set Encrypted: true",
            }

        return None

    def _check_lambda_tracing(
        self, resource: Dict[str, Any], file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Check for Lambda function tracing."""
        if resource["type"] != "AWS::Lambda::Function":
            return None

        properties = resource["properties"]
        tracing_config = properties.get("TracingConfig", {})
        mode = tracing_config.get("Mode", "PassThrough")

        if mode == "PassThrough":
            return {
                "type": "IAC_MISCONFIGURATION",
                "id": "CF009",
                "severity": Severity.LOW.value,
                "resource": f"{resource['type']}.{resource['name']}",
                "file": file_path,
                "description": f"Lambda function '{resource['name']}' does not have active X-Ray tracing",
                "remediation": "Set TracingConfig.Mode to 'Active' for better observability",
            }

        return None

    def _check_apigateway_logging(
        self, resource: Dict[str, Any], file_path: str
    ) -> Optional[Dict[str, Any]]:
        """Check for API Gateway logging."""
        if resource["type"] != "AWS::ApiGateway::Stage":
            return None

        properties = resource["properties"]
        method_settings = properties.get("MethodSettings", [])

        has_logging = False
        for setting in method_settings:
            if isinstance(setting, dict):
                logging_level = setting.get("LoggingLevel", "OFF")
                if logging_level != "OFF":
                    has_logging = True
                    break

        if not has_logging:
            return {
                "type": "IAC_MISCONFIGURATION",
                "id": "CF010",
                "severity": Severity.MEDIUM.value,
                "resource": f"{resource['type']}.{resource['name']}",
                "file": file_path,
                "description": f"API Gateway stage '{resource['name']}' does not have logging enabled",
                "remediation": "Enable CloudWatch logging in MethodSettings",
            }

        return None
