"""Fixer for Terraform security misconfigurations."""

import re
from typing import Dict, Any, List, Optional
from pathlib import Path

from secureguard.remediation.fixers.base import BaseFixer, Fix, FixStrategy


class TerraformFixer(BaseFixer):
    """Fixes Terraform security misconfigurations."""

    # Mapping of finding IDs to fix methods
    FIX_METHODS = {
        "TF001": "_fix_s3_public_access",
        "TF002": "_fix_s3_encryption",
        "TF003": "_fix_rds_encryption",
        "TF004": "_fix_rds_public_access",
        "TF005": "_fix_security_group_ingress",
        "TF006": "_fix_iam_policy_wildcards",
        "TF007": "_fix_cloudwatch_logging",
        "TF008": "_fix_ebs_encryption",
        "TF009": "_fix_lb_access_logging",
        "TF010": "_fix_database_backup",
    }

    def __init__(self, **kwargs):
        """Initialize Terraform fixer."""
        super().__init__(**kwargs)

    def can_fix(self, finding: Dict[str, Any]) -> bool:
        """Check if this is a Terraform finding.

        Args:
            finding: Security finding dictionary

        Returns:
            True if this is a fixable Terraform finding
        """
        finding_id = finding.get("id", "")
        return finding_id in self.FIX_METHODS

    def generate_fix(self, finding: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Optional[Fix]:
        """Generate fix for Terraform misconfiguration.

        Args:
            finding: Security finding
            context: Optional context with file content

        Returns:
            Fix object or None
        """
        finding_id = finding.get("id")
        fix_method_name = self.FIX_METHODS.get(finding_id)

        if not fix_method_name:
            return None

        file_path = finding.get("file")
        if not file_path:
            return None

        original_content = context.get("content") if context else self.get_file_content(file_path)
        resource_name = finding.get("resource")

        # Get the fix method
        fix_method = getattr(self, fix_method_name)

        # Apply the fix
        fixed_content = fix_method(original_content, resource_name, finding)

        if not fixed_content or fixed_content == original_content:
            return None

        return Fix(
            finding_id=finding_id,
            file_path=file_path,
            original_content=original_content,
            fixed_content=fixed_content,
            description=finding.get("remediation", f"Fix {finding_id}: {finding.get('title')}"),
            strategy=FixStrategy.RULE_BASED,
            confidence=0.85,
            metadata={
                "resource": resource_name,
                "finding_type": finding_id,
            }
        )

    def validate_fix(self, fix: Fix) -> tuple[bool, List[str]]:
        """Validate Terraform fix.

        Args:
            fix: The fix to validate

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Check that content changed
        if fix.original_content == fix.fixed_content:
            errors.append("Fix did not modify the file")

        # Basic syntax check - ensure resource block is still present
        resource_name = fix.metadata.get("resource")
        if resource_name and resource_name not in fix.fixed_content:
            errors.append(f"Resource '{resource_name}' not found in fixed content")

        # Check for balanced braces
        if fix.fixed_content.count("{") != fix.fixed_content.count("}"):
            errors.append("Unbalanced braces in Terraform file")

        return (len(errors) == 0, errors)

    def _fix_s3_public_access(self, content: str, resource: str, finding: Dict) -> str:
        """Fix S3 bucket public access.

        Changes:
        - Set acl = "private"
        - Remove public ACLs
        """
        # Find the resource block
        pattern = rf'(resource\s+"aws_s3_bucket"\s+"{resource}"\s*\{{[^}}]*?)'
        match = re.search(pattern, content, re.DOTALL)

        if not match:
            return content

        resource_block = match.group(1)

        # Replace public ACL with private
        fixed_block = re.sub(
            r'acl\s*=\s*"public-read.*?"',
            'acl = "private"',
            resource_block
        )

        # If no ACL specified, add private ACL
        if "acl" not in fixed_block:
            # Add before closing brace
            fixed_block = fixed_block.rstrip() + '\n  acl = "private"\n'

        return content.replace(resource_block, fixed_block)

    def _fix_s3_encryption(self, content: str, resource: str, finding: Dict) -> str:
        """Fix S3 bucket encryption.

        Adds server_side_encryption_configuration block.
        """
        pattern = rf'(resource\s+"aws_s3_bucket"\s+"{resource}"\s*\{{[^}}]*?)\}}'
        match = re.search(pattern, content, re.DOTALL)

        if not match:
            return content

        resource_block = match.group(1)

        # Check if encryption already exists
        if "server_side_encryption_configuration" in resource_block:
            return content

        # Add encryption configuration
        encryption_block = '''
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
'''

        fixed_block = resource_block + encryption_block + "}"

        return content.replace(match.group(0), fixed_block)

    def _fix_rds_encryption(self, content: str, resource: str, finding: Dict) -> str:
        """Fix RDS instance encryption.

        Adds storage_encrypted = true.
        """
        pattern = rf'(resource\s+"aws_db_instance"\s+"{resource}"\s*\{{[^}}]*?)'
        match = re.search(pattern, content, re.DOTALL)

        if not match:
            return content

        resource_block = match.group(1)

        # Check if already has encryption
        if "storage_encrypted" in resource_block:
            # Replace false with true
            fixed_block = re.sub(
                r'storage_encrypted\s*=\s*false',
                'storage_encrypted = true',
                resource_block
            )
        else:
            # Add encryption
            fixed_block = resource_block.rstrip() + '\n  storage_encrypted = true\n'

        return content.replace(resource_block, fixed_block)

    def _fix_rds_public_access(self, content: str, resource: str, finding: Dict) -> str:
        """Fix RDS public accessibility.

        Sets publicly_accessible = false.
        """
        pattern = rf'(resource\s+"aws_db_instance"\s+"{resource}"\s*\{{[^}}]*?)'
        match = re.search(pattern, content, re.DOTALL)

        if not match:
            return content

        resource_block = match.group(1)

        # Replace true with false
        if "publicly_accessible" in resource_block:
            fixed_block = re.sub(
                r'publicly_accessible\s*=\s*true',
                'publicly_accessible = false',
                resource_block
            )
        else:
            # Add publicly_accessible = false
            fixed_block = resource_block.rstrip() + '\n  publicly_accessible = false\n'

        return content.replace(resource_block, fixed_block)

    def _fix_security_group_ingress(self, content: str, resource: str, finding: Dict) -> str:
        """Fix unrestricted security group ingress.

        Restricts 0.0.0.0/0 to specific IP ranges.
        """
        pattern = rf'(resource\s+"aws_security_group"\s+"{resource}"\s*\{{.*?)\}}'
        match = re.search(pattern, content, re.DOTALL)

        if not match:
            return content

        resource_block = match.group(1)

        # Replace 0.0.0.0/0 with restricted range (example: office IP)
        # In production, this should be configurable
        fixed_block = resource_block.replace(
            '"0.0.0.0/0"',
            '"10.0.0.0/8"  # TODO: Replace with your specific IP range'
        )

        return content.replace(resource_block, fixed_block)

    def _fix_iam_policy_wildcards(self, content: str, resource: str, finding: Dict) -> str:
        """Fix overly permissive IAM policies.

        Adds comment warning about wildcards.
        """
        pattern = rf'(resource\s+"aws_iam_.*?"\s+"{resource}".*?policy\s*=.*?)"(\*)"'
        matches = list(re.finditer(pattern, content, re.DOTALL))

        if not matches:
            return content

        # Add comments warning about wildcards
        fixed_content = content
        for match in reversed(matches):  # Reverse to maintain positions
            warning = '# WARNING: Wildcard permissions - restrict to specific resources\n      "'
            fixed_content = fixed_content[:match.start(2)] + warning + "*" + fixed_content[match.end(2):]

        return fixed_content

    def _fix_cloudwatch_logging(self, content: str, resource: str, finding: Dict) -> str:
        """Enable CloudWatch logging.

        Adds logging configuration.
        """
        # This is a placeholder - actual implementation would depend on resource type
        # For now, add a comment
        pattern = rf'(resource\s+.*?"{resource}"\s*\{{)'
        match = re.search(pattern, content, re.DOTALL)

        if not match:
            return content

        comment = '\n  # TODO: Enable CloudWatch logging for this resource\n'
        return content.replace(match.group(1), match.group(1) + comment)

    def _fix_ebs_encryption(self, content: str, resource: str, finding: Dict) -> str:
        """Fix EBS volume encryption.

        Adds encrypted = true.
        """
        pattern = rf'(resource\s+"aws_ebs_volume"\s+"{resource}"\s*\{{[^}}]*?)'
        match = re.search(pattern, content, re.DOTALL)

        if not match:
            return content

        resource_block = match.group(1)

        if "encrypted" in resource_block:
            fixed_block = re.sub(
                r'encrypted\s*=\s*false',
                'encrypted = true',
                resource_block
            )
        else:
            fixed_block = resource_block.rstrip() + '\n  encrypted = true\n'

        return content.replace(resource_block, fixed_block)

    def _fix_lb_access_logging(self, content: str, resource: str, finding: Dict) -> str:
        """Enable load balancer access logging."""
        pattern = rf'(resource\s+"aws_.*?lb"\s+"{resource}"\s*\{{[^}}]*?)\}}'
        match = re.search(pattern, content, re.DOTALL)

        if not match:
            return content

        resource_block = match.group(1)

        if "access_logs" not in resource_block:
            logging_block = '''
  access_logs {
    enabled = true
    bucket  = "my-lb-logs"  # TODO: Replace with your S3 bucket
  }
'''
            fixed_block = resource_block + logging_block + "}"
            return content.replace(match.group(0), fixed_block)

        return content

    def _fix_database_backup(self, content: str, resource: str, finding: Dict) -> str:
        """Enable database backups."""
        pattern = rf'(resource\s+"aws_db_instance"\s+"{resource}"\s*\{{[^}}]*?)'
        match = re.search(pattern, content, re.DOTALL)

        if not match:
            return content

        resource_block = match.group(1)

        # Enable backups
        if "backup_retention_period" not in resource_block:
            fixed_block = resource_block.rstrip() + '\n  backup_retention_period = 7\n'
        else:
            fixed_block = re.sub(
                r'backup_retention_period\s*=\s*0',
                'backup_retention_period = 7',
                resource_block
            )

        return content.replace(resource_block, fixed_block)
