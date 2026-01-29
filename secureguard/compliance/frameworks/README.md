# Compliance Frameworks

This directory contains compliance framework definitions in YAML format.

## Available Frameworks

- **soc2.yaml** - SOC 2 Type II Trust Service Criteria (2017)
- **nist_csf.yaml** - NIST Cybersecurity Framework (v1.1)
- **pci_dss.yaml** - PCI DSS (Payment Card Industry Data Security Standard) - Coming soon
- **iso27001.yaml** - ISO 27001 Information Security Management - Coming soon

## Framework Structure

Each framework YAML file contains:

```yaml
framework:
  id: "FRAMEWORK_ID"
  name: "Framework Name"
  version: "1.0"
  description: "Framework description"

domains:
  - id: "DOMAIN_ID"
    name: "Domain Name"
    description: "Domain description"

    controls:
      - id: "CONTROL_ID"
        title: "Control Title"
        description: "Control description"
        category: "Category"
        severity: "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        priority: 1  # 1-5, 1 being highest

        requirements:
          - "Requirement 1"
          - "Requirement 2"

        mapped_checks:
          - check_id: "TF001"  # SecureGuard check ID
            scanner_type: "iac"  # deps, iac, runtime
            weight: 0.9  # 0.0-1.0

        evidence_requirements:
          - type: "configuration_scan"
            frequency: "weekly"
            description: "Evidence description"

        implementation_guidance: |
          Implementation guidance text
```

## Mapped Check IDs

### IaC Checks (Terraform)
- TF001: S3 Bucket Public Access
- TF002: S3 Bucket Encryption
- TF003: RDS Instance Encryption
- TF004: RDS Instance Public Access
- TF005: Security Group Unrestricted Ingress
- TF006: IAM Policy Overly Permissive
- TF007: CloudWatch Logging Disabled
- TF008: EBS Volume Encryption
- TF009: Load Balancer Access Logging
- TF010: Database Backup Disabled

### IaC Checks (CloudFormation)
- CF001: S3 Bucket Public Access
- CF002: S3 Bucket Encryption
- CF003: RDS Instance Encryption
- CF004: RDS Instance Public Access
- CF005: Security Group Unrestricted Access
- CF006: IAM Policy Wildcard Permissions
- CF007: CloudTrail Logging Disabled
- CF008: EBS Volume Encryption
- CF009: Lambda Function X-Ray Tracing
- CF010: API Gateway Logging

### Runtime Attack Detection
- SQL_INJECTION: SQL injection patterns
- XSS: Cross-site scripting patterns
- PATH_TRAVERSAL: Path traversal patterns
- COMMAND_INJECTION: Command injection patterns
- XXE: XML external entity patterns
- LDAP_INJECTION: LDAP injection patterns
- SSRF: Server-side request forgery patterns
- NOSQL_INJECTION: NoSQL injection patterns

### Dependency Scanning
- DEPENDENCY_VULNERABILITY: Known CVEs in dependencies

## Adding New Frameworks

To add a new compliance framework:

1. Create a new YAML file in this directory (e.g., `your_framework.yaml`)
2. Follow the structure shown above
3. Map controls to appropriate SecureGuard check IDs
4. Set appropriate weights (0.0-1.0) based on relevance
5. Document evidence requirements
6. Provide implementation guidance

## Control Mapping Guidelines

When mapping controls to checks:

- **Weight 1.0**: Check directly validates the control requirement
- **Weight 0.8-0.9**: Check strongly relates to the control
- **Weight 0.5-0.7**: Check partially relates to the control
- **Weight < 0.5**: Weak relationship, consider excluding

## Testing Frameworks

Test framework loading:

```python
from secureguard.compliance.core.framework import FrameworkLoader

loader = FrameworkLoader()
framework = loader.load("soc2")
print(f"Loaded: {framework.name}")
print(f"Controls: {framework.get_control_count()}")
```
