# SecureGuard Compliance Automation

SecureGuard now includes comprehensive compliance automation capabilities to help you assess and maintain compliance with various security frameworks including SOC 2, NIST CSF, PCI DSS, ISO 27001, and others.

## Overview

The compliance automation system:
- **Maps security findings to compliance controls** automatically
- **Performs gap analysis** to identify compliance gaps
- **Generates audit-ready reports** in multiple formats (HTML, JSON, PDF, Excel)
- **Supports Policy-as-Code** for customizable compliance policies
- **Provides evidence collection** for audit trails
- **Integrates with CI/CD** pipelines for continuous compliance monitoring

## Architecture

### Core Components

```
secureguard/compliance/
├── core/
│   ├── framework.py       # Framework data models and loader
│   ├── control.py         # Control and domain definitions
│   ├── evidence.py        # Evidence and audit trail models
│   ├── mapper.py          # Finding-to-control mapper
│   ├── gap_analyzer.py    # Gap analysis engine
│   └── policy.py          # Policy-as-code parser
├── frameworks/            # Framework definitions (YAML)
│   ├── soc2.yaml         # SOC 2 Type II
│   ├── nist_csf.yaml     # NIST Cybersecurity Framework
│   ├── pci_dss.yaml      # PCI DSS (coming soon)
│   └── iso27001.yaml     # ISO 27001 (coming soon)
├── reports/               # Report generators
│   ├── base.py           # Base generator interface
│   ├── html_generator.py # HTML reports
│   ├── json_generator.py # JSON reports
│   ├── pdf_generator.py  # PDF reports (coming soon)
│   └── excel_generator.py # Excel reports (coming soon)
└── cli_commands.py        # CLI command implementations
```

## Quick Start

### Installation

```bash
# Install SecureGuard
cd /Users/andrechim/secureguard
pip install -e .

# Install optional compliance dependencies
pip install jinja2>=3.1.0
```

### Basic Usage

1. **List available frameworks**:
   ```bash
   secureguard compliance frameworks
   ```

2. **Show framework details**:
   ```bash
   secureguard compliance show-framework --id soc2
   ```

3. **Run compliance scan**:
   ```bash
   # First, generate security findings
   secureguard scan iac --path ./terraform --format json --output findings.json

   # Then run compliance scan
   secureguard compliance scan \
     --framework soc2 \
     --findings findings.json \
     --format html \
     --output compliance-report.html
   ```

4. **Analyze gaps**:
   ```bash
   secureguard compliance gaps \
     --framework soc2 \
     --findings findings.json \
     --status non_compliant
   ```

5. **Map findings to controls**:
   ```bash
   secureguard compliance map \
     --findings findings.json \
     --framework soc2
   ```

## Supported Frameworks

### Currently Available

#### SOC 2 Type II (2017)
- 15 controls across 5 trust service categories
- Common Criteria (CC)
- Availability (A)
- Confidentiality (C)
- Privacy (P)
- Secure Development (SDLC)

**Key Controls**:
- CC6.1: Logical and Physical Access Controls
- CC6.6: Encryption
- CC7.1: System Monitoring
- CC7.2: Security Incident Detection
- SDLC1.1: Dependency Vulnerability Management

#### NIST Cybersecurity Framework (v1.1)
- 13 controls across 5 core functions
- Identify (ID)
- Protect (PR)
- Detect (DE)
- Respond (RS)
- Recover (RC)

**Key Controls**:
- PR.AC-4: Access Permissions Management
- PR.DS-1: Data-at-Rest Protection
- DE.CM-8: Vulnerability Scans
- RC.RP-1: Recovery Plan Execution

### Coming Soon
- PCI DSS (Payment Card Industry Data Security Standard)
- ISO 27001 (Information Security Management)
- COSO (Enterprise Risk Management)
- COBIT (IT Governance)
- RBI Regulations (Reserve Bank of India)
- SOX (Sarbanes-Oxley Act)
- SSAE16/ISAE3402 (Audit Standards)

## Control Mapping

### How Mapping Works

Each security check in SecureGuard is mapped to one or more compliance controls:

```yaml
# Example from soc2.yaml
controls:
  - id: "CC6.1"
    title: "Logical and Physical Access Controls"
    mapped_checks:
      - check_id: "TF001"  # S3 Bucket Public Access
        scanner_type: "iac"
        weight: 0.9        # High relevance

      - check_id: "CF001"  # CloudFormation S3 Public Access
        scanner_type: "iac"
        weight: 0.9
```

### Supported Security Checks

**Infrastructure as Code (IaC)**:
- TF001-TF010: Terraform security checks
- CF001-CF010: CloudFormation security checks

**Runtime Security**:
- SQL_INJECTION: SQL injection patterns
- XSS: Cross-site scripting patterns
- COMMAND_INJECTION: Command injection patterns
- SSRF: Server-side request forgery
- PATH_TRAVERSAL: Path traversal attacks

**Dependency Scanning**:
- DEPENDENCY_VULNERABILITY: Known CVEs in dependencies

## Gap Analysis

### How It Works

1. **Load Framework**: Load the compliance framework with all controls
2. **Map Findings**: Map security findings to relevant controls
3. **Calculate Coverage**: For each control, calculate coverage percentage
4. **Determine Status**: Assign status based on coverage:
   - **Compliant**: ≥95% coverage
   - **Partial**: 50-95% coverage
   - **Non-Compliant**: <50% coverage
   - **Not Tested**: No automated checks available
5. **Calculate Score**: Compute weighted overall score
6. **Generate Report**: Create audit-ready report with recommendations

### Coverage Calculation

```python
coverage = (passing_checks_weight / total_checks_weight) * 100

# Example:
# Control has 3 mapped checks with weights: 1.0, 0.9, 0.8
# Total weight = 2.7
# If check 1 (weight 1.0) has findings (fails):
# Passing weight = 0.9 + 0.8 = 1.7
# Coverage = (1.7 / 2.7) * 100 = 62.96% → Partial compliance
```

## Report Formats

### HTML Report
Professional, audit-ready HTML report with:
- Executive summary
- Compliance score visualization
- Summary statistics
- Control status dashboard
- Gap analysis with recommendations
- Detailed findings per control

### JSON Report
Machine-readable format for:
- Programmatic analysis
- CI/CD integration
- Custom dashboards
- SIEM integration

### PDF Report (Coming Soon)
Print-ready format for:
- Audit submissions
- Management review
- Compliance documentation

### Excel Report (Coming Soon)
Spreadsheet format for:
- Data analysis
- Control tracking
- Custom reporting

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Compliance Check
on: [push, pull_request]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install SecureGuard
        run: pip install secureguard

      - name: Scan Infrastructure
        run: |
          secureguard scan iac --path . --format json --output findings.json

      - name: SOC 2 Compliance Check
        run: |
          secureguard compliance scan \
            --framework soc2 \
            --findings findings.json \
            --format json \
            --output compliance.json

      - name: Verify Compliance Score
        run: |
          SCORE=$(jq '.overall_score' compliance.json)
          if (( $(echo "$SCORE < 80" | bc -l) )); then
            echo "❌ Compliance score too low: $SCORE%"
            exit 1
          else
            echo "✅ Compliance score: $SCORE%"
          fi

      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: compliance-report
          path: compliance.json
```

## CLI Reference

### Commands

#### `secureguard compliance frameworks`
List all available compliance frameworks.

#### `secureguard compliance show-framework --id <framework_id>`
Show detailed information about a specific framework.

**Options**:
- `--id, -i`: Framework ID (required)

#### `secureguard compliance scan`
Run compliance assessment against security findings.

**Options**:
- `--framework, -f`: Compliance framework (required)
- `--findings, -F`: Path to findings JSON file (required)
- `--format, -o`: Output format (html, json) - default: html
- `--output, -O`: Output file path

**Example**:
```bash
secureguard compliance scan \
  --framework soc2 \
  --findings findings.json \
  --format html \
  --output report.html
```

#### `secureguard compliance gaps`
Analyze compliance gaps and show detailed results.

**Options**:
- `--framework, -f`: Compliance framework (required)
- `--findings, -F`: Path to findings JSON file (required)
- `--format, -o`: Output format (table, json) - default: table
- `--severity, -s`: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- `--status`: Filter by status (compliant, partial, non_compliant, not_tested)

**Example**:
```bash
secureguard compliance gaps \
  --framework soc2 \
  --findings findings.json \
  --status non_compliant
```

#### `secureguard compliance map`
Map security findings to compliance controls.

**Options**:
- `--findings, -F`: Path to findings JSON file (required)
- `--framework, -f`: Compliance framework (required)

**Example**:
```bash
secureguard compliance map \
  --findings findings.json \
  --framework soc2
```

## Example Workflow

### 1. Scan Your Infrastructure

```bash
# Scan Terraform infrastructure
secureguard scan iac --path ./terraform --format json --output tf-findings.json

# Scan dependencies
secureguard scan deps --file requirements.txt --format json --output dep-findings.json

# Combine findings (manual or scripted)
jq -s '.[0].findings + .[1].findings | {findings: .}' \
  tf-findings.json dep-findings.json > all-findings.json
```

### 2. Run Compliance Assessment

```bash
# SOC 2 compliance
secureguard compliance scan \
  --framework soc2 \
  --findings all-findings.json \
  --format html \
  --output soc2-report.html

# NIST CSF compliance
secureguard compliance scan \
  --framework nist_csf \
  --findings all-findings.json \
  --format html \
  --output nist-report.html
```

### 3. Review and Remediate

```bash
# View non-compliant controls
secureguard compliance gaps \
  --framework soc2 \
  --findings all-findings.json \
  --status non_compliant

# See control mapping details
secureguard compliance map \
  --findings all-findings.json \
  --framework soc2
```

### 4. Track Progress

```bash
# Re-scan after remediation
secureguard scan iac --path ./terraform --format json --output findings-v2.json

# Generate updated compliance report
secureguard compliance scan \
  --framework soc2 \
  --findings findings-v2.json \
  --format html \
  --output soc2-report-v2.html

# Compare scores
# (manual comparison or build a tracking dashboard)
```

## Adding Custom Frameworks

You can add your own compliance frameworks by creating YAML files in the `secureguard/compliance/frameworks/` directory.

### Framework YAML Structure

```yaml
framework:
  id: "CUSTOM_FRAMEWORK"
  name: "Custom Framework Name"
  version: "1.0"
  description: "Framework description"

domains:
  - id: "DOMAIN_1"
    name: "Domain Name"
    description: "Domain description"

    controls:
      - id: "CTRL_1.1"
        title: "Control Title"
        description: "Control description"
        category: "Category"
        severity: "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        priority: 1  # 1-5, 1 being highest

        requirements:
          - "Requirement 1"
          - "Requirement 2"

        mapped_checks:
          - check_id: "TF001"
            scanner_type: "iac"
            weight: 0.9

        evidence_requirements:
          - type: "configuration_scan"
            frequency: "weekly"

        implementation_guidance: |
          Detailed guidance here
```

## Roadmap

### Phase 1: Foundation ✅ COMPLETED
- Core data models
- Framework loader
- SOC 2 and NIST CSF frameworks
- Basic CLI commands

### Phase 2: Analysis Engine ✅ COMPLETED
- Compliance mapper
- Gap analyzer
- HTML and JSON report generators

### Phase 3: Integration ✅ COMPLETED
- CLI integration
- Example workflows
- Documentation

### Phase 4: Policy-as-Code (In Progress)
- Policy schema and validation
- Custom policy templates
- Policy application to gap analysis

### Phase 5: Advanced Reporting (Planned)
- PDF report generator
- Excel report generator
- Report customization

### Phase 6: Additional Frameworks (Planned)
- PCI DSS
- ISO 27001
- COSO, COBIT
- RBI Regulations

### Phase 7: Evidence Management (Planned)
- Audit trail persistence
- Evidence storage and retrieval
- Evidence export

### Phase 8: Enterprise Features (Planned)
- Multi-tenant support
- Historical trend analysis
- Dashboard integration
- Third-party integrations (Jira, ServiceNow, Splunk)

## Support

- **Documentation**: [examples/compliance/README.md](examples/compliance/README.md)
- **GitHub**: https://github.com/chimandre04/secureguard
- **Issues**: https://github.com/chimandre04/secureguard/issues

## License

MIT License - see LICENSE file for details
