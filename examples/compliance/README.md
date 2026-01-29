# Compliance Automation Examples

This directory contains examples demonstrating SecureGuard's compliance automation capabilities.

## Quick Start

### 1. List Available Frameworks

```bash
secureguard compliance frameworks
```

This will show:
- soc2 - SOC 2 Type II (v2017) - 15 controls
- nist_csf - NIST Cybersecurity Framework (v1.1) - 13 controls

### 2. Show Framework Details

```bash
secureguard compliance show-framework --id soc2
```

### 3. Run Compliance Scan

Using the example findings file:

```bash
secureguard compliance scan \
  --framework soc2 \
  --findings examples/compliance/example-findings.json \
  --format html \
  --output compliance-report.html
```

This will:
- Load the SOC 2 framework
- Analyze the security findings
- Map findings to SOC 2 controls
- Perform gap analysis
- Generate an HTML compliance report

### 4. Analyze Gaps

Show only non-compliant controls:

```bash
secureguard compliance gaps \
  --framework soc2 \
  --findings examples/compliance/example-findings.json \
  --status non_compliant
```

### 5. Map Findings to Controls

See how security findings map to compliance controls:

```bash
secureguard compliance map \
  --findings examples/compliance/example-findings.json \
  --framework soc2
```

## Example Findings

The [example-findings.json](example-findings.json) file contains sample security findings:
- S3 bucket public access (CRITICAL)
- S3 bucket encryption disabled (HIGH)
- RDS encryption disabled (HIGH)
- Unrestricted security group ingress (HIGH)
- CloudWatch logging disabled (MEDIUM)
- Vulnerable dependency (HIGH)

These findings will map to multiple SOC 2 controls:
- **CC6.1** - Logical and Physical Access Controls
- **CC6.6** - Encryption
- **CC7.1** - System Monitoring
- **CC7.2** - Security Incident Detection
- **SDLC1.1** - Dependency Vulnerability Management

## Understanding the Results

### Compliance Status
- **Compliant**: ≥95% coverage
- **Partial**: 50-95% coverage
- **Non-Compliant**: <50% coverage
- **Not Tested**: No automated checks available

### Coverage Calculation
Coverage is calculated as: `(passing_checks / total_checks) * 100`

Each control has weighted checks. A finding reduces coverage proportionally to the check's weight.

### Overall Score
The overall compliance score is a weighted average of all control coverage scores, weighted by control priority.

## Real-World Usage

### CI/CD Integration

```yaml
# .github/workflows/compliance.yml
name: Compliance Check
on: [push, pull_request]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install SecureGuard
        run: pip install -e .

      - name: Scan Infrastructure
        run: |
          secureguard scan iac --path ./terraform --format json --output findings.json

      - name: Check SOC 2 Compliance
        run: |
          secureguard compliance scan \
            --framework soc2 \
            --findings findings.json \
            --format json \
            --output compliance-results.json

      - name: Verify Compliance Score
        run: |
          SCORE=$(jq '.overall_score' compliance-results.json)
          if (( $(echo "$SCORE < 80" | bc -l) )); then
            echo "Compliance score too low: $SCORE%"
            exit 1
          fi
```

### Multi-Framework Compliance

Check compliance against multiple frameworks:

```bash
for framework in soc2 nist_csf; do
  secureguard compliance scan \
    --framework $framework \
    --findings findings.json \
    --format html \
    --output "reports/${framework}-report.html"
done
```

## Output Formats

### JSON Format
Machine-readable format for programmatic analysis and CI/CD integration:

```bash
secureguard compliance scan \
  --framework soc2 \
  --findings findings.json \
  --format json \
  --output report.json
```

### HTML Format
Human-readable format for audit reports and management review:

```bash
secureguard compliance scan \
  --framework soc2 \
  --findings findings.json \
  --format html \
  --output report.html
```

The HTML report includes:
- Executive summary
- Compliance score visualization
- Control status dashboard
- Gap analysis with recommendations
- Detailed findings per control

## Next Steps

1. **Scan Your Infrastructure**: Run SecureGuard security scans on your actual infrastructure
2. **Generate Findings**: Export findings to JSON format
3. **Run Compliance Scan**: Use the compliance scan command with your findings
4. **Review Report**: Open the HTML report and review gaps
5. **Remediate**: Address non-compliant controls based on recommendations
6. **Re-scan**: Run compliance scan again to verify improvements

## Supported Frameworks

Current:
- ✅ SOC 2 Type II (2017)
- ✅ NIST Cybersecurity Framework (v1.1)

Coming Soon:
- PCI DSS
- ISO 27001
- COSO
- COBIT
- RBI Regulations
- SOX
- SSAE16/ISAE3402
