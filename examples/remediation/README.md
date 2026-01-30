# Auto-Remediation Examples

This directory contains examples demonstrating SecureGuard's auto-remediation capabilities.

## Quick Demo

### 1. Basic Workflow

```bash
# Step 1: Scan for vulnerabilities
cd examples/remediation
secureguard scan iac --path vulnerable-terraform --format json --output findings.json

# Step 2: Preview fixes
secureguard fix security --findings findings.json --dry-run

# Step 3: Apply fixes interactively
secureguard fix security --findings findings.json

# Step 4: Verify fixes worked
secureguard scan iac --path vulnerable-terraform --format json
```

### 2. Dependency Fix Example

```bash
# Create a vulnerable requirements.txt
echo "requests==2.25.0" > requirements.txt
echo "flask==1.0.0" >> requirements.txt

# Scan
secureguard scan deps --file requirements.txt --format json --output deps.json

# Fix automatically
secureguard fix security --findings deps.json --mode auto

# Result: Packages updated to secure versions
cat requirements.txt
```

### 3. Terraform Fix Example

```bash
# Scan Terraform files
secureguard scan iac --path vulnerable-terraform --format json --output tf.json

# Fix with AI
export ANTHROPIC_API_KEY="your-key"
secureguard fix security --findings tf.json --strategy hybrid --auto-commit

# Check git log
git log --oneline -5
```

### 4. Compliance-Driven Remediation

```bash
# Run compliance scan
secureguard compliance scan \\
  --framework soc2 \\
  --findings findings.json \\
  --format json \\
  --output compliance.json

# Fix compliance violations
secureguard fix compliance \\
  --framework soc2 \\
  --findings findings.json \\
  --mode auto

# Re-check compliance
secureguard compliance scan \\
  --framework soc2 \\
  --findings findings.json \\
  --format html \\
  --output after-fix-report.html
```

## Files in This Directory

- `vulnerable-requirements.txt` - Example with dependency vulnerabilities
- `vulnerable-terraform.tf` - Example Terraform with security issues
- `fix-workflow.sh` - Complete automated fix workflow script

## Try It Yourself

### Fix Dependency Vulnerabilities

```bash
# Use the example file
cp vulnerable-requirements.txt requirements.txt

# Scan
secureguard scan deps --file requirements.txt --format json --output findings.json

# Fix interactively
secureguard fix security --findings findings.json
```

### Fix Terraform Misconfigurations

```bash
# Use the example file
cp vulnerable-terraform.tf main.tf

# Scan
secureguard scan iac --path . --format json --output findings.json

# Preview fixes
secureguard fix security --findings findings.json --dry-run

# Apply fixes
secureguard fix security --findings findings.json --mode auto
```

## Expected Results

### Before Remediation

```json
{
  "findings": [
    {"id": "TF001", "severity": "CRITICAL", "title": "S3 Bucket Public Access"},
    {"id": "TF002", "severity": "HIGH", "title": "S3 Encryption Disabled"},
    {"id": "CVE-2023-xxxxx", "severity": "HIGH", "package": "requests"}
  ]
}
```

### After Remediation

```json
{
  "total_findings": 3,
  "successful_fixes": 3,
  "failed_fixes": 0,
  "results": [
    {"status": "success", "file": "requirements.txt", "confidence": 0.9},
    {"status": "success", "file": "main.tf", "confidence": 0.85},
    {"status": "success", "file": "main.tf", "confidence": 0.85}
  ]
}
```

## Advanced Usage

### Custom Fix Script

```bash
#!/bin/bash
# fix-all.sh - Complete remediation workflow

# Scan everything
secureguard scan iac --path . --format json --output iac.json
secureguard scan deps --file requirements.txt --format json --output deps.json

# Combine findings
jq -s '.[0].findings + .[1].findings | {findings: .}' iac.json deps.json > all-findings.json

# Fix automatically
secureguard fix security \\
  --findings all-findings.json \\
  --mode auto \\
  --strategy hybrid \\
  --auto-commit \\
  --output fix-results.json

# Generate compliance report
secureguard compliance scan \\
  --framework soc2 \\
  --findings all-findings.json \\
  --format html \\
  --output compliance-report.html

echo "✓ Remediation complete!"
echo "✓ See fix-results.json for details"
echo "✓ See compliance-report.html for compliance status"
```

## Notes

- Always review AI-generated fixes carefully
- Test your code after applying fixes
- Use version control to track changes
- Start with dry-run mode
- Enable backups (enabled by default)

## Support

For more information, see [REMEDIATION.md](../../REMEDIATION.md)
