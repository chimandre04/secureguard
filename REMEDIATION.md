# SecureGuard Auto-Remediation

**AI-powered automated fixing of security vulnerabilities and compliance violations.**

## Overview

SecureGuard now includes intelligent auto-remediation capabilities that can automatically fix security issues in your code using a hybrid approach combining rule-based fixes and AI-powered solutions.

### Key Features

- 🤖 **AI-Powered Fixes**: Uses Claude AI for complex, context-aware code fixes
- 📋 **Rule-Based Fixes**: Fast, deterministic fixes for common issues
- 🔄 **Hybrid Strategy**: Combines both approaches for optimal results
- 🛡️ **Safety First**: Automatic backups, validation, and dry-run mode
- 🔧 **Git Integration**: Automatic commit creation with detailed messages
- 📊 **Multiple Modes**: Interactive review or fully automated
- 💯 **High Confidence**: Confidence scores for each fix

## Quick Start

### 1. Install Dependencies

```bash
# Install SecureGuard with remediation support
pip install -e .
pip install anthropic>=0.18.0  # For AI-powered fixes
```

### 2. Set API Key (for AI fixes)

```bash
export ANTHROPIC_API_KEY="your-api-key-here"
```

### 3. Run Auto-Remediation

```bash
# Scan for issues
secureguard scan iac --path ./terraform --format json --output findings.json

# Fix issues interactively
secureguard fix security --findings findings.json

# Or fix automatically
secureguard fix security --findings findings.json --mode auto
```

## Usage

### Fix Security Vulnerabilities

#### Interactive Mode (Default)

Review each fix before applying:

```bash
secureguard fix security --findings findings.json
```

This will:
1. Show each finding and proposed fix
2. Display a diff of changes
3. Ask for confirmation
4. Apply fix if confirmed
5. Create backup automatically

#### Automatic Mode

Apply all fixes without prompts:

```bash
secureguard fix security \\
  --findings findings.json \\
  --mode auto
```

#### Dry Run Mode

Preview fixes without applying:

```bash
secureguard fix security \\
  --findings findings.json \\
  --dry-run
```

### Fix Compliance Violations

Fix issues to meet compliance requirements:

```bash
# Fix all compliance issues for SOC 2
secureguard fix compliance \\
  --framework soc2 \\
  --findings findings.json

# Fix specific controls only
secureguard fix compliance \\
  --framework soc2 \\
  --findings findings.json \\
  --controls CC6.1,CC6.6
```

### Fix Strategies

Choose how fixes are generated:

#### Hybrid (Recommended)

Use rule-based fixes when possible, AI for complex cases:

```bash
secureguard fix security \\
  --findings findings.json \\
  --strategy hybrid
```

#### Rule-Based Only

Fast, deterministic fixes (no AI):

```bash
secureguard fix security \\
  --findings findings.json \\
  --strategy rule_based
```

#### LLM-Powered Only

AI-generated fixes for all issues:

```bash
secureguard fix security \\
  --findings findings.json \\
  --strategy llm_powered \\
  --api-key sk-ant-...
```

### Advanced Options

#### With Git Integration

Automatically create commits:

```bash
secureguard fix security \\
  --findings findings.json \\
  --auto-commit
```

Each fix creates a commit with message like:
```
fix: Update requests from 2.25.0 to 2.31.0

Finding ID: CVE-2023-xxxxx
Strategy: rule_based
Confidence: 0.90
```

#### Limit Number of Fixes

```bash
secureguard fix security \\
  --findings findings.json \\
  --max-fixes 5
```

#### Export Results

```bash
secureguard fix security \\
  --findings findings.json \\
  --output results.json
```

#### Without Backups

```bash
secureguard fix security \\
  --findings findings.json \\
  --no-backup
```

⚠️ **Warning**: Not recommended - always keep backups!

### Fix a Single Issue

Fix a custom security issue not detected by scanners:

```bash
secureguard fix single \\
  --file src/app.py \\
  --finding-id CUSTOM_001 \\
  --description "SQL injection in user input" \\
  --severity HIGH \\
  --strategy llm_powered
```

## How It Works

### Architecture

```
Finding → Orchestrator → Fixer Selection → Fix Generation → Validation → Application
                    ↓                   ↓              ↓             ↓
                Rule-Based          Template       Check Syntax   Backup
                LLM-Powered         AI Prompt      AI Validate    Git Commit
                Hybrid              Context        Manual         Results
```

### Fix Strategies

1. **Rule-Based Fixer**
   - Uses predefined templates
   - Fast and deterministic
   - Handles common patterns
   - Examples: Update dependency versions, add encryption settings

2. **LLM-Powered Fixer**
   - Uses Claude AI
   - Context-aware fixes
   - Handles complex cases
   - Examples: Refactor insecure logic, fix injection vulnerabilities

3. **Hybrid Approach**
   - Tries rule-based first
   - Falls back to LLM if needed
   - Best of both worlds
   - Optimal balance of speed and intelligence

### Supported Fix Types

#### Dependency Vulnerabilities
- ✅ Python (requirements.txt, Pipfile, pyproject.toml)
- ✅ JavaScript (package.json)
- ✅ Java (pom.xml)
- ✅ Ruby (Gemfile)
- ✅ Automatic version updates

#### Infrastructure as Code (Terraform)
- ✅ S3 bucket public access → Set ACL to private
- ✅ Missing encryption → Add encryption configuration
- ✅ RDS public access → Disable public accessibility
- ✅ Unrestricted security groups → Restrict IP ranges
- ✅ IAM wildcards → Add warnings and restrictions

#### CloudFormation
- ✅ Similar to Terraform fixes
- ✅ YAML and JSON support

#### Runtime Code Issues (via LLM)
- ✅ SQL injection fixes
- ✅ XSS vulnerability patches
- ✅ Path traversal prevention
- ✅ Command injection fixes
- ✅ Secure coding patterns

## Examples

### Example 1: Fix Dependency Vulnerabilities

```bash
# 1. Scan dependencies
secureguard scan deps --file requirements.txt --format json --output deps.json

# 2. Fix vulnerabilities interactively
secureguard fix security --findings deps.json

# Output:
# Finding: CVE-2023-xxxxx - requests package vulnerability
# Severity: HIGH
# File: requirements.txt
# Strategy: rule_based
# Confidence: 90%
#
# Proposed changes:
# - requests==2.25.0
# + requests>=2.31.0
#
# Apply this fix? [y/N]: y
# ✓ Successfully applied fix to requirements.txt
```

### Example 2: Fix IaC Misconfigurations

```bash
# 1. Scan Terraform
secureguard scan iac --path ./terraform --format json --output iac.json

# 2. Fix automatically with git commits
secureguard fix security \\
  --findings iac.json \\
  --mode auto \\
  --auto-commit

# Output:
# Processing file: terraform/main.tf
# Found 3 issue(s)
#
# ✓ Fixed TF001: S3 Bucket Public Access (committed to git)
# ✓ Fixed TF002: S3 Bucket Encryption (committed to git)
# ✓ Fixed TF003: RDS Instance Encryption (committed to git)
#
# REMEDIATION SUMMARY
# Total findings: 3
#   ✓ Successfully fixed: 3
#   ✗ Failed: 0
#   - Skipped: 0
```

### Example 3: AI-Powered Complex Fix

```bash
# Fix a complex SQL injection vulnerability
secureguard fix single \\
  --file api/users.py \\
  --finding-id SQL_INJ_001 \\
  --description "SQL injection in user search endpoint" \\
  --severity CRITICAL \\
  --strategy llm_powered

# Claude will:
# 1. Analyze the code context
# 2. Generate a parameterized query
# 3. Add input validation
# 4. Include security comments
# 5. Validate the fix
```

### Example 4: Compliance-Driven Fixes

```bash
# 1. Run compliance scan
secureguard compliance scan \\
  --framework soc2 \\
  --findings findings.json \\
  --format json \\
  --output compliance.json

# 2. Fix non-compliant controls
secureguard fix compliance \\
  --framework soc2 \\
  --findings findings.json \\
  --controls CC6.1,CC6.6 \\
  --mode auto

# This fixes all findings mapped to CC6.1 and CC6.6
```

## Safety Features

### 1. Automatic Backups

Every file is backed up before modification:

```
original-file.tf
original-file.tf.backup.20260129_143022
```

Restore manually if needed:
```bash
cp original-file.tf.backup.20260129_143022 original-file.tf
```

### 2. Validation

All fixes are validated before and after application:
- Syntax checking
- Resource existence verification
- AI validation (for LLM fixes)
- Git diff review

### 3. Dry Run Mode

Preview all changes without modifying files:

```bash
secureguard fix security --findings findings.json --dry-run
```

### 4. Interactive Confirmation

Review each fix before applying (default mode).

### 5. Confidence Scores

Each fix includes a confidence score:
- **0.9+**: High confidence (rule-based, well-tested)
- **0.7-0.9**: Good confidence (AI-generated, validated)
- **<0.7**: Lower confidence (complex cases, needs review)

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Auto-Fix Security Issues
on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly
  workflow_dispatch:  # Manual trigger

jobs:
  auto-fix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install SecureGuard
        run: |
          pip install secureguard anthropic

      - name: Scan for Issues
        run: |
          secureguard scan iac --path . --format json --output findings.json

      - name: Fix Issues
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          secureguard fix security \\
            --findings findings.json \\
            --mode auto \\
            --strategy hybrid \\
            --auto-commit \\
            --output fix-results.json

      - name: Create Pull Request
        uses: peter-evans/create-pull-request@v5
        with:
          commit-message: "fix: Auto-remediate security vulnerabilities"
          title: "🤖 Automated Security Fixes"
          body: |
            ## Automated Security Remediation

            This PR contains automated fixes for security vulnerabilities.

            See fix-results.json for details.
          branch: auto-fix/security
          labels: security, automated
```

## Best Practices

### 1. Start with Dry Run

Always preview fixes first:
```bash
secureguard fix security --findings findings.json --dry-run
```

### 2. Use Interactive Mode Initially

Get comfortable with the fixes:
```bash
secureguard fix security --findings findings.json --mode interactive
```

### 3. Test After Fixes

Always test after applying fixes:
```bash
# Run your test suite
pytest
npm test
terraform validate
```

### 4. Review AI Fixes Carefully

LLM-generated fixes should be reviewed:
- Check the diff carefully
- Verify logic is correct
- Test thoroughly
- Consider security implications

### 5. Use Version Control

Always have git history:
```bash
# Create a branch for fixes
git checkout -b security-fixes

# Run remediation with auto-commit
secureguard fix security --findings findings.json --auto-commit

# Review commits
git log

# Push for review
git push origin security-fixes
```

### 6. Gradual Rollout

Fix issues gradually:
```bash
# Fix 5 issues at a time
secureguard fix security --findings findings.json --max-fixes 5

# Review and test
pytest

# Fix next batch
secureguard fix security --findings findings.json --max-fixes 5
```

## Troubleshooting

### API Key Issues

```bash
# Set API key
export ANTHROPIC_API_KEY="sk-ant-..."

# Verify
echo $ANTHROPIC_API_KEY

# Or pass directly
secureguard fix security --findings findings.json --api-key sk-ant-...
```

### Fix Validation Errors

If a fix fails validation:
1. Check the error message
2. Review the proposed fix
3. Try LLM strategy instead:
   ```bash
   secureguard fix security --findings findings.json --strategy llm_powered
   ```

### Restore from Backup

```bash
# Find backup file
ls -la *.backup.*

# Restore
cp myfile.tf.backup.20260129_143022 myfile.tf
```

### Git Commit Issues

If auto-commit fails:
1. Check you're in a git repository
2. Verify git is installed
3. Ensure no uncommitted changes
4. Commit manually:
   ```bash
   git add fixed-file.tf
   git commit -m "fix: Security issue remediation"
   ```

## Limitations

Current limitations:
- **CloudFormation fixes**: Limited compared to Terraform
- **Runtime fixes**: Requires LLM (no rule-based option yet)
- **Multi-file refactoring**: May need manual intervention
- **Language support**: Python, JavaScript, Terraform primarily
- **Complex logic**: AI may not always understand business context

## Roadmap

Planned enhancements:
- More rule-based fixers
- Additional language support (Go, Rust, etc.)
- CloudFormation parity with Terraform
- Multi-file refactoring
- Learning from feedback
- Custom fix templates
- Integration with more LLMs (OpenAI GPT-4, etc.)

## Support

- **Documentation**: [REMEDIATION.md](REMEDIATION.md)
- **Examples**: [examples/remediation/](examples/remediation/)
- **GitHub**: https://github.com/chimandre04/secureguard
- **Issues**: https://github.com/chimandre04/secureguard/issues

## License

MIT License - see LICENSE file for details
