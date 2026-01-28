# Getting Started with SecureGuard

This guide will help you set up and use SecureGuard for your resume project.

## Installation

### Development Setup

1. Navigate to the project directory:
```bash
cd secureguard
```

2. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the package in development mode:
```bash
pip install -e ".[dev,sensor]"
```

4. Verify installation:
```bash
secureguard --version
```

## Quick Start Guide

### 1. Dependency Scanning

Test the dependency scanner with the example file:

```bash
# Scan requirements.txt for vulnerabilities
secureguard scan deps --file examples/vulnerable_requirements.txt

# Output as JSON
secureguard scan deps --file examples/vulnerable_requirements.txt --format json

# Only show HIGH and CRITICAL vulnerabilities
secureguard scan deps --file examples/vulnerable_requirements.txt --severity HIGH
```

### 2. Infrastructure as Code Analysis

Test the IaC analyzer with example files:

```bash
# Scan Terraform file
secureguard scan iac --path examples/vulnerable_terraform.tf

# Scan CloudFormation template
secureguard scan iac --path examples/vulnerable_cloudformation.yaml

# Scan entire examples directory
secureguard scan iac --path examples/ --format json
```

### 3. Runtime Security Sensor

#### FastAPI Example

Run the FastAPI example:

```bash
# Install FastAPI and uvicorn
pip install fastapi uvicorn

# Run the example server
python examples/fastapi_example.py
```

Test with malicious requests:

```bash
# Test SQL injection detection
curl "http://localhost:8000/users/1'%20OR%20'1'='1"

# Test XSS detection
curl "http://localhost:8000/search?q=<script>alert('XSS')</script>"

# Test path traversal
curl -X POST "http://localhost:8000/upload?filename=../../etc/passwd"
```

#### Flask Example

Run the Flask example:

```bash
# Install Flask
pip install flask

# Run the example server
python examples/flask_example.py
```

Test with similar malicious requests on port 5000.

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=secureguard

# Run specific test file
pytest tests/test_attack_detector.py

# Run with verbose output
pytest -v
```

## Demo for Resume/Portfolio

### Create a Demo Video

1. **Dependency Scanning Demo**:
   - Show scanning a vulnerable requirements.txt
   - Highlight the detected CVEs with severity ratings
   - Show JSON output for CI/CD integration

2. **IaC Analysis Demo**:
   - Scan Terraform/CloudFormation files
   - Point out critical misconfigurations (public S3 buckets, unencrypted databases)
   - Show remediation suggestions

3. **Runtime Protection Demo**:
   - Run the FastAPI/Flask example
   - Send malicious requests
   - Show how attacks are detected and blocked
   - Display attack logs

### GitHub Repository Setup

1. Initialize git repository:
```bash
git init
git add .
git commit -m "Initial commit: SecureGuard security scanning platform"
```

2. Create a new repository on GitHub

3. Push your code:
```bash
git remote add origin https://github.com/yourusername/secureguard.git
git branch -M main
git push -u origin main
```

4. Add these sections to make it impressive:
   - Screenshots of the tool in action
   - CI/CD integration example (GitHub Actions workflow)
   - Performance metrics (scan speed, detection accuracy)
   - Comparison with similar tools

### Resume Bullet Points

Here are some suggested bullet points for your resume:

- "Developed **SecureGuard**, a comprehensive security scanning platform in Python that combines dependency vulnerability scanning, infrastructure-as-code analysis, and runtime attack detection"

- "Implemented vulnerability detection using the OSV database API, supporting multiple package ecosystems (pip, npm, Maven) with CVSS-based severity ratings"

- "Built IaC security analyzers for Terraform and CloudFormation with 20+ detection rules covering OWASP Top 10 and CIS benchmarks"

- "Created runtime security middleware for FastAPI and Flask that detects SQL injection, XSS, command injection, and path traversal attacks in real-time"

- "Designed modular architecture with CLI interface supporting multiple output formats (table, JSON, SARIF) for CI/CD integration"

- "Wrote comprehensive test suite achieving >80% code coverage and extensive documentation for open-source contributors"

## Extending the Project

### Add New Features

Some ideas to expand the project:

1. **More Package Managers**:
   - Add support for Cargo (Rust)
   - Add support for Go modules
   - Add support for Gradle

2. **Auto-Remediation**:
   - Automatically update vulnerable dependencies
   - Generate patches for IaC misconfigurations

3. **Dashboard**:
   - Create a web dashboard for viewing scan results
   - Add historical trend analysis
   - Implement team collaboration features

4. **More IaC Platforms**:
   - Kubernetes manifests
   - Ansible playbooks
   - Pulumi

5. **Integration**:
   - GitHub Actions
   - GitLab CI
   - Jenkins plugin
   - VS Code extension

### Contributing

1. Create a new branch for your feature
2. Write tests for new functionality
3. Update documentation
4. Submit a pull request

## Troubleshooting

### Common Issues

**Issue**: `secureguard: command not found`
- Solution: Make sure you activated the virtual environment and installed the package

**Issue**: Import errors for FastAPI/Flask sensors
- Solution: Install sensor dependencies: `pip install secureguard[sensor]`

**Issue**: Tests failing
- Solution: Ensure all dependencies are installed: `pip install -e ".[dev]"`

**Issue**: OSV API timeout
- Solution: The OSV API may be slow or down. Try again later or implement caching

## Next Steps

1. Customize the project with your name and details in `pyproject.toml`
2. Add more security rules based on your learning
3. Create comprehensive documentation
4. Record demo videos
5. Deploy to PyPI (optional)
6. Share on LinkedIn and GitHub

## Resources

- [OSV Database](https://osv.dev/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [CVSS Scoring](https://www.first.org/cvss/)
- [SARIF Format](https://sarifweb.azurewebsites.net/)

Good luck with your resume project! 🚀
