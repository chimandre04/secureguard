# SecureGuard

A comprehensive security scanning platform that detects vulnerabilities across your entire development lifecycle - from dependencies to infrastructure and runtime.

## Features

### 🔍 Dependency Vulnerability Scanner
- Scans package manifests for known vulnerabilities
- Supports multiple formats: `requirements.txt`, `package.json`, `pom.xml`, `Pipfile`, `pyproject.toml`
- Uses CVE databases (OSV, NVD) for up-to-date vulnerability information
- Provides severity ratings and remediation suggestions

### 🏗️ Infrastructure as Code Analyzer
- Analyzes Terraform and CloudFormation templates
- Detects security misconfigurations
- Checks for:
  - Unencrypted storage
  - Overly permissive IAM policies
  - Missing logging/monitoring
  - Public exposure risks
  - Insecure network configurations

### 🛡️ Runtime Security Sensor
- Real-time attack detection for web applications
- Middleware for FastAPI and Flask
- Detects:
  - SQL Injection attempts
  - Cross-Site Scripting (XSS)
  - Path Traversal attacks
  - Command Injection
  - Suspicious payloads
- Configurable blocking or logging mode

## Installation

```bash
pip install secureguard
```

For runtime sensor support:
```bash
pip install secureguard[sensor]
```

For development:
```bash
pip install secureguard[dev]
```

## Quick Start

### Scan Dependencies
```bash
secureguard scan deps --file requirements.txt
```

### Analyze Infrastructure
```bash
secureguard scan iac --path ./terraform
```

### Enable Runtime Protection
```python
from fastapi import FastAPI
from secureguard.sensors import FastAPISecuritySensor

app = FastAPI()
sensor = FastAPISecuritySensor(block_attacks=True)
app.middleware("http")(sensor)
```

## Usage

### Dependency Scanning
```bash
# Scan a requirements.txt file
secureguard scan deps --file requirements.txt

# Scan package.json
secureguard scan deps --file package.json

# Output as JSON
secureguard scan deps --file requirements.txt --format json

# Set severity threshold
secureguard scan deps --file requirements.txt --severity high
```

### IaC Analysis
```bash
# Scan Terraform files
secureguard scan iac --path ./infrastructure --type terraform

# Scan CloudFormation templates
secureguard scan iac --path ./cloudformation --type cloudformation

# Scan all IaC files in directory
secureguard scan iac --path ./
```

### Runtime Sensor

#### FastAPI Example
```python
from fastapi import FastAPI
from secureguard.sensors.fastapi_sensor import FastAPISecuritySensor

app = FastAPI()

# Initialize sensor
sensor = FastAPISecuritySensor(
    block_attacks=True,
    webhook_url="https://your-siem.com/webhook"
)

# Add as middleware
app.middleware("http")(sensor)
```

#### Flask Example
```python
from flask import Flask
from secureguard.sensors.flask_sensor import FlaskSecuritySensor

app = Flask(__name__)

# Initialize sensor
sensor = FlaskSecuritySensor(
    block_attacks=False,  # Log only mode
    webhook_url="https://your-siem.com/webhook"
)

# Register sensor
sensor.init_app(app)
```

## Output Formats

- **Table**: Human-readable table output (default)
- **JSON**: Machine-readable JSON for CI/CD integration
- **SARIF**: Static Analysis Results Interchange Format

## CI/CD Integration

### GitHub Actions
```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install SecureGuard
        run: pip install secureguard
      - name: Scan Dependencies
        run: secureguard scan deps --file requirements.txt --format json
      - name: Scan Infrastructure
        run: secureguard scan iac --path ./terraform
```

## Development

```bash
# Clone repository
git clone https://github.com/yourusername/secureguard.git
cd secureguard

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=secureguard

# Format code
black secureguard tests

# Type checking
mypy secureguard
```

## Project Structure

```
secureguard/
├── secureguard/
│   ├── scanners/          # Vulnerability scanners
│   │   ├── deps_scanner.py
│   │   └── ...
│   ├── analyzers/         # IaC analyzers
│   │   ├── terraform.py
│   │   ├── cloudformation.py
│   │   └── ...
│   ├── sensors/           # Runtime sensors
│   │   ├── fastapi_sensor.py
│   │   ├── flask_sensor.py
│   │   └── ...
│   ├── utils/             # Shared utilities
│   └── cli.py             # CLI interface
├── tests/                 # Test suite
├── examples/              # Usage examples
└── README.md
```

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please open an issue or submit a pull request.

## Roadmap

- [ ] Support for more package managers (Gradle, Cargo, Go modules)
- [ ] Auto-fix capabilities for IaC misconfigurations
- [ ] Dashboard for centralized monitoring
- [ ] Support for Kubernetes security analysis
- [ ] Integration with popular SIEM platforms

## Author

Built as a portfolio project demonstrating security engineering expertise.
