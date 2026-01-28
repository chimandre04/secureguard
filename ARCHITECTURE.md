# SecureGuard Architecture

This document explains the architecture and design decisions of SecureGuard.

## Overview

SecureGuard is a modular security scanning platform with three main components:

1. **Dependency Vulnerability Scanner**: Detects known vulnerabilities in package dependencies
2. **Infrastructure as Code (IaC) Analyzer**: Identifies security misconfigurations in cloud infrastructure templates
3. **Runtime Security Sensor**: Real-time attack detection for web applications

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI Interface                         │
│                      (secureguard.cli)                       │
└─────────────────────┬────────────────────┬──────────────────┘
                      │                    │
        ┌─────────────┴─────────┐    ┌────┴─────────────┐
        │   Scanners Module     │    │ Analyzers Module │
        │  (deps_scanner.py)    │    │  (terraform.py,  │
        │                       │    │ cloudformation.py)│
        └───────────┬───────────┘    └────┬─────────────┘
                    │                     │
        ┌───────────┴─────────────────────┴─────────┐
        │          External APIs                     │
        │     (OSV Database, NVD, etc.)             │
        └───────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    Sensors Module                            │
│              (fastapi_sensor, flask_sensor)                  │
│                          │                                   │
│                  ┌───────┴────────┐                         │
│                  │ Attack Detector │                         │
│                  │ (pattern rules) │                         │
│                  └────────────────┘                          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                      Utils Module                            │
│              (severity, output formatting)                   │
└─────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Dependency Scanner

**Purpose**: Scan package manifest files for known vulnerabilities

**Components**:
- `DependencyScanner`: Main scanner class
- Package parsers for different ecosystems (pip, npm, maven)
- OSV API integration

**Flow**:
1. Detect package ecosystem from filename
2. Parse package file to extract dependencies
3. Query OSV API in batch for vulnerability data
4. Process and filter results by severity
5. Return formatted findings

**Key Design Decisions**:
- Uses OSV API for up-to-date vulnerability data
- Batch queries for performance
- Supports both specific versions and version ranges
- Modular parsers for easy addition of new package managers

### 2. IaC Analyzers

**Purpose**: Analyze infrastructure code for security misconfigurations

**Components**:
- `TerraformAnalyzer`: Analyzes .tf files
- `CloudFormationAnalyzer`: Analyzes CloudFormation templates
- Rule-based detection system

**Flow**:
1. Parse IaC file (HCL for Terraform, YAML/JSON for CloudFormation)
2. Extract resources and their configurations
3. Run security rules against each resource
4. Collect findings with severity and remediation guidance
5. Return filtered results

**Key Design Decisions**:
- Rule-based system for extensibility
- Simple parsers (trade-off: some complex syntax not supported)
- Focus on common high-impact misconfigurations
- Remediation guidance included in findings

**Security Rules**:
- Storage encryption (S3, RDS, EBS)
- Network exposure (public access, security groups)
- IAM permissions (overly permissive policies)
- Logging and monitoring (CloudWatch, CloudTrail)
- Backup configurations

### 3. Runtime Security Sensors

**Purpose**: Detect attacks in real-time within web applications

**Components**:
- `AttackDetector`: Pattern-based detection engine
- `FastAPISecuritySensor`: FastAPI middleware
- `FlaskSecuritySensor`: Flask before/after request hooks

**Flow**:
1. Intercept HTTP request
2. Extract relevant data (path, query params, headers, body)
3. URL decode (including double-encoding)
4. Match against attack patterns
5. Take action (log/block) based on configuration
6. Send alerts to webhook if configured

**Key Design Decisions**:
- Regex-based pattern matching for performance
- Double URL decoding to catch evasion attempts
- Configurable blocking vs logging mode
- Severity and confidence levels for each pattern
- Webhook integration for SIEM/alerting

**Attack Types Detected**:
- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Command Injection
- XXE (XML External Entity)
- LDAP Injection
- SSRF (Server-Side Request Forgery)
- NoSQL Injection

### 4. Utilities

**Severity Module**:
- Enum-based severity levels (INFO, LOW, MEDIUM, HIGH, CRITICAL)
- CVSS score to severity conversion
- Comparison operators for filtering

**Output Module**:
- Multiple output formats:
  - Table: Rich console output for humans
  - JSON: Machine-readable for CI/CD
  - SARIF: Standard format for security tools
- Summary statistics
- Color-coded severity display

### 5. CLI Interface

**Purpose**: User-friendly command-line interface

**Commands**:
- `scan deps`: Scan dependencies
- `scan iac`: Analyze infrastructure code
- `check-file`: Quick check of any file
- `init`: Create configuration file
- `info`: Display tool information

**Key Features**:
- Clear help messages
- Progress indicators
- Exit codes for CI/CD integration
- Output redirection support

## Data Flow

### Dependency Scanning
```
Package File → Parser → Dependency List → OSV API → Vulnerability Data → Findings
```

### IaC Analysis
```
IaC File → Parser → Resource List → Security Rules → Findings
```

### Runtime Detection
```
HTTP Request → Data Extraction → Pattern Matching → Action (Block/Log) → Webhook
```

## Extensibility Points

### Adding New Package Managers

1. Add file pattern to `SUPPORTED_FILES` in `DependencyScanner`
2. Implement parser method (e.g., `_parse_cargo_dependencies`)
3. Add ecosystem mapping for OSV API

### Adding New IaC Rules

1. Define rule function in analyzer class
2. Add to `_load_rules()` method
3. Rule should return `None` (no issue) or finding dictionary

### Adding New Attack Patterns

1. Add pattern to `_load_patterns()` in `AttackDetector`
2. Include: name, regex, severity, confidence, description
3. Test with various attack vectors

## Security Considerations

### False Positives

- Pattern-based detection may flag legitimate requests
- Confidence levels help prioritize alerts
- Logging mode allows tuning before blocking

### Performance

- Batch API queries to reduce latency
- Regex patterns optimized for speed
- Minimal processing overhead in runtime sensors

### Privacy

- No data sent to external services (except vulnerability databases)
- Webhook data should be sanitized in production
- Optional features can be disabled

## Testing Strategy

### Unit Tests
- Test individual components in isolation
- Mock external API calls
- Test edge cases and error handling

### Integration Tests
- Test end-to-end flows
- Use example vulnerable files
- Verify output formatting

### Performance Tests
- Benchmark scan times
- Test with large files
- Measure memory usage

## Future Enhancements

### Short-term
1. Add caching for OSV API responses
2. Improve HCL parsing for complex Terraform
3. Add more attack patterns
4. Configuration file support

### Long-term
1. Web dashboard for scan results
2. Historical analysis and trends
3. Auto-remediation capabilities
4. Machine learning for anomaly detection
5. Plugin system for custom rules
6. Integration with popular CI/CD platforms

## Performance Characteristics

### Dependency Scanner
- Time: O(n) where n = number of dependencies
- API calls: 1 batch request per scan
- Memory: Low (streaming parsers)

### IaC Analyzer
- Time: O(n × m) where n = resources, m = rules
- API calls: None
- Memory: Low (file processed once)

### Runtime Sensor
- Time: O(p) where p = number of patterns
- API calls: Optional webhook only
- Memory: Minimal per request
- Overhead: ~1-5ms per request

## Code Organization

```
secureguard/
├── cli.py              # CLI entry point
├── scanners/           # Vulnerability scanners
│   └── deps_scanner.py
├── analyzers/          # IaC analyzers
│   ├── terraform.py
│   └── cloudformation.py
├── sensors/            # Runtime sensors
│   ├── attack_detector.py
│   ├── fastapi_sensor.py
│   └── flask_sensor.py
└── utils/              # Shared utilities
    ├── severity.py
    └── output.py
```

## Dependencies

**Core**:
- `requests`: HTTP client for API calls
- `click`: CLI framework
- `rich`: Terminal output formatting
- `pyyaml`: YAML parsing
- `packaging`: Version parsing

**Optional**:
- `fastapi`: For FastAPI sensor
- `flask`: For Flask sensor
- `pytest`: For testing
- `black`: Code formatting
- `mypy`: Type checking

## Conclusion

SecureGuard's modular architecture makes it easy to extend and maintain. Each component has a single responsibility and clear interfaces. The design prioritizes:

1. **Usability**: Simple CLI, clear output
2. **Extensibility**: Easy to add new scanners and rules
3. **Performance**: Efficient algorithms and batch operations
4. **Accuracy**: Multiple severity levels and confidence ratings
5. **Integration**: Standard output formats and exit codes
