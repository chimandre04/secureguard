"""Attack pattern detection engine."""

import re
from typing import Dict, Any, Optional, List
from urllib.parse import unquote


class AttackDetector:
    """Detects common attack patterns in HTTP requests."""

    def __init__(self):
        """Initialize attack detector with pattern rules."""
        self.patterns = self._load_patterns()

    def detect(
        self, method: str, path: str, query_params: Dict[str, Any],
        headers: Dict[str, str], body: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Detect attacks in an HTTP request.

        Args:
            method: HTTP method
            path: Request path
            query_params: Query parameters
            headers: Request headers
            body: Request body

        Returns:
            List of detected attacks
        """
        detections = []

        # Combine all input sources for analysis
        inputs_to_check = {
            "path": path,
            "query": " ".join([f"{k}={v}" for k, v in query_params.items()]),
            "headers": " ".join([f"{k}: {v}" for k, v in headers.items()]),
            "body": body or ""
        }

        # URL decode inputs for better detection
        decoded_inputs = {
            key: unquote(unquote(value))  # Double decode for double-encoded attacks
            for key, value in inputs_to_check.items()
        }

        # Check each pattern category
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                for source, content in decoded_inputs.items():
                    if content and re.search(pattern["regex"], content, re.IGNORECASE):
                        # Extract the matching content
                        match = re.search(pattern["regex"], content, re.IGNORECASE)
                        matched_text = match.group(0) if match else ""

                        detections.append({
                            "attack_type": category,
                            "pattern": pattern["name"],
                            "severity": pattern["severity"],
                            "confidence": pattern["confidence"],
                            "source": source,
                            "matched_text": matched_text[:100],  # Limit size
                            "description": pattern["description"]
                        })

        return detections

    def _load_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load attack detection patterns."""
        return {
            "SQL_INJECTION": [
                {
                    "name": "SQL Comments",
                    "regex": r"(--|#|/\*|\*/)",
                    "severity": "HIGH",
                    "confidence": "medium",
                    "description": "SQL comment syntax detected"
                },
                {
                    "name": "SQL Union",
                    "regex": r"\bunion\b.+\bselect\b",
                    "severity": "HIGH",
                    "confidence": "high",
                    "description": "SQL UNION SELECT statement detected"
                },
                {
                    "name": "SQL Injection Keywords",
                    "regex": r"(\bor\b|\band\b).+[=<>].+(\'|\"|;)",
                    "severity": "HIGH",
                    "confidence": "medium",
                    "description": "SQL injection pattern with logical operators"
                },
                {
                    "name": "SQL Time-based Blind",
                    "regex": r"\b(sleep|benchmark|waitfor delay)\b",
                    "severity": "HIGH",
                    "confidence": "high",
                    "description": "Time-based blind SQL injection detected"
                },
                {
                    "name": "SQL Stacked Queries",
                    "regex": r";.*(drop|delete|update|insert|alter)",
                    "severity": "CRITICAL",
                    "confidence": "high",
                    "description": "Stacked SQL query detected"
                },
            ],
            "XSS": [
                {
                    "name": "Script Tags",
                    "regex": r"<script[^>]*>.*?</script>",
                    "severity": "HIGH",
                    "confidence": "high",
                    "description": "Script tag detected"
                },
                {
                    "name": "Event Handlers",
                    "regex": r"\bon\w+\s*=",
                    "severity": "HIGH",
                    "confidence": "medium",
                    "description": "JavaScript event handler detected"
                },
                {
                    "name": "JavaScript Protocol",
                    "regex": r"javascript:",
                    "severity": "HIGH",
                    "confidence": "high",
                    "description": "JavaScript protocol handler detected"
                },
                {
                    "name": "Iframe Injection",
                    "regex": r"<iframe[^>]*>",
                    "severity": "HIGH",
                    "confidence": "high",
                    "description": "Iframe tag detected"
                },
                {
                    "name": "Encoded XSS",
                    "regex": r"(%3C|&lt;).*(%3E|&gt;)",
                    "severity": "MEDIUM",
                    "confidence": "medium",
                    "description": "Encoded HTML tags detected"
                },
            ],
            "PATH_TRAVERSAL": [
                {
                    "name": "Directory Traversal",
                    "regex": r"\.\.[/\\]",
                    "severity": "HIGH",
                    "confidence": "high",
                    "description": "Directory traversal pattern detected"
                },
                {
                    "name": "Absolute Path",
                    "regex": r"^(/etc/|/root/|c:\\|\\\\)",
                    "severity": "HIGH",
                    "confidence": "medium",
                    "description": "Absolute path to sensitive directory"
                },
                {
                    "name": "Encoded Traversal",
                    "regex": r"(%2e%2e[/\\]|\.\.%2f|\.\.%5c)",
                    "severity": "HIGH",
                    "confidence": "high",
                    "description": "Encoded directory traversal detected"
                },
            ],
            "COMMAND_INJECTION": [
                {
                    "name": "Command Chaining",
                    "regex": r"[;&|]+\s*(ls|cat|curl|wget|nc|bash|sh|python|perl|ruby)",
                    "severity": "CRITICAL",
                    "confidence": "high",
                    "description": "Command chaining detected"
                },
                {
                    "name": "Backticks",
                    "regex": r"`[^`]+`",
                    "severity": "HIGH",
                    "confidence": "medium",
                    "description": "Command substitution with backticks"
                },
                {
                    "name": "Command Substitution",
                    "regex": r"\$\([^)]+\)",
                    "severity": "HIGH",
                    "confidence": "medium",
                    "description": "Command substitution syntax detected"
                },
            ],
            "XXE": [
                {
                    "name": "External Entity",
                    "regex": r"<!ENTITY[^>]+SYSTEM",
                    "severity": "HIGH",
                    "confidence": "high",
                    "description": "XML external entity (XXE) detected"
                },
                {
                    "name": "DOCTYPE Declaration",
                    "regex": r"<!DOCTYPE[^>]+\[",
                    "severity": "MEDIUM",
                    "confidence": "medium",
                    "description": "DOCTYPE with entity declaration"
                },
            ],
            "LDAP_INJECTION": [
                {
                    "name": "LDAP Filter Injection",
                    "regex": r"[*()&|]",
                    "severity": "MEDIUM",
                    "confidence": "low",
                    "description": "LDAP filter metacharacters detected"
                },
            ],
            "SSRF": [
                {
                    "name": "Localhost Access",
                    "regex": r"(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)",
                    "severity": "MEDIUM",
                    "confidence": "low",
                    "description": "Localhost reference detected"
                },
                {
                    "name": "Internal IP",
                    "regex": r"(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)",
                    "severity": "MEDIUM",
                    "confidence": "low",
                    "description": "Private IP address detected"
                },
                {
                    "name": "Cloud Metadata",
                    "regex": r"169\.254\.169\.254",
                    "severity": "HIGH",
                    "confidence": "high",
                    "description": "Cloud metadata service access attempt"
                },
            ],
            "NOSQL_INJECTION": [
                {
                    "name": "MongoDB Operators",
                    "regex": r"\$\w+:",
                    "severity": "HIGH",
                    "confidence": "medium",
                    "description": "MongoDB query operator detected"
                },
                {
                    "name": "NoSQL JSON Injection",
                    "regex": r"\{.*\$\w+.*:.*\}",
                    "severity": "HIGH",
                    "confidence": "medium",
                    "description": "NoSQL injection pattern in JSON"
                },
            ],
        }
