"""Anthropic Claude client for AI-powered code fixes."""

import os
from typing import Dict, Any, Optional, List
import json


class ClaudeClient:
    """Client for interacting with Anthropic Claude API."""

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-3-5-sonnet-20241022"):
        """Initialize Claude client.

        Args:
            api_key: Anthropic API key (defaults to ANTHROPIC_API_KEY env var)
            model: Claude model to use
        """
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.model = model

        if not self.api_key:
            raise ValueError(
                "Anthropic API key not provided. Set ANTHROPIC_API_KEY environment variable "
                "or pass api_key parameter."
            )

    def generate_fix(
        self,
        finding: Dict[str, Any],
        file_content: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """Generate a code fix using Claude.

        Args:
            finding: Security finding dictionary
            file_content: Current content of the file
            context: Optional additional context

        Returns:
            Dictionary with 'fixed_content', 'explanation', and 'confidence'
        """
        try:
            from anthropic import Anthropic
        except ImportError:
            raise ImportError(
                "anthropic package not installed. Install with: pip install anthropic"
            )

        client = Anthropic(api_key=self.api_key)

        prompt = self._build_fix_prompt(finding, file_content, context)

        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=4096,
                temperature=0.2,  # Lower temperature for more deterministic fixes
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )

            # Parse response
            response_text = response.content[0].text

            # Extract fixed code and explanation
            result = self._parse_fix_response(response_text, file_content)

            return result

        except Exception as e:
            print(f"Error calling Claude API: {e}")
            return None

    def _build_fix_prompt(
        self,
        finding: Dict[str, Any],
        file_content: str,
        context: Optional[Dict[str, Any]]
    ) -> str:
        """Build prompt for generating fix.

        Args:
            finding: Security finding
            file_content: File content
            context: Additional context

        Returns:
            Prompt string
        """
        finding_type = finding.get("type", "SECURITY_ISSUE")
        severity = finding.get("severity", "MEDIUM")
        description = finding.get("description", "Security issue detected")
        remediation = finding.get("remediation", "")
        resource = finding.get("resource", "")
        file_path = finding.get("file", "")

        prompt = f"""You are a security expert. I need you to fix a security vulnerability in code.

**Security Finding:**
- Type: {finding_type}
- Severity: {severity}
- Description: {description}
- Resource/Location: {resource}
- File: {file_path}

**Remediation Guidance:**
{remediation if remediation else "No specific guidance provided"}

**Current Code:**
```
{file_content}
```

**Task:**
Fix the security issue in the code above. Your response must be in the following JSON format:

{{
  "fixed_code": "... complete fixed code here ...",
  "explanation": "Brief explanation of what was changed and why",
  "confidence": 0.85,
  "changes_made": ["List of specific changes"]
}}

**Requirements:**
1. Provide the COMPLETE fixed code, not just the changed parts
2. Maintain all existing functionality
3. Follow security best practices
4. Keep the same code structure and style
5. Add comments explaining security-critical changes
6. Ensure the fix is minimal and focused on the security issue

Respond ONLY with valid JSON, no other text."""

        return prompt

    def _parse_fix_response(self, response_text: str, original_content: str) -> Optional[Dict[str, Any]]:
        """Parse Claude's response to extract fix information.

        Args:
            response_text: Response from Claude
            original_content: Original file content

        Returns:
            Dictionary with fix information or None if parsing fails
        """
        try:
            # Try to extract JSON from response
            # Sometimes Claude wraps JSON in markdown code blocks
            if "```json" in response_text:
                json_start = response_text.find("```json") + 7
                json_end = response_text.find("```", json_start)
                json_text = response_text[json_start:json_end].strip()
            elif "```" in response_text:
                json_start = response_text.find("```") + 3
                json_end = response_text.find("```", json_start)
                json_text = response_text[json_start:json_end].strip()
            else:
                # Assume entire response is JSON
                json_text = response_text.strip()

            # Parse JSON
            result = json.loads(json_text)

            # Validate required fields
            if "fixed_code" not in result:
                return None

            # Ensure confidence is present
            if "confidence" not in result:
                result["confidence"] = 0.7  # Default confidence

            return {
                "fixed_content": result["fixed_code"],
                "explanation": result.get("explanation", ""),
                "confidence": float(result.get("confidence", 0.7)),
                "changes_made": result.get("changes_made", [])
            }

        except json.JSONDecodeError as e:
            print(f"Failed to parse Claude response as JSON: {e}")
            # Try to extract code between markers
            if "```" in response_text:
                try:
                    code_start = response_text.find("```") + 3
                    # Skip language identifier
                    if response_text[code_start:code_start+10].strip() and not response_text[code_start].isspace():
                        newline = response_text.find("\n", code_start)
                        code_start = newline + 1 if newline != -1 else code_start
                    code_end = response_text.find("```", code_start)
                    fixed_code = response_text[code_start:code_end].strip()

                    return {
                        "fixed_content": fixed_code,
                        "explanation": "Fix generated by AI",
                        "confidence": 0.6,
                        "changes_made": []
                    }
                except Exception:
                    pass

            return None

        except Exception as e:
            print(f"Error parsing fix response: {e}")
            return None

    def validate_fix_with_ai(
        self,
        original_content: str,
        fixed_content: str,
        finding: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Use AI to validate that a fix is correct.

        Args:
            original_content: Original file content
            fixed_content: Fixed file content
            finding: The security finding

        Returns:
            Validation result with is_valid, issues, and suggestions
        """
        try:
            from anthropic import Anthropic
        except ImportError:
            return {"is_valid": True, "issues": [], "suggestions": []}

        client = Anthropic(api_key=self.api_key)

        prompt = f"""Review this security fix to ensure it's correct and doesn't introduce new issues.

**Original Issue:**
{finding.get('description', 'Security issue')}

**Original Code:**
```
{original_content}
```

**Fixed Code:**
```
{fixed_content}
```

Analyze the fix and respond in JSON format:
{{
  "is_valid": true/false,
  "issues": ["List any problems with the fix"],
  "suggestions": ["List any improvements"],
  "security_impact": "Brief assessment of security improvement"
}}
"""

        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=2048,
                temperature=0.1,
                messages=[{"role": "user", "content": prompt}]
            )

            response_text = response.content[0].text

            # Parse JSON response
            if "```json" in response_text:
                json_start = response_text.find("```json") + 7
                json_end = response_text.find("```", json_start)
                result = json.loads(response_text[json_start:json_end])
            else:
                result = json.loads(response_text)

            return result

        except Exception as e:
            print(f"Error validating fix with AI: {e}")
            return {"is_valid": True, "issues": [], "suggestions": []}
