"""Flask security sensor middleware."""

import json
import time
from typing import Optional
import requests

try:
    from flask import Flask, request, jsonify
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    Flask = None

from secureguard.sensors.attack_detector import AttackDetector


class FlaskSecuritySensor:
    """Runtime security sensor for Flask applications."""

    def __init__(
        self,
        block_attacks: bool = False,
        webhook_url: Optional[str] = None,
        severity_threshold: str = "MEDIUM"
    ):
        """Initialize Flask security sensor.

        Args:
            block_attacks: If True, block requests with detected attacks
            webhook_url: Optional webhook URL for sending alerts
            severity_threshold: Minimum severity to trigger actions (LOW, MEDIUM, HIGH, CRITICAL)
        """
        if not FLASK_AVAILABLE:
            raise ImportError(
                "Flask is not installed. "
                "Install with: pip install secureguard[sensor]"
            )

        self.block_attacks = block_attacks
        self.webhook_url = webhook_url
        self.severity_threshold = severity_threshold
        self.detector = AttackDetector()

        # Severity ordering
        self.severity_order = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }

    def init_app(self, app: Flask):
        """Initialize sensor with Flask app.

        Args:
            app: Flask application instance
        """
        app.before_request(self._before_request)
        app.after_request(self._after_request)

    def _before_request(self):
        """Before request handler."""
        # Extract request information
        method = request.method
        path = request.path
        query_params = dict(request.args)
        headers = dict(request.headers)

        # Read body if present
        body = None
        if method in ["POST", "PUT", "PATCH"]:
            try:
                if request.is_json:
                    body = json.dumps(request.get_json())
                else:
                    body = request.get_data(as_text=True)
            except Exception:
                body = None

        # Detect attacks
        detections = self.detector.detect(
            method=method,
            path=path,
            query_params=query_params,
            headers=headers,
            body=body
        )

        # Filter by severity threshold
        threshold_value = self.severity_order.get(self.severity_threshold, 2)
        significant_detections = [
            d for d in detections
            if self.severity_order.get(d["severity"], 0) >= threshold_value
        ]

        # Store detections in Flask g object for after_request
        from flask import g
        g.secureguard_detections = significant_detections

        # Handle detections
        if significant_detections:
            # Log the attack
            attack_info = {
                "timestamp": time.time(),
                "method": method,
                "path": path,
                "source_ip": request.remote_addr or "unknown",
                "user_agent": headers.get("user-agent", "unknown"),
                "detections": significant_detections,
                "blocked": self.block_attacks
            }

            # Send to webhook if configured
            if self.webhook_url:
                self._send_webhook(attack_info)

            # Block if configured
            if self.block_attacks:
                return jsonify({
                    "error": "Request blocked by security sensor",
                    "reason": "Potential attack detected",
                    "request_id": str(time.time())
                }), 403

    def _after_request(self, response):
        """After request handler.

        Args:
            response: Flask response object

        Returns:
            Modified response
        """
        # Add security headers
        response.headers["X-SecureGuard"] = "active"

        # Add detection count if any
        from flask import g
        if hasattr(g, "secureguard_detections") and g.secureguard_detections:
            response.headers["X-SecureGuard-Detections"] = str(
                len(g.secureguard_detections)
            )

        return response

    def _send_webhook(self, attack_info: dict):
        """Send attack information to webhook.

        Args:
            attack_info: Dictionary containing attack details
        """
        try:
            requests.post(
                self.webhook_url,
                json=attack_info,
                timeout=5
            )
        except Exception as e:
            # Log error but don't fail the request
            print(f"Warning: Failed to send webhook: {e}")
