"""FastAPI security sensor middleware."""

import json
import time
from typing import Callable, Optional
import requests

try:
    from fastapi import Request, Response
    from starlette.middleware.base import BaseHTTPMiddleware
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    Request = None
    Response = None
    BaseHTTPMiddleware = object

from secureguard.sensors.attack_detector import AttackDetector


class FastAPISecuritySensor:
    """Runtime security sensor for FastAPI applications."""

    def __init__(
        self,
        block_attacks: bool = False,
        webhook_url: Optional[str] = None,
        severity_threshold: str = "MEDIUM"
    ):
        """Initialize FastAPI security sensor.

        Args:
            block_attacks: If True, block requests with detected attacks
            webhook_url: Optional webhook URL for sending alerts
            severity_threshold: Minimum severity to trigger actions (LOW, MEDIUM, HIGH, CRITICAL)
        """
        if not FASTAPI_AVAILABLE:
            raise ImportError(
                "FastAPI is not installed. "
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

    async def __call__(self, request: Request, call_next: Callable) -> Response:
        """Middleware handler for FastAPI.

        Args:
            request: FastAPI request object
            call_next: Next middleware in chain

        Returns:
            Response object
        """
        start_time = time.time()

        # Extract request information
        method = request.method
        path = str(request.url.path)
        query_params = dict(request.query_params)
        headers = dict(request.headers)

        # Read body if present
        body = None
        if method in ["POST", "PUT", "PATCH"]:
            try:
                body_bytes = await request.body()
                body = body_bytes.decode("utf-8")
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

        # Handle detections
        if significant_detections:
            # Log the attack
            attack_info = {
                "timestamp": time.time(),
                "method": method,
                "path": path,
                "source_ip": request.client.host if request.client else "unknown",
                "user_agent": headers.get("user-agent", "unknown"),
                "detections": significant_detections,
                "blocked": self.block_attacks
            }

            # Send to webhook if configured
            if self.webhook_url:
                self._send_webhook(attack_info)

            # Block if configured
            if self.block_attacks:
                return Response(
                    content=json.dumps({
                        "error": "Request blocked by security sensor",
                        "reason": "Potential attack detected",
                        "request_id": str(time.time())
                    }),
                    status_code=403,
                    media_type="application/json"
                )

        # Continue with request
        response = await call_next(request)

        # Add security headers
        response.headers["X-SecureGuard"] = "active"
        if significant_detections:
            response.headers["X-SecureGuard-Detections"] = str(len(significant_detections))

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
