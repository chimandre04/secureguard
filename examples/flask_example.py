"""Example Flask application with SecureGuard sensor."""

from flask import Flask, request, jsonify
from secureguard.sensors.flask_sensor import FlaskSecuritySensor

app = Flask(__name__)

# Initialize security sensor
sensor = FlaskSecuritySensor(
    block_attacks=False,  # Log only mode
    severity_threshold="MEDIUM",
    webhook_url=None  # Optional: Add webhook URL for SIEM integration
)

# Register sensor with app
sensor.init_app(app)


@app.route("/")
def index():
    """Root endpoint."""
    return jsonify({
        "message": "SecureGuard Demo API",
        "status": "protected (log only mode)"
    })


@app.route("/users/<user_id>")
def get_user(user_id):
    """Get user by ID.

    Try testing with SQL injection:
    /users/1' OR '1'='1
    """
    return jsonify({"user_id": user_id, "name": "Demo User"})


@app.route("/search")
def search():
    """Search endpoint.

    Try testing with XSS:
    /search?q=<script>alert('XSS')</script>
    """
    query = request.args.get("q", "")
    return jsonify({"query": query, "results": []})


@app.route("/upload", methods=["POST"])
def upload_file():
    """File upload endpoint.

    Try testing with path traversal:
    POST /upload with {"filename": "../../etc/passwd"}
    """
    data = request.get_json()
    filename = data.get("filename", "")
    return jsonify({"filename": filename, "status": "uploaded"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
