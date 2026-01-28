"""Example FastAPI application with SecureGuard sensor."""

from fastapi import FastAPI
from secureguard.sensors.fastapi_sensor import FastAPISecuritySensor

app = FastAPI(title="SecureGuard Demo API")

# Initialize security sensor
sensor = FastAPISecuritySensor(
    block_attacks=True,  # Block detected attacks
    severity_threshold="MEDIUM",  # Alert on MEDIUM and above
    webhook_url=None  # Optional: Add webhook URL for SIEM integration
)

# Add as middleware
app.middleware("http")(sensor)


@app.get("/")
def read_root():
    """Root endpoint."""
    return {"message": "SecureGuard Demo API", "status": "protected"}


@app.get("/users/{user_id}")
def get_user(user_id: str):
    """Get user by ID.

    Try testing with SQL injection:
    /users/1' OR '1'='1
    """
    return {"user_id": user_id, "name": "Demo User"}


@app.get("/search")
def search(q: str):
    """Search endpoint.

    Try testing with XSS:
    /search?q=<script>alert('XSS')</script>
    """
    return {"query": q, "results": []}


@app.post("/upload")
def upload_file(filename: str):
    """File upload endpoint.

    Try testing with path traversal:
    POST /upload with filename=../../etc/passwd
    """
    return {"filename": filename, "status": "uploaded"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
