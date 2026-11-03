from fastapi import FastAPI
from datetime import datetime, timezone
from engine.core.config import settings

app = FastAPI(
    title="PkgSentinel Security Engine",
    description="Analysis and Detection Engine for PkgSentinel",
    version="0.1.0"
)


@app.get("/health", tags=["Health"])
def health_check():
    """Health endpoint returning service status and timestamp."""
    return {
        "status": "HEALTHY",
        "service": settings.app_name,
        "environment": settings.environment,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/api/v1/status", tags=["System"])
def system_status():
    """System configuration summary."""
    return {
        "engine_version": "0.1.0",
        "redis_host": settings.redis_host,
        "scan_stream": settings.scan_stream_key,
        "consumer_group": settings.consumer_group
    }
