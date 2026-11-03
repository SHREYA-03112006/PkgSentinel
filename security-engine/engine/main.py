from fastapi import FastAPI, HTTPException, status
from datetime import datetime, timezone
from engine.core.config import settings
from engine.ingestion.models import (
    PackageCoordinates,
    IngestionResult,
    CoordinateValidationError,
    RegistryResolutionError,
    SSRFSecurityError,
    DownloadIntegrityError,
    DownloadSizeLimitError,
    ArchiveExtractionError,
    IngestionError,
)
from engine.ingestion.pipeline import IngestionPipeline

app = FastAPI(
    title="PkgSentinel Security Engine",
    description="Analysis and Detection Engine for PkgSentinel",
    version="0.1.0"
)

pipeline = IngestionPipeline()


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


@app.post(
    "/api/v1/ingest",
    response_model=IngestionResult,
    tags=["Ingestion"],
    summary="Safely resolve, download, extract, and inventory an npm or PyPI package"
)
def ingest_package_endpoint(coords: PackageCoordinates):
    """
    Ingests an npm or PyPI package:
    - Validates package coordinates against strict naming rules.
    - Resolves official metadata from allowlisted registries.
    - Streams download with size quotas and anti-SSRF protections.
    - Verifies cryptographic integrity (SRI / SHA-256).
    - Safely extracts with TarSlip, ZipBomb, and symlink protection.
    - Generates a deterministic file inventory.
    """
    try:
        result = pipeline.ingest_package(coords)
        return result
    except (CoordinateValidationError, SSRFSecurityError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except RegistryResolutionError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except (DownloadIntegrityError, DownloadSizeLimitError, ArchiveExtractionError) as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    except IngestionError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
