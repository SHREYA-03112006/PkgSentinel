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
from engine.schemas.verdict import AnalysisVerdictReport
from engine.detection.pipeline import DetectionPipeline

app = FastAPI(
    title="PkgSentinel Security Engine",
    description="Analysis and Detection Engine for PkgSentinel",
    version="0.1.0"
)

ingestion_pipeline = IngestionPipeline()
detection_pipeline = DetectionPipeline()


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
    Ingests an npm or PyPI package safely without code execution.
    """
    try:
        result = ingestion_pipeline.ingest_package(coords)
        return result
    except (CoordinateValidationError, SSRFSecurityError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except RegistryResolutionError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except (DownloadIntegrityError, DownloadSizeLimitError, ArchiveExtractionError) as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    except IngestionError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.post(
    "/api/v1/analyze",
    response_model=AnalysisVerdictReport,
    tags=["Detection"],
    summary="Execute full static security detection and explainable risk scoring on a package"
)
def analyze_package_endpoint(coords: PackageCoordinates):
    """
    End-to-end static security analysis:
    1. Ingestion (Metadata resolution, safe download, integrity check, safe extraction, inventory)
    2. Module A: Metadata & Publisher Analysis
    3. Module B: Typosquatting & Homoglyph Detection
    4. Module C: Static Python & JavaScript AST Analysis
    5. Module C: Shannon Entropy Obfuscation Analysis
    6. Module G: Deduplication, Explainable Risk Scoring, and Verdict Generation
    """
    ingest_result = None
    try:
        ingest_result = ingestion_pipeline.ingest_package(coords)
        report = detection_pipeline.analyze(ingest_result, job_id=f"adhoc-{coords.name}-{coords.version}")
        return report
    except (CoordinateValidationError, SSRFSecurityError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except RegistryResolutionError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except (DownloadIntegrityError, DownloadSizeLimitError, ArchiveExtractionError) as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    except IngestionError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    finally:
        # Guarantee ephemeral workspace cleanup after analysis
        if ingest_result:
            try:
                ingestion_pipeline.cleanup_workspace(ingest_result)
            except Exception:
                pass
