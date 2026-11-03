"""
PkgSentinel Secure Package Ingestion & Archive Analysis Engine
"""

from engine.ingestion.models import (
    Ecosystem,
    DistributionType,
    PackageCoordinates,
    ResolvedDistribution,
    FileInventoryItem,
    PackageInventory,
    IngestionResult,
    IngestionError,
    CoordinateValidationError,
    RegistryResolutionError,
    SSRFSecurityError,
    DownloadIntegrityError,
    DownloadSizeLimitError,
    ArchiveExtractionError,
    ArchiveBombError,
    ArchiveTraversalError,
    ArchiveSpecialFileError,
)
from engine.ingestion.integrity import (
    verify_file_integrity,
    compute_file_hashes,
    parse_integrity_string,
)
from engine.ingestion.registry_client import (
    validate_coordinates,
    validate_registry_url,
    validate_ip_address,
    ALLOWED_REGISTRY_HOSTS,
)
from engine.ingestion.registry_downloader import RegistryDownloader
from engine.ingestion.archive_extractor import (
    SecureArchiveExtractor,
    ArchiveLimits,
    sanitize_relative_path,
)
from engine.ingestion.inventory import (
    build_package_inventory,
    detect_file_type_and_binary,
    check_suspicious_filename,
)
from engine.ingestion.pipeline import IngestionPipeline

__all__ = [
    "Ecosystem",
    "DistributionType",
    "PackageCoordinates",
    "ResolvedDistribution",
    "FileInventoryItem",
    "PackageInventory",
    "IngestionResult",
    "IngestionError",
    "CoordinateValidationError",
    "RegistryResolutionError",
    "SSRFSecurityError",
    "DownloadIntegrityError",
    "DownloadSizeLimitError",
    "ArchiveExtractionError",
    "ArchiveBombError",
    "ArchiveTraversalError",
    "ArchiveSpecialFileError",
    "verify_file_integrity",
    "compute_file_hashes",
    "parse_integrity_string",
    "validate_coordinates",
    "validate_registry_url",
    "validate_ip_address",
    "ALLOWED_REGISTRY_HOSTS",
    "RegistryDownloader",
    "SecureArchiveExtractor",
    "ArchiveLimits",
    "sanitize_relative_path",
    "build_package_inventory",
    "detect_file_type_and_binary",
    "check_suspicious_filename",
    "IngestionPipeline",
]

