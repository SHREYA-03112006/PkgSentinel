"""
Data models and structured exceptions for PkgSentinel package ingestion.
"""

from enum import Enum
from typing import List, Dict, Optional
from pydantic import BaseModel, Field, ConfigDict


# ==============================================================================
# Exceptions
# ==============================================================================

class IngestionError(Exception):
    """Base exception for all ingestion failures."""
    pass


class CoordinateValidationError(IngestionError):
    """Raised when package name or version does not conform to specification."""
    pass


class RegistryResolutionError(IngestionError):
    """Raised when metadata resolution fails on official registries."""
    pass


class SSRFSecurityError(IngestionError):
    """Raised when an outbound URL violates SSRF, DNS, or IP policy."""
    pass


class DownloadIntegrityError(IngestionError):
    """Raised when downloaded bytes do not match registry integrity digest."""
    pass


class DownloadSizeLimitError(IngestionError):
    """Raised when an archive exceeds the maximum permitted download size."""
    pass


class ArchiveExtractionError(IngestionError):
    """Base error for archive extraction failures."""
    pass


class ArchiveBombError(ArchiveExtractionError):
    """Raised when decompression exceeds compression ratio or byte quotas."""
    pass


class ArchiveTraversalError(ArchiveExtractionError):
    """Raised when an entry attempts directory or path traversal."""
    pass


class ArchiveSpecialFileError(ArchiveExtractionError):
    """Raised when an archive contains forbidden special entries (FIFOs, devices, symlink escapes)."""
    pass


# ==============================================================================
# Enums
# ==============================================================================

class Ecosystem(str, Enum):
    NPM = "NPM"
    PYPI = "PYPI"


class DistributionType(str, Enum):
    NPM_TARBALL = "NPM_TARBALL"
    PYPI_WHEEL = "PYPI_WHEEL"
    PYPI_SDIST = "PYPI_SDIST"


# ==============================================================================
# Ingestion Pydantic Models
# ==============================================================================

class PackageCoordinates(BaseModel):
    ecosystem: Ecosystem
    name: str
    version: str

    model_config = ConfigDict(frozen=True)


class ResolvedDistribution(BaseModel):
    filename: str
    download_url: str
    dist_type: DistributionType
    integrity_value: str
    integrity_algo: str  # sha512, sha256, sha1
    size_bytes: Optional[int] = None
    release_date: Optional[str] = None


class FileInventoryItem(BaseModel):
    relative_path: str
    size_bytes: int
    sha256: str
    extension: str
    file_type: str
    is_binary: bool
    is_executable: bool


class PackageInventory(BaseModel):
    total_files: int
    total_bytes: int
    extension_distribution: Dict[str, int]
    binary_file_count: int
    suspicious_files: List[str]
    files: List[FileInventoryItem]


class IngestionResult(BaseModel):
    coordinates: PackageCoordinates
    distribution: ResolvedDistribution
    archive_path: str
    extracted_workspace: str
    archive_sha256: str
    archive_size_bytes: int
    inventory: PackageInventory
    ingested_at: str
