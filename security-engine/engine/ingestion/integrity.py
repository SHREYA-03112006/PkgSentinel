"""
Integrity verification module supporting SRI digests, hex checksums, and streaming validation.
"""

import hashlib
import hmac
import base64
import re
from typing import Tuple, Optional
from engine.ingestion.models import DownloadIntegrityError

SRI_REGEX = re.compile(r"^(sha256|sha384|sha512)-([A-Za-z0-9+/=]+)$")


def parse_integrity_string(integrity_str: str) -> Tuple[str, bytes]:
    """
    Parses an integrity string (SRI, hex digest, or raw base64).
    Returns (algorithm_name, raw_digest_bytes).
    """
    clean_str = integrity_str.strip()
    
    # Check for SRI format: e.g., sha512-H1a...
    sri_match = SRI_REGEX.match(clean_str)
    if sri_match:
        algo = sri_match.group(1).lower()
        b64_digest = sri_match.group(2)
        try:
            return algo, base64.b64decode(b64_digest)
        except Exception as e:
            raise DownloadIntegrityError(f"Invalid base64 in SRI digest: {e}")

    # Check for 64-char hex (SHA-256)
    if len(clean_str) == 64 and all(c in "0123456789abcdefABCDEF" for c in clean_str):
        return "sha256", bytes.fromhex(clean_str)

    # Check for 128-char hex (SHA-512)
    if len(clean_str) == 128 and all(c in "0123456789abcdefABCDEF" for c in clean_str):
        return "sha512", bytes.fromhex(clean_str)

    # Check for 40-char hex (SHA-1 / npm shasum)
    if len(clean_str) == 40 and all(c in "0123456789abcdefABCDEF" for c in clean_str):
        return "sha1", bytes.fromhex(clean_str)

    raise DownloadIntegrityError(f"Unrecognized integrity digest format: '{integrity_str}'")


def compute_file_hashes(file_path: str) -> Tuple[str, str]:
    """
    Computes both sha256 (hex) and sha512 (hex) of a local file in 64KB blocks.
    Returns (sha256_hex, sha512_hex).
    """
    h256 = hashlib.sha256()
    h512 = hashlib.sha512()

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h256.update(chunk)
            h512.update(chunk)

    return h256.hexdigest(), h512.hexdigest()


def verify_file_integrity(file_path: str, expected_integrity: str, expected_algo: Optional[str] = None) -> bool:
    """
    Validates a file on disk against the expected integrity string.
    Raises DownloadIntegrityError if mismatched or unparseable.
    """
    algo, expected_bytes = parse_integrity_string(expected_integrity)
    
    if expected_algo and expected_algo.lower() != algo:
        # If specified algo does not match parsed algo, verify parsed takes precedence
        pass

    try:
        hasher = hashlib.new(algo)
    except ValueError:
        raise DownloadIntegrityError(f"Unsupported hash algorithm: {algo}")

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            hasher.update(chunk)

    actual_bytes = hasher.digest()

    if not hmac.compare_digest(actual_bytes, expected_bytes):
        actual_hex = hasher.hexdigest()
        expected_hex = expected_bytes.hex()
        raise DownloadIntegrityError(
            f"Integrity check failed ({algo.upper()}). "
            f"Expected: {expected_hex[:16]}... Actual: {actual_hex[:16]}..."
        )

    return True
