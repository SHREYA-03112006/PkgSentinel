"""
Secure registry metadata resolver and package archive streaming downloader.
"""

import os
import tempfile
import urllib.parse
from typing import Optional, Dict, Any, List
import httpx
from packaging.version import parse as parse_version

from engine.ingestion.models import (
    Ecosystem,
    DistributionType,
    PackageCoordinates,
    ResolvedDistribution,
    RegistryResolutionError,
    DownloadSizeLimitError,
    SSRFSecurityError,
)
from engine.ingestion.registry_client import (
    validate_coordinates,
    validate_registry_url,
)
from engine.ingestion.integrity import verify_file_integrity, compute_file_hashes

DEFAULT_MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024  # 100 MB
CONNECT_TIMEOUT_SECS = 10.0
READ_TIMEOUT_SECS = 30.0


def is_latest_version(version: Optional[str]) -> bool:
    """Returns True if the requested version indicates resolving the latest release."""
    return not version or not version.strip() or version.strip().lower() == "latest"


def is_stable_release(version_str: str) -> bool:
    """Returns True if the version string represents a stable release (excluding prereleases/dev releases)."""
    try:
        parsed = parse_version(version_str)
        return not (parsed.is_prerelease or parsed.is_devrelease)
    except Exception:
        lower = version_str.lower()
        return not any(marker in lower for marker in ("a", "b", "rc", "dev", "alpha", "beta", "preview"))


class RegistryDownloader:
    """
    Handles metadata resolution and safe streaming archive downloads for npm and PyPI.
    """

    def __init__(
        self,
        max_download_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES,
        client: Optional[httpx.Client] = None,
        skip_dns_validation: bool = False,
    ):
        self.max_download_bytes = max_download_bytes
        self.skip_dns_validation = skip_dns_validation
        
        # Enforce no environment proxies, explicit timeouts, strict TLS verification
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(READ_TIMEOUT_SECS, connect=CONNECT_TIMEOUT_SECS),
            follow_redirects=False,
            trust_env=False,
            verify=True,
        )

    def resolve_distribution(self, coords: PackageCoordinates) -> ResolvedDistribution:
        """
        Queries official registry API to resolve distribution artifact URL and integrity digest.
        """
        validate_coordinates(coords.ecosystem, coords.name, coords.version)

        if coords.ecosystem == Ecosystem.NPM:
            return self._resolve_npm(coords)
        elif coords.ecosystem == Ecosystem.PYPI:
            return self._resolve_pypi(coords)
        else:
            raise RegistryResolutionError(f"Unsupported ecosystem: {coords.ecosystem}")

    def _resolve_npm(self, coords: PackageCoordinates) -> ResolvedDistribution:
        encoded_name = urllib.parse.quote(coords.name, safe="@")
        metadata_url = f"https://registry.npmjs.org/{encoded_name}"
        
        if not self.skip_dns_validation:
            validate_registry_url(metadata_url)

        try:
            resp = self._client.get(metadata_url)
        except Exception as e:
            raise RegistryResolutionError(f"Failed to fetch npm metadata for {coords.name}: {e}")

        if resp.status_code == 404:
            raise RegistryResolutionError(f"Package '{coords.name}' not found on npm registry.")
        if resp.status_code != 200:
            raise RegistryResolutionError(f"npm registry returned HTTP {resp.status_code} for {coords.name}")

        try:
            data = resp.json()
        except Exception as e:
            raise RegistryResolutionError(f"Malformed JSON from npm registry: {e}")

        versions: Dict[str, Any] = data.get("versions", {})
        if not versions:
            raise RegistryResolutionError(f"No versions found for npm package '{coords.name}'.")

        # Determine target version without ever passing literal 'latest' into exact-version lookup
        target_version = coords.version
        if is_latest_version(target_version):
            dist_tags = data.get("dist-tags", {})
            latest_from_tag = dist_tags.get("latest")
            if latest_from_tag and latest_from_tag in versions:
                resolved_version = latest_from_tag
            else:
                # Fallback: resolve the latest stable release from versions dictionary
                stable_versions = [v for v in versions.keys() if is_stable_release(v)]
                candidates = stable_versions if stable_versions else list(versions.keys())
                try:
                    resolved_version = max(candidates, key=parse_version)
                except Exception:
                    resolved_version = candidates[-1]
        else:
            resolved_version = target_version.strip()

        version_data = versions.get(resolved_version)
        if not version_data:
            raise RegistryResolutionError(
                f"Version '{resolved_version}' not found for npm package '{coords.name}'. "
                f"Available versions count: {len(versions)}"
            )

        dist: Dict[str, Any] = version_data.get("dist", {})
        tarball_url = dist.get("tarball")
        if not tarball_url:
            raise RegistryResolutionError(f"Missing tarball URL in npm metadata for {coords.name}@{resolved_version}")

        # Check integrity: prefer SRI integrity (sha512), fallback to shasum (sha1)
        integrity_val = dist.get("integrity")
        algo = "sha512"
        if not integrity_val:
            integrity_val = dist.get("shasum")
            algo = "sha1"

        if not integrity_val:
            raise RegistryResolutionError(f"Missing integrity digest in npm metadata for {coords.name}@{resolved_version}")

        filename = os.path.basename(urllib.parse.urlparse(tarball_url).path)
        release_date = data.get("time", {}).get(resolved_version)

        return ResolvedDistribution(
            filename=filename,
            download_url=tarball_url,
            dist_type=DistributionType.NPM_TARBALL,
            integrity_value=integrity_val,
            integrity_algo=algo,
            size_bytes=dist.get("unpackedSize"),
            release_date=release_date,
            resolved_version=resolved_version,
        )

    def _resolve_pypi(self, coords: PackageCoordinates) -> ResolvedDistribution:
        metadata_url = f"https://pypi.org/pypi/{coords.name}/json"

        if not self.skip_dns_validation:
            validate_registry_url(metadata_url)

        try:
            resp = self._client.get(metadata_url)
        except Exception as e:
            raise RegistryResolutionError(f"Failed to fetch PyPI metadata for {coords.name}: {e}")

        if resp.status_code == 404:
            raise RegistryResolutionError(f"Package '{coords.name}' not found on PyPI registry.")
        if resp.status_code != 200:
            raise RegistryResolutionError(f"PyPI registry returned HTTP {resp.status_code} for {coords.name}")

        try:
            data = resp.json()
        except Exception as e:
            raise RegistryResolutionError(f"Malformed JSON from PyPI registry: {e}")

        releases: Dict[str, Any] = data.get("releases", {})
        if not releases:
            raise RegistryResolutionError(f"No releases found for PyPI package '{coords.name}'.")

        # Determine target version without ever passing literal 'latest' into exact-version lookup
        target_version = coords.version
        if is_latest_version(target_version):
            # Resolve the latest stable release from metadata
            candidate_versions = [v for v, files in releases.items() if files]
            if not candidate_versions:
                candidate_versions = list(releases.keys())

            stable_versions = [v for v in candidate_versions if is_stable_release(v)]
            info_version = data.get("info", {}).get("version")

            if stable_versions:
                try:
                    resolved_version = str(max(stable_versions, key=parse_version))
                except Exception:
                    resolved_version = stable_versions[-1]
            elif info_version and info_version in releases and releases[info_version]:
                resolved_version = info_version
            elif candidate_versions:
                try:
                    resolved_version = str(max(candidate_versions, key=parse_version))
                except Exception:
                    resolved_version = candidate_versions[-1]
            else:
                raise RegistryResolutionError(f"No valid releases available for PyPI package '{coords.name}'.")
        else:
            resolved_version = target_version.strip()

        release_files = releases.get(resolved_version)
        if not release_files:
            raise RegistryResolutionError(
                f"Version '{resolved_version}' not found for PyPI package '{coords.name}'."
            )

        # Selection strategy: prefer bdist_wheel (.whl), fallback to sdist (.tar.gz / .zip)
        selected_file = None
        for f in release_files:
            if f.get("packagetype") == "bdist_wheel" and f.get("filename", "").endswith(".whl"):
                selected_file = f
                dist_type = DistributionType.PYPI_WHEEL
                break

        if not selected_file:
            for f in release_files:
                if f.get("packagetype") == "sdist":
                    selected_file = f
                    dist_type = DistributionType.PYPI_SDIST
                    break

        if not selected_file:
            # Take the first available file if neither wheel nor standard sdist matched
            selected_file = release_files[0]
            fname = selected_file.get("filename", "")
            dist_type = DistributionType.PYPI_WHEEL if fname.endswith(".whl") else DistributionType.PYPI_SDIST

        download_url = selected_file.get("url")
        if not download_url:
            raise RegistryResolutionError(f"Missing download URL in PyPI file entry for {coords.name}@{resolved_version}")

        digests = selected_file.get("digests", {})
        sha256_digest = digests.get("sha256")
        algo = "sha256"

        if not sha256_digest:
            sha256_digest = selected_file.get("md5_digest")
            algo = "md5"

        if not sha256_digest:
            raise RegistryResolutionError(f"Missing integrity digest in PyPI metadata for {coords.name}@{resolved_version}")

        filename = selected_file.get("filename") or os.path.basename(urllib.parse.urlparse(download_url).path)
        upload_time = selected_file.get("upload_time_iso_8601")

        return ResolvedDistribution(
            filename=filename,
            download_url=download_url,
            dist_type=dist_type,
            integrity_value=sha256_digest,
            integrity_algo=algo,
            size_bytes=selected_file.get("size"),
            release_date=upload_time,
            resolved_version=resolved_version,
        )

    def download_archive(self, dist: ResolvedDistribution, destination_dir: str) -> str:
        """
        Streams package archive into a temporary file in destination_dir, enforces maximum size,
        verifies cryptographic integrity, and atomically finalizes to target path.
        Returns final path to downloaded archive on disk.
        """
        if not self.skip_dns_validation:
            validate_registry_url(dist.download_url)

        os.makedirs(destination_dir, exist_ok=True)
        final_path = os.path.join(destination_dir, dist.filename)

        # Temporary file created in the same destination directory for atomic rename
        temp_fd, temp_path = tempfile.mkstemp(prefix="pkg_dl_", dir=destination_dir)
        os.close(temp_fd)

        try:
            with open(temp_path, "wb") as f_out:
                with self._client.stream("GET", dist.download_url) as resp:
                    # Enforce strict redirect check
                    if resp.status_code in (301, 302, 303, 307, 308):
                        redirect_url = resp.headers.get("location")
                        if not redirect_url:
                            raise SSRFSecurityError("Redirect received without Location header.")
                        if not self.skip_dns_validation:
                            validate_registry_url(redirect_url)
                        raise SSRFSecurityError(f"Unexpected redirect to '{redirect_url}'. Direct download required.")

                    if resp.status_code != 200:
                        raise RegistryResolutionError(f"Failed download: HTTP {resp.status_code} from {dist.download_url}")

                    total_bytes = 0
                    for chunk in resp.iter_bytes(chunk_size=65536):
                        total_bytes += len(chunk)
                        if total_bytes > self.max_download_bytes:
                            raise DownloadSizeLimitError(
                                f"Package download exceeded maximum limit of {self.max_download_bytes} bytes "
                                f"(downloaded {total_bytes} bytes so far)."
                            )
                        f_out.write(chunk)
                    f_out.flush()
                    os.fsync(f_out.fileno())

            # Verify cryptographic integrity
            verify_file_integrity(temp_path, dist.integrity_value, dist.integrity_algo)

            # Atomic move to final destination
            if os.path.exists(final_path):
                os.remove(final_path)
            os.replace(temp_path, final_path)
            return final_path

        except Exception:
            # Clean up partial download immediately
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            raise

