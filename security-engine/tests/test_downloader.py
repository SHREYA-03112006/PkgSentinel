"""
Unit and security tests for RegistryDownloader, coordinate validation, and SSRF defenses.
"""

import os
import tempfile
import pytest
import httpx
import ipaddress

from engine.ingestion.models import (
    Ecosystem,
    PackageCoordinates,
    CoordinateValidationError,
    RegistryResolutionError,
    SSRFSecurityError,
    DownloadIntegrityError,
    DownloadSizeLimitError,
)
from engine.ingestion.registry_client import (
    validate_coordinates,
    validate_registry_url,
    validate_ip_address,
)
from engine.ingestion.registry_downloader import RegistryDownloader


def test_coordinate_validation_npm():
    # Valid npm coordinates
    validate_coordinates(Ecosystem.NPM, "express", "4.18.2")
    validate_coordinates(Ecosystem.NPM, "@angular/core", "16.0.0")
    validate_coordinates(Ecosystem.NPM, "left-pad", "1.3.0")

    # Invalid names
    with pytest.raises(CoordinateValidationError):
        validate_coordinates(Ecosystem.NPM, "express; rm -rf /", "1.0.0")
    with pytest.raises(CoordinateValidationError):
        validate_coordinates(Ecosystem.NPM, "../express", "1.0.0")
    with pytest.raises(CoordinateValidationError):
        validate_coordinates(Ecosystem.NPM, "", "1.0.0")
    with pytest.raises(CoordinateValidationError):
        validate_coordinates(Ecosystem.NPM, "express", "1.0/../../evil")


def test_coordinate_validation_pypi():
    # Valid PyPI coordinates
    validate_coordinates(Ecosystem.PYPI, "requests", "2.31.0")
    validate_coordinates(Ecosystem.PYPI, "scikit-learn", "1.3.0")

    # Invalid names
    with pytest.raises(CoordinateValidationError):
        validate_coordinates(Ecosystem.PYPI, "requests/../malicious", "1.0.0")
    with pytest.raises(CoordinateValidationError):
        validate_coordinates(Ecosystem.PYPI, "requests$", "1.0.0")


def test_ssrf_ip_validation():
    # Public IP should pass
    validate_ip_address(ipaddress.ip_address("151.101.1.69"))

    # Loopback addresses
    with pytest.raises(SSRFSecurityError):
        validate_ip_address(ipaddress.ip_address("127.0.0.1"))
    with pytest.raises(SSRFSecurityError):
        validate_ip_address(ipaddress.ip_address("::1"))

    # Private network addresses (RFC 1918)
    with pytest.raises(SSRFSecurityError):
        validate_ip_address(ipaddress.ip_address("10.0.0.1"))
    with pytest.raises(SSRFSecurityError):
        validate_ip_address(ipaddress.ip_address("172.16.0.1"))
    with pytest.raises(SSRFSecurityError):
        validate_ip_address(ipaddress.ip_address("192.168.1.1"))

    # Link-local / Cloud metadata (169.254.169.254)
    with pytest.raises(SSRFSecurityError):
        validate_ip_address(ipaddress.ip_address("169.254.169.254"))

    # Multicast / Carrier-grade NAT
    with pytest.raises(SSRFSecurityError):
        validate_ip_address(ipaddress.ip_address("224.0.0.1"))
    with pytest.raises(SSRFSecurityError):
        validate_ip_address(ipaddress.ip_address("100.64.0.1"))

    # IPv4-mapped IPv6 loopback
    with pytest.raises(SSRFSecurityError):
        validate_ip_address(ipaddress.ip_address("::ffff:127.0.0.1"))


def test_ssrf_url_validation_disallowed_host():
    with pytest.raises(SSRFSecurityError):
        validate_registry_url("https://malicious-registry.com/package.tgz")
    with pytest.raises(SSRFSecurityError):
        validate_registry_url("http://registry.npmjs.org/package.tgz")  # Insecure HTTP


def test_npm_metadata_resolution():
    npm_mock_response = {
        "name": "test-pkg",
        "versions": {
            "1.0.0": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz",
                    "integrity": "sha512-H1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7==",
                    "unpackedSize": 1024
                }
            }
        },
        "time": {
            "1.0.0": "2026-01-01T00:00:00.000Z"
        }
    }

    def handler(request: httpx.Request):
        assert request.url == "https://registry.npmjs.org/test-pkg"
        return httpx.Response(200, json=npm_mock_response)

    transport = httpx.MockTransport(handler)
    mock_client = httpx.Client(transport=transport)
    downloader = RegistryDownloader(client=mock_client, skip_dns_validation=True)

    dist = downloader.resolve_distribution(PackageCoordinates(
        ecosystem=Ecosystem.NPM,
        name="test-pkg",
        version="1.0.0"
    ))

    assert dist.filename == "test-pkg-1.0.0.tgz"
    assert dist.download_url == "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz"
    assert dist.integrity_algo == "sha512"


def test_npm_scoped_package_resolution():
    def handler(request: httpx.Request):
        # Must quote @scope/pkg as @scope%2Fpkg
        assert "registry.npmjs.org/@scope%2Fpkg" in str(request.url)
        return httpx.Response(200, json={
            "versions": {
                "2.0.0": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz",
                        "shasum": "a9993e364706816aba3e25717850c26c9cd0d89d"
                    }
                }
            }
        })

    mock_client = httpx.Client(transport=httpx.MockTransport(handler))
    downloader = RegistryDownloader(client=mock_client, skip_dns_validation=True)

    dist = downloader.resolve_distribution(PackageCoordinates(
        ecosystem=Ecosystem.NPM,
        name="@scope/pkg",
        version="2.0.0"
    ))

    assert dist.filename == "pkg-2.0.0.tgz"
    assert dist.integrity_algo == "sha1"


def test_pypi_metadata_resolution_prefers_wheel():
    pypi_mock_response = {
        "releases": {
            "3.1.0": [
                {
                    "filename": "mypkg-3.1.0.tar.gz",
                    "packagetype": "sdist",
                    "url": "https://files.pythonhosted.org/packages/source/m/mypkg/mypkg-3.1.0.tar.gz",
                    "digests": {"sha256": "aaaa" * 16}
                },
                {
                    "filename": "mypkg-3.1.0-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": "https://files.pythonhosted.org/packages/wheel/m/mypkg/mypkg-3.1.0-py3-none-any.whl",
                    "digests": {"sha256": "bbbb" * 16}
                }
            ]
        }
    }

    def handler(request: httpx.Request):
        return httpx.Response(200, json=pypi_mock_response)

    mock_client = httpx.Client(transport=httpx.MockTransport(handler))
    downloader = RegistryDownloader(client=mock_client, skip_dns_validation=True)

    dist = downloader.resolve_distribution(PackageCoordinates(
        ecosystem=Ecosystem.PYPI,
        name="mypkg",
        version="3.1.0"
    ))

    assert dist.filename == "mypkg-3.1.0-py3-none-any.whl"
    assert dist.integrity_value == "bbbb" * 16


def test_missing_version_raises_registry_error():
    mock_client = httpx.Client(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, json={"versions": {}})
    ))
    downloader = RegistryDownloader(client=mock_client, skip_dns_validation=True)

    with pytest.raises(RegistryResolutionError):
        downloader.resolve_distribution(PackageCoordinates(
            ecosystem=Ecosystem.NPM,
            name="pkg",
            version="99.9.9"
        ))


def test_oversized_download_raises_size_limit_error():
    # Return 1000 chunks of 1KB to exceed a 500-byte limit
    chunk = b"A" * 1024

    def handler(request: httpx.Request):
        return httpx.Response(200, content=chunk * 5)

    mock_client = httpx.Client(transport=httpx.MockTransport(handler))
    downloader = RegistryDownloader(max_download_bytes=1024, client=mock_client, skip_dns_validation=True)

    with tempfile.TemporaryDirectory() as tmp_dir:
        from engine.ingestion.models import ResolvedDistribution, DistributionType
        dist = ResolvedDistribution(
            filename="large.tgz",
            download_url="https://registry.npmjs.org/large.tgz",
            dist_type=DistributionType.NPM_TARBALL,
            integrity_value="any",
            integrity_algo="sha256"
        )
        with pytest.raises(DownloadSizeLimitError):
            downloader.download_archive(dist, tmp_dir)

        # Verify partial file is completely cleaned up
        assert len(os.listdir(tmp_dir)) == 0


def test_integrity_verification_failure_cleans_up():
    content = b"malicious or altered payload bytes"

    def handler(request: httpx.Request):
        return httpx.Response(200, content=content)

    mock_client = httpx.Client(transport=httpx.MockTransport(handler))
    downloader = RegistryDownloader(client=mock_client, skip_dns_validation=True)

    with tempfile.TemporaryDirectory() as tmp_dir:
        from engine.ingestion.models import ResolvedDistribution, DistributionType
        dist = ResolvedDistribution(
            filename="altered.tgz",
            download_url="https://registry.npmjs.org/altered.tgz",
            dist_type=DistributionType.NPM_TARBALL,
            integrity_value="0000000000000000000000000000000000000000000000000000000000000000",
            integrity_algo="sha256"
        )
        with pytest.raises(DownloadIntegrityError):
            downloader.download_archive(dist, tmp_dir)

        # Temporary files must be cleaned up
        assert len(os.listdir(tmp_dir)) == 0


def test_npm_version_resolution_latest_dist_tags():
    npm_payload = {
        "name": "express",
        "dist-tags": {
            "latest": "4.21.1",
            "next": "5.0.0-beta.3"
        },
        "versions": {
            "4.20.0": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/express/-/express-4.20.0.tgz",
                    "integrity": "sha512-4200==",
                    "unpackedSize": 500
                }
            },
            "4.21.1": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/express/-/express-4.21.1.tgz",
                    "integrity": "sha512-4211==",
                    "unpackedSize": 600
                }
            },
            "5.0.0-beta.3": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/express/-/express-5.0.0-beta.3.tgz",
                    "integrity": "sha512-5000==",
                    "unpackedSize": 700
                }
            }
        },
        "time": {
            "4.21.1": "2026-10-01T12:00:00.000Z"
        }
    }

    mock_client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json=npm_payload)))
    downloader = RegistryDownloader(client=mock_client, skip_dns_validation=True)

    # 1. Version 'latest' (case-insensitive)
    dist = downloader.resolve_distribution(PackageCoordinates(
        ecosystem=Ecosystem.NPM,
        name="express",
        version="latest"
    ))
    assert dist.resolved_version == "4.21.1"
    assert dist.filename == "express-4.21.1.tgz"
    assert dist.download_url == "https://registry.npmjs.org/express/-/express-4.21.1.tgz"


def test_npm_version_resolution_omitted_version():
    npm_payload = {
        "name": "express",
        "dist-tags": {"latest": "4.21.1"},
        "versions": {
            "4.21.1": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/express/-/express-4.21.1.tgz",
                    "integrity": "sha512-4211==",
                }
            }
        }
    }

    mock_client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json=npm_payload)))
    downloader = RegistryDownloader(client=mock_client, skip_dns_validation=True)

    # 2. Version omitted (None or default)
    dist_none = downloader.resolve_distribution(PackageCoordinates(
        ecosystem=Ecosystem.NPM,
        name="express",
        version=None
    ))
    assert dist_none.resolved_version == "4.21.1"

    dist_default = downloader.resolve_distribution(PackageCoordinates(
        ecosystem=Ecosystem.NPM,
        name="express"
    ))
    assert dist_default.resolved_version == "4.21.1"


def test_npm_version_resolution_explicit_version():
    npm_payload = {
        "name": "express",
        "dist-tags": {"latest": "4.21.1"},
        "versions": {
            "4.18.2": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
                    "integrity": "sha512-4182==",
                }
            },
            "4.21.1": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/express/-/express-4.21.1.tgz",
                    "integrity": "sha512-4211==",
                }
            }
        }
    }

    mock_client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json=npm_payload)))
    downloader = RegistryDownloader(client=mock_client, skip_dns_validation=True)

    # 3. Explicit version supported
    dist = downloader.resolve_distribution(PackageCoordinates(
        ecosystem=Ecosystem.NPM,
        name="express",
        version="4.18.2"
    ))
    assert dist.resolved_version == "4.18.2"
    assert dist.download_url == "https://registry.npmjs.org/express/-/express-4.18.2.tgz"

    # Explicit version not found raises RegistryResolutionError
    with pytest.raises(RegistryResolutionError) as exc_info:
        downloader.resolve_distribution(PackageCoordinates(
            ecosystem=Ecosystem.NPM,
            name="express",
            version="99.99.99"
        ))
    assert "Version '99.99.99' not found" in str(exc_info.value)


def test_npm_version_resolution_fallback_to_highest_stable():
    # If dist-tags is absent or missing 'latest'
    npm_payload = {
        "name": "legacy-pkg",
        "dist-tags": {},
        "versions": {
            "1.0.0": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/legacy-pkg/-/legacy-pkg-1.0.0.tgz",
                    "integrity": "sha512-100==",
                }
            },
            "2.1.0": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/legacy-pkg/-/legacy-pkg-2.1.0.tgz",
                    "integrity": "sha512-210==",
                }
            },
            "3.0.0-alpha.1": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/legacy-pkg/-/legacy-pkg-3.0.0-alpha.1.tgz",
                    "integrity": "sha512-300==",
                }
            }
        }
    }

    mock_client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json=npm_payload)))
    downloader = RegistryDownloader(client=mock_client, skip_dns_validation=True)

    dist = downloader.resolve_distribution(PackageCoordinates(
        ecosystem=Ecosystem.NPM,
        name="legacy-pkg",
        version="latest"
    ))
    # Should resolve to 2.1.0 (highest stable), ignoring 3.0.0-alpha.1
    assert dist.resolved_version == "2.1.0"


def test_pypi_version_resolution_latest_stable():
    pypi_payload = {
        "info": {
            "name": "requests",
            "version": "2.32.3"
        },
        "releases": {
            "2.31.0": [
                {
                    "filename": "requests-2.31.0-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": "https://files.pythonhosted.org/requests-2.31.0.whl",
                    "digests": {"sha256": "1111" * 16}
                }
            ],
            "2.32.3": [
                {
                    "filename": "requests-2.32.3-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": "https://files.pythonhosted.org/requests-2.32.3.whl",
                    "digests": {"sha256": "2222" * 16}
                }
            ],
            "3.0.0b1": [
                {
                    "filename": "requests-3.0.0b1-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": "https://files.pythonhosted.org/requests-3.0.0b1.whl",
                    "digests": {"sha256": "3333" * 16}
                }
            ]
        }
    }

    mock_client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json=pypi_payload)))
    downloader = RegistryDownloader(client=mock_client, skip_dns_validation=True)

    dist = downloader.resolve_distribution(PackageCoordinates(
        ecosystem=Ecosystem.PYPI,
        name="requests",
        version="latest"
    ))
    # Must resolve 2.32.3, not the prerelease 3.0.0b1
    assert dist.resolved_version == "2.32.3"
    assert dist.filename == "requests-2.32.3-py3-none-any.whl"


def test_pypi_version_resolution_omitted_version():
    pypi_payload = {
        "info": {
            "name": "requests",
            "version": "2.32.3"
        },
        "releases": {
            "2.32.3": [
                {
                    "filename": "requests-2.32.3-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": "https://files.pythonhosted.org/requests-2.32.3.whl",
                    "digests": {"sha256": "2222" * 16}
                }
            ]
        }
    }

    mock_client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json=pypi_payload)))
    downloader = RegistryDownloader(client=mock_client, skip_dns_validation=True)

    dist_none = downloader.resolve_distribution(PackageCoordinates(
        ecosystem=Ecosystem.PYPI,
        name="requests",
        version=None
    ))
    assert dist_none.resolved_version == "2.32.3"

    dist_omitted = downloader.resolve_distribution(PackageCoordinates(
        ecosystem=Ecosystem.PYPI,
        name="requests"
    ))
    assert dist_omitted.resolved_version == "2.32.3"


def test_pypi_version_resolution_explicit_version():
    pypi_payload = {
        "info": {"version": "2.32.3"},
        "releases": {
            "2.31.0": [
                {
                    "filename": "requests-2.31.0-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": "https://files.pythonhosted.org/requests-2.31.0.whl",
                    "digests": {"sha256": "1111" * 16}
                }
            ],
            "2.32.3": [
                {
                    "filename": "requests-2.32.3-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": "https://files.pythonhosted.org/requests-2.32.3.whl",
                    "digests": {"sha256": "2222" * 16}
                }
            ]
        }
    }

    mock_client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json=pypi_payload)))
    downloader = RegistryDownloader(client=mock_client, skip_dns_validation=True)

    dist = downloader.resolve_distribution(PackageCoordinates(
        ecosystem=Ecosystem.PYPI,
        name="requests",
        version="2.31.0"
    ))
    assert dist.resolved_version == "2.31.0"

    with pytest.raises(RegistryResolutionError) as exc_info:
        downloader.resolve_distribution(PackageCoordinates(
            ecosystem=Ecosystem.PYPI,
            name="requests",
            version="99.99.99"
        ))
    assert "Version '99.99.99' not found" in str(exc_info.value)


def test_never_lookup_literal_latest_as_exact_key():
    # If a malicious or malformed registry response happens to have a literal key "latest" in versions
    npm_payload = {
        "name": "tricky-pkg",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "latest": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/tricky-pkg/-/tricky-pkg-evil.tgz",
                    "integrity": "sha512-evil==",
                }
            },
            "1.0.0": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/tricky-pkg/-/tricky-pkg-1.0.0.tgz",
                    "integrity": "sha512-good==",
                }
            }
        }
    }

    mock_client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json=npm_payload)))
    downloader = RegistryDownloader(client=mock_client, skip_dns_validation=True)

    dist = downloader.resolve_distribution(PackageCoordinates(
        ecosystem=Ecosystem.NPM,
        name="tricky-pkg",
        version="latest"
    ))
    # It must resolve via dist-tags to 1.0.0, NEVER picking the literal "latest" key!
    assert dist.resolved_version == "1.0.0"
    assert "tricky-pkg-1.0.0.tgz" in dist.filename


