"""
Validation and SSRF-hardened network utilities for package registry interactions.
"""

import socket
import ipaddress
import re
from urllib.parse import urlparse
from typing import Set, List
from engine.ingestion.models import (
    Ecosystem,
    CoordinateValidationError,
    SSRFSecurityError,
)

# Strict coordinate patterns
NPM_NAME_REGEX = re.compile(r"^(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+$")
PYPI_NAME_REGEX = re.compile(r"^[A-Za-z0-9_.-]+$")
VERSION_REGEX = re.compile(r"^[A-Za-z0-9_.-]+$")

# Official registry hostname allowlist
ALLOWED_REGISTRY_HOSTS: Set[str] = {
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
}

# Blocked IP networks (Carrier-grade NAT, private, documentation, etc.)
CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
DOC_NET1 = ipaddress.ip_network("192.0.2.0/24")
DOC_NET2 = ipaddress.ip_network("198.51.100.0/24")
DOC_NET3 = ipaddress.ip_network("203.0.113.0/24")


def validate_coordinates(ecosystem: Ecosystem, name: str, version: str) -> None:
    """
    Validates package name and version against ecosystem-specific strict schemas.
    Raises CoordinateValidationError if invalid.
    """
    if not name or not name.strip():
        raise CoordinateValidationError("Package name cannot be empty.")
    if not version or not version.strip():
        raise CoordinateValidationError("Package version cannot be empty.")

    clean_name = name.strip()
    clean_version = version.strip()

    if ecosystem == Ecosystem.NPM:
        if not NPM_NAME_REGEX.match(clean_name):
            raise CoordinateValidationError(f"Invalid npm package name format: '{clean_name}'")
    elif ecosystem == Ecosystem.PYPI:
        if not PYPI_NAME_REGEX.match(clean_name):
            raise CoordinateValidationError(f"Invalid PyPI package name format: '{clean_name}'")
    else:
        raise CoordinateValidationError(f"Unsupported ecosystem: {ecosystem}")

    if not VERSION_REGEX.match(clean_version):
        raise CoordinateValidationError(f"Invalid version format: '{clean_version}'")


def validate_ip_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    """
    Ensures an IP address is a public, routable destination.
    Rejects loopback, private, link-local, multicast, reserved, and documentation ranges.
    """
    # Check for IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        validate_ip_address(ip.ipv4_mapped)
        return

    if ip.is_loopback:
        raise SSRFSecurityError(f"Rejected loopback IP destination: {ip}")
    if ip.is_private:
        raise SSRFSecurityError(f"Rejected private network IP destination: {ip}")
    if ip.is_link_local:
        raise SSRFSecurityError(f"Rejected link-local IP destination: {ip}")
    if ip.is_multicast:
        raise SSRFSecurityError(f"Rejected multicast IP destination: {ip}")
    if ip.is_reserved:
        raise SSRFSecurityError(f"Rejected reserved IP destination: {ip}")
    if ip.is_unspecified:
        raise SSRFSecurityError(f"Rejected unspecified IP destination: {ip}")

    # Check IPv4 specific documentation / carrier-grade ranges
    if isinstance(ip, ipaddress.IPv4Address):
        if ip in CGNAT_NET:
            raise SSRFSecurityError(f"Rejected Carrier-Grade NAT IP: {ip}")
        if ip in DOC_NET1 or ip in DOC_NET2 or ip in DOC_NET3:
            raise SSRFSecurityError(f"Rejected documentation IP: {ip}")


def resolve_and_validate_hostname(hostname: str) -> List[str]:
    """
    Resolves hostname to IP addresses and validates all resolved IPs.
    Returns list of validated IP strings.
    """
    clean_host = hostname.strip().lower()
    if clean_host not in ALLOWED_REGISTRY_HOSTS:
        raise SSRFSecurityError(f"Hostname '{clean_host}' is not in the official registry allowlist.")

    try:
        addr_infos = socket.getaddrinfo(clean_host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SSRFSecurityError(f"DNS resolution failed for {clean_host}: {e}")

    if not addr_infos:
        raise SSRFSecurityError(f"No IP addresses returned for {clean_host}")

    validated_ips: List[str] = []
    for info in addr_infos:
        ip_str = info[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            validate_ip_address(ip_obj)
            if ip_str not in validated_ips:
                validated_ips.append(ip_str)
        except ValueError:
            raise SSRFSecurityError(f"Invalid IP address format resolved: {ip_str}")

    return validated_ips


def validate_registry_url(url: str) -> str:
    """
    Validates a registry or download URL against scheme, host allowlist, and SSRF rules.
    Returns normalized URL string.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise SSRFSecurityError(f"Insecure scheme '{parsed.scheme}'. Only HTTPS is permitted.")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise SSRFSecurityError(f"Missing hostname in URL: {url}")

    if hostname not in ALLOWED_REGISTRY_HOSTS:
        raise SSRFSecurityError(f"Host '{hostname}' is not in the allowed registry whitelist.")

    # Validate resolved IPs (checks against loopback, private ranges, etc.)
    resolve_and_validate_hostname(hostname)

    return url
