"""
Module A — Metadata and Publisher Analysis
Evaluates publication cadence, version jumps, repository consistency, and maintainer signals.
Enforces that missing signals are never treated as malicious.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import re
from urllib.parse import urlparse

from engine.schemas.finding import SecurityFinding, Severity, FindingCategory
from engine.ingestion.models import PackageCoordinates, Ecosystem

FREE_EMAIL_DOMAINS = {
    "gmail.com", "protonmail.com", "proton.me", "yahoo.com",
    "hotmail.com", "outlook.com", "mail.ru", "yandex.com"
}

POPULAR_REPO_ORGS = {
    "facebook", "google", "microsoft", "vercel", "angular",
    "vuejs", "airbnb", "palantir", "amazon", "aws", "netflix"
}


class MetadataAnalyzer:
    """
    Analyzes package publication metadata, author signals, and version histories.
    """

    def analyze(
        self,
        coords: PackageCoordinates,
        registry_metadata: Optional[Dict[str, Any]] = None,
        manifest_data: Optional[Dict[str, Any]] = None,
    ) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        if not registry_metadata and not manifest_data:
            # Metadata unavailable: do not raise false findings
            return findings

        reg_data = registry_metadata or {}
        pkg_data = manifest_data or {}

        # 1. Timeline & Release Frequency Analysis
        findings.extend(self._analyze_timeline(coords, reg_data))

        # 2. Version Jump / Anomaly Analysis
        findings.extend(self._analyze_version_anomalies(coords, reg_data))

        # 3. Repository & Provenance Consistency
        findings.extend(self._analyze_repository_consistency(coords, pkg_data, reg_data))

        # 4. Publisher / Maintainer Heuristics
        findings.extend(self._analyze_maintainers(coords, reg_data))

        return findings

    def _analyze_timeline(
        self, coords: PackageCoordinates, registry_metadata: Dict[str, Any]
    ) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        time_data = registry_metadata.get("time", {})
        if not time_data or not isinstance(time_data, dict):
            return findings

        # Parse timestamps for versions
        version_times = []
        for ver, t_str in time_data.items():
            if ver in ("created", "modified"):
                continue
            try:
                dt = datetime.fromisoformat(t_str.replace("Z", "+00:00"))
                version_times.append((ver, dt))
            except (ValueError, TypeError):
                continue

        if not version_times:
            return findings

        # Check for rapid release burst (>= 5 versions within 3 hours)
        version_times.sort(key=lambda x: x[1])
        for i in range(len(version_times)):
            window = [version_times[j] for j in range(i, len(version_times))
                      if (version_times[j][1] - version_times[i][1]).total_seconds() <= 10800]
            if len(window) >= 5:
                findings.append(SecurityFinding(
                    module="METADATA_ANALYZER",
                    rule_id="META_RAPID_RELEASE_BURST",
                    category=FindingCategory.METADATA,
                    severity=Severity.LOW,  # Weak signal as required
                    confidence=0.6,
                    title="Rapid Version Release Burst",
                    description=(
                        f"Detected {len(window)} releases within 3 hours. "
                        "Rapid release bursts may indicate automated scripting, typosquat flooding, or release pipeline churn."
                    ),
                    evidence={
                        "burst_count": len(window),
                        "window_start": window[0][1].isoformat(),
                        "window_end": window[-1][1].isoformat(),
                        "versions": [w[0] for w in window],
                    },
                    detection_method="REGISTRY_TIMELINE_ANALYSIS",
                ))
                break

        return findings

    def _analyze_version_anomalies(
        self, coords: PackageCoordinates, registry_metadata: Dict[str, Any]
    ) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        versions = registry_metadata.get("versions", {})
        if not isinstance(versions, dict) or not versions:
            return findings

        # Check for extreme version hijacking numbers (e.g. 99.0.0, 999.9.9) characteristic of dependency confusion
        try:
            semver_match = re.match(r"^(\d+)\.(\d+)\.(\d+)", coords.version)
            if semver_match:
                major = int(semver_match.group(1))
                if major >= 99:
                    findings.append(SecurityFinding(
                        module="METADATA_ANALYZER",
                        rule_id="META_SUSPICIOUS_MAJOR_VERSION",
                        category=FindingCategory.METADATA,
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        title="Abnormally High Major Version",
                        description=(
                            f"Version '{coords.version}' uses an unusually elevated major version ({major}). "
                            "This pattern is frequently observed in dependency confusion attacks designed to override internal feeds."
                        ),
                        evidence={"version": coords.version, "major": major},
                        detection_method="VERSION_NUMBER_HEURISTIC",
                    ))
        except Exception:
            pass

        return findings

    def _analyze_repository_consistency(
        self,
        coords: PackageCoordinates,
        manifest_data: Dict[str, Any],
        registry_metadata: Dict[str, Any],
    ) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        repo_url = ""
        # 1. From manifest (package.json)
        repo_field = manifest_data.get("repository", {})
        if isinstance(repo_field, dict):
            repo_url = repo_field.get("url", "")
        elif isinstance(repo_field, str):
            repo_url = repo_field

        # 2. From registry metadata
        if not repo_url:
            reg_repo = registry_metadata.get("repository", {})
            if isinstance(reg_repo, dict):
                repo_url = reg_repo.get("url", "")
            elif isinstance(reg_repo, str):
                repo_url = reg_repo

        if not repo_url:
            return findings

        try:
            parsed = urlparse(repo_url)
            path_parts = [p for p in parsed.path.strip("/").split("/") if p]
            if len(path_parts) >= 2:
                org, repo_name = path_parts[0].lower(), path_parts[1].lower()
                repo_name = repo_name.removesuffix(".git")

                # If claims popular org repo but package name is completely unrelated
                clean_pkg_name = coords.name.lower().split("/")[-1]
                if org in POPULAR_REPO_ORGS and repo_name not in clean_pkg_name and clean_pkg_name not in repo_name:
                    # Mismatch must NOT exceed MEDIUM severity per architectural constraints
                    findings.append(SecurityFinding(
                        module="METADATA_ANALYZER",
                        rule_id="META_REPO_MISMATCH_SUSPICIOUS",
                        category=FindingCategory.METADATA,
                        severity=Severity.MEDIUM,
                        confidence=0.65,
                        title="Repository Provenance Mismatch",
                        description=(
                            f"Package metadata references high-profile repository '{org}/{repo_name}', "
                            f"which diverges from package name '{coords.name}'. "
                            "Attackers sometimes point to legitimate repositories to fabricate false credibility."
                        ),
                        evidence={
                            "declared_repo": f"{org}/{repo_name}",
                            "package_name": coords.name,
                            "url": repo_url,
                        },
                        detection_method="PROVENANCE_CONSISTENCY_CHECK",
                    ))
        except Exception:
            pass

        return findings

    def _analyze_maintainers(
        self, coords: PackageCoordinates, registry_metadata: Dict[str, Any]
    ) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        # Maintainer list from registry
        maintainers = registry_metadata.get("maintainers", [])
        if not isinstance(maintainers, list):
            return findings

        for m in maintainers:
            if not isinstance(m, dict):
                continue
            email = (m.get("email") or "").lower()
            name = m.get("name") or "unknown"
            if "@" in email:
                domain = email.split("@")[-1]
                if domain in FREE_EMAIL_DOMAINS:
                    # Free email domain is a weak signal (LOW severity)
                    findings.append(SecurityFinding(
                        module="METADATA_ANALYZER",
                        rule_id="META_FREE_EMAIL_MAINTAINER",
                        category=FindingCategory.METADATA,
                        severity=Severity.LOW,
                        confidence=0.4,
                        title="Maintainer Free Email Domain",
                        description=f"Maintainer '{name}' registered with disposable/free email provider ({domain}).",
                        evidence={"maintainer": name, "domain": domain},
                        detection_method="AUTHOR_EMAIL_REPUTATION",
                    ))

        return findings

