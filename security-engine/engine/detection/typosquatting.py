"""
Module B — Typosquatting Detection Engine
Implements length-bounded Damerau-Levenshtein, homoglyphs, PyPI normalization,
and scope-aware proximity matching against curated reference packages.
"""

import re
import unicodedata
from typing import List, Dict, Tuple, Optional

from engine.schemas.finding import SecurityFinding, Severity, FindingCategory
from engine.ingestion.models import PackageCoordinates, Ecosystem

# Reference Popular Packages Dataset (Curated top ecosystem libraries)
POPULAR_NPM_PACKAGES = {
    "react", "react-dom", "lodash", "express", "chalk", "axios",
    "commander", "tslib", "typescript", "debug", "moment", "dotenv",
    "cors", "glob", "async", "uuid", "webpack", "babel", "rxjs",
    "yargs", "request", "core-js", "semver", "bluebird", "inquirer",
    "winston", "morgan", "body-parser", "jest", "next", "vue"
}

POPULAR_PYPI_PACKAGES = {
    "requests", "urllib3", "numpy", "pandas", "flask", "django",
    "scipy", "pytest", "boto3", "cryptography", "certifi", "click",
    "pydantic", "httpx", "six", "jinja2", "setuptools", "wheel",
    "pip", "virtualenv", "scikit-learn", "tensorflow", "torch",
    "pillow", "sqlalchemy", "celery", "pyyaml", "fastapi"
}

# Homoglyph translation map (Confusables: Cyrillic/Greek/Lookalikes to Latin ASCII)
HOMOGLYPH_MAP = {
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ո": "n", "0": "o", "1": "l"
}


def pypi_normalize(name: str) -> str:
    """Implements PEP 503 package name normalization: lowercase, [-_.]+ collapsed to '-'."""
    return re.sub(r"[-_.]+", "-", name).lower()


def damerau_levenshtein_distance(s1: str, s2: str, max_dist: int = 2) -> int:
    """
    Computes Damerau-Levenshtein distance (insertions, deletions, substitutions, transpositions).
    Returns exact distance if <= max_dist, else returns max_dist + 1 (length-bounded optimization).
    """
    len1, len2 = len(s1), len(s2)
    if abs(len1 - len2) > max_dist:
        return max_dist + 1

    # Damerau-Levenshtein matrix
    d: Dict[Tuple[int, int], int] = {}
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,        # deletion
                d[(i, j - 1)] + 1,        # insertion
                d[(i - 1, j - 1)] + cost  # substitution
            )
            # Transposition of adjacent characters
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)

    return d[(len1 - 1, len2 - 1)]


def check_homoglyphs(target: str, reference: str) -> Optional[str]:
    """
    Checks if target is identical to reference after homoglyph substitution.
    Returns normalized string if homoglyph match detected, else None.
    """
    if target == reference:
        return None

    # Replace known confusables
    normalized_target = "".join(HOMOGLYPH_MAP.get(c, c) for c in target)
    if normalized_target == reference:
        return normalized_target
    return None


class TyposquattingDetector:
    """
    Detects typosquatting, character transposition, homoglyphs, and combo-squatting
    against reference popular packages.
    """

    def __init__(
        self,
        npm_reference: Optional[set] = None,
        pypi_reference: Optional[set] = None,
    ):
        self.npm_reference = npm_reference or POPULAR_NPM_PACKAGES
        self.pypi_reference = pypi_reference or POPULAR_PYPI_PACKAGES

    def analyze(self, coords: PackageCoordinates) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        is_npm = coords.ecosystem == Ecosystem.NPM
        raw_name = coords.name.lower()
        ref_set = self.npm_reference if is_npm else self.pypi_reference

        # Handle npm scopes: @scope/pkg -> examine 'pkg' against reference
        compare_name = raw_name
        if is_npm and "/" in raw_name:
            compare_name = raw_name.split("/", 1)[1]
        elif not is_npm:
            compare_name = pypi_normalize(raw_name)

        # If exactly equal to reference package, it's the legitimate package itself
        if compare_name in ref_set or raw_name in ref_set:
            return findings

        for ref_pkg in ref_set:
            norm_ref = ref_pkg if is_npm else pypi_normalize(ref_pkg)

            # 1. Homoglyph check
            homoglyph_match = check_homoglyphs(compare_name, norm_ref)
            if homoglyph_match:
                findings.append(SecurityFinding(
                    module="TYPOSQUATTING_DETECTOR",
                    rule_id="TYPO_HOMOGLYPH_ATTACK",
                    category=FindingCategory.TYPOSQUATTING,
                    severity=Severity.HIGH,
                    confidence=0.90,
                    title="Homoglyph Typosquatting Detected",
                    description=(
                        f"Package '{coords.name}' visually mimics legitimate library '{ref_pkg}' "
                        "using lookalike Unicode / confusable characters."
                    ),
                    evidence={
                        "target_name": coords.name,
                        "reference_package": ref_pkg,
                        "technique": "HOMOGLYPH_SUBSTITUTION",
                        "normalized": homoglyph_match,
                    },
                    detection_method="HOMOGLYPH_MAPPING",
                ))
                continue

            # 2. Length-bounded Damerau-Levenshtein
            dist = damerau_levenshtein_distance(compare_name, norm_ref, max_dist=2)

            if dist == 1:
                # Single edit (transposition, omission, substitution)
                findings.append(SecurityFinding(
                    module="TYPOSQUATTING_DETECTOR",
                    rule_id="TYPO_DISTANCE_ONE",
                    category=FindingCategory.TYPOSQUATTING,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    title="Immediate Typosquatting Proximity (Distance 1)",
                    description=(
                        f"Package name '{coords.name}' has edit distance 1 from popular library '{ref_pkg}'. "
                        "High probability of typosquatting targeting mistyped developer commands."
                    ),
                    evidence={
                        "target_name": coords.name,
                        "reference_package": ref_pkg,
                        "distance": dist,
                        "algorithm": "DAMERAU_LEVENSHTEIN",
                    },
                    detection_method="EDIT_DISTANCE_ANALYSIS",
                ))
            elif dist == 2 and len(norm_ref) >= 5:
                # Distance 2 for longer package names
                findings.append(SecurityFinding(
                    module="TYPOSQUATTING_DETECTOR",
                    rule_id="TYPO_DISTANCE_TWO",
                    category=FindingCategory.TYPOSQUATTING,
                    severity=Severity.MEDIUM,
                    confidence=0.65,
                    title="Typosquatting Candidate (Distance 2)",
                    description=(
                        f"Package name '{coords.name}' is within edit distance 2 of popular library '{ref_pkg}'."
                    ),
                    evidence={
                        "target_name": coords.name,
                        "reference_package": ref_pkg,
                        "distance": dist,
                        "algorithm": "DAMERAU_LEVENSHTEIN",
                    },
                    detection_method="EDIT_DISTANCE_ANALYSIS",
                ))

            # 3. Combo-squatting (prefix/suffix injection, e.g. requests-official, axios-js)
            if compare_name.startswith(f"{norm_ref}-") or compare_name.endswith(f"-{norm_ref}"):
                suffix_part = compare_name.replace(norm_ref, "").strip("-")
                if suffix_part in ("js", "official", "node", "core", "cli", "client", "lib"):
                    findings.append(SecurityFinding(
                        module="TYPOSQUATTING_DETECTOR",
                        rule_id="TYPO_COMBOSQUATTING_AFFIX",
                        category=FindingCategory.TYPOSQUATTING,
                        severity=Severity.MEDIUM,
                        confidence=0.75,
                        title="Combosquatting Affix Pattern",
                        description=(
                            f"Package '{coords.name}' appends deceptive affix '{suffix_part}' to popular library '{ref_pkg}'."
                        ),
                        evidence={
                            "target_name": coords.name,
                            "reference_package": ref_pkg,
                            "affix": suffix_part,
                        },
                        detection_method="COMBO_AFFIX_ANALYSIS",
                    ))

        return findings
