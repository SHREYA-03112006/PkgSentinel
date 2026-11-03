"""
Unit tests for Module B: Typosquatting Detector.
Tests Damerau-Levenshtein, homoglyphs, PyPI normalization, and npm scopes.
"""

import pytest
from engine.ingestion.models import PackageCoordinates, Ecosystem
from engine.detection.typosquatting import (
    TyposquattingDetector,
    damerau_levenshtein_distance,
    pypi_normalize,
    check_homoglyphs,
)
from engine.schemas.finding import Severity


def test_damerau_levenshtein_distance():
    # Identical
    assert damerau_levenshtein_distance("express", "express") == 0
    # Single substitution
    assert damerau_levenshtein_distance("chalk", "choalk") == 1
    # Transposition of adjacent characters
    assert damerau_levenshtein_distance("lodash", "loadsh") == 1
    # Insertion
    assert damerau_levenshtein_distance("react", "reactt") == 1
    # Deletion
    assert damerau_levenshtein_distance("requests", "reqests") == 1
    # Distance 2
    assert damerau_levenshtein_distance("express", "expresxy") == 2
    # Beyond length bound
    assert damerau_levenshtein_distance("express", "completely_different") > 2


def test_pypi_normalization():
    assert pypi_normalize("Scikit_Learn") == "scikit-learn"
    assert pypi_normalize("pytest...asyncio") == "pytest-asyncio"
    assert pypi_normalize("PyYAML") == "pyyaml"


def test_homoglyph_detection():
    # Cyrillic 'а' (U+0430) vs Latin 'a'
    cyrillic_react = "re\u0430ct"
    match = check_homoglyphs(cyrillic_react, "react")
    assert match == "react"


def test_typosquatting_detector_distance_one():
    detector = TyposquattingDetector()
    coords = PackageCoordinates(ecosystem=Ecosystem.NPM, name="choalk", version="1.0.0")

    findings = detector.analyze(coords)
    typo_findings = [f for f in findings if f.rule_id == "TYPO_DISTANCE_ONE"]
    assert len(typo_findings) == 1
    assert typo_findings[0].severity == Severity.HIGH
    assert typo_findings[0].evidence["reference_package"] == "chalk"


def test_typosquatting_detector_homoglyph():
    detector = TyposquattingDetector()
    # Cyrillic 'е' (U+0435) in requests
    coords = PackageCoordinates(ecosystem=Ecosystem.PYPI, name="r\u0435quests", version="1.0.0")

    findings = detector.analyze(coords)
    homo_findings = [f for f in findings if f.rule_id == "TYPO_HOMOGLYPH_ATTACK"]
    assert len(homo_findings) == 1
    assert homo_findings[0].severity == Severity.HIGH
    assert homo_findings[0].evidence["reference_package"] == "requests"


def test_typosquatting_detector_combosquatting():
    detector = TyposquattingDetector()
    coords = PackageCoordinates(ecosystem=Ecosystem.NPM, name="axios-js", version="1.0.0")

    findings = detector.analyze(coords)
    combo_findings = [f for f in findings if f.rule_id == "TYPO_COMBOSQUATTING_AFFIX"]
    assert len(combo_findings) == 1
    assert combo_findings[0].severity == Severity.MEDIUM
    assert combo_findings[0].evidence["reference_package"] == "axios"


def test_typosquatting_scoped_npm_package():
    detector = TyposquattingDetector()
    # Scoped package with typosquatted internal name
    coords = PackageCoordinates(ecosystem=Ecosystem.NPM, name="@evil/loadsh", version="1.0.0")

    findings = detector.analyze(coords)
    typo_findings = [f for f in findings if f.rule_id == "TYPO_DISTANCE_ONE"]
    assert len(typo_findings) == 1
    assert typo_findings[0].evidence["reference_package"] == "lodash"


def test_legitimate_exact_match_has_no_findings():
    detector = TyposquattingDetector()
    # Exact name matches popular package itself -> no typosquatting finding
    coords = PackageCoordinates(ecosystem=Ecosystem.PYPI, name="requests", version="2.31.0")
    findings = detector.analyze(coords)
    assert findings == []
