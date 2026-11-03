"""
PkgSentinel Core Detection Engine Package
"""

from engine.detection.metadata_analyzer import MetadataAnalyzer
from engine.detection.typosquatting import TyposquattingDetector
from engine.detection.static.python_ast import PythonASTAnalyzer
from engine.detection.static.javascript_ast import JavaScriptASTAnalyzer
from engine.detection.static.entropy import EntropyAnalyzer, calculate_shannon_entropy
from engine.detection.scoring_engine import RiskScoringEngine, deduplicate_findings
from engine.detection.pipeline import DetectionPipeline

__all__ = [
    "MetadataAnalyzer",
    "TyposquattingDetector",
    "PythonASTAnalyzer",
    "JavaScriptASTAnalyzer",
    "EntropyAnalyzer",
    "calculate_shannon_entropy",
    "RiskScoringEngine",
    "deduplicate_findings",
    "DetectionPipeline",
]

