"""
Detection Pipeline Coordinator
Connects IngestionResult to Metadata, Typosquatting, Static AST, Entropy, and Scoring.
Enforces fault isolation so individual module errors do not crash the pipeline.
"""

import os
import json
import time
from typing import List, Dict, Any, Optional

from engine.ingestion.models import IngestionResult, Ecosystem
from engine.schemas.finding import SecurityFinding
from engine.schemas.verdict import AnalysisVerdictReport
from engine.detection.metadata_analyzer import MetadataAnalyzer
from engine.detection.typosquatting import TyposquattingDetector
from engine.detection.static.python_ast import PythonASTAnalyzer
from engine.detection.static.javascript_ast import JavaScriptASTAnalyzer
from engine.detection.static.entropy import EntropyAnalyzer
from engine.detection.scoring_engine import RiskScoringEngine


class DetectionPipeline:
    """
    Executes all static security inspection modules on an ingested package workspace.
    """

    def __init__(
        self,
        metadata_analyzer: Optional[MetadataAnalyzer] = None,
        typosquat_detector: Optional[TyposquattingDetector] = None,
        python_analyzer: Optional[PythonASTAnalyzer] = None,
        js_analyzer: Optional[JavaScriptASTAnalyzer] = None,
        entropy_analyzer: Optional[EntropyAnalyzer] = None,
        scoring_engine: Optional[RiskScoringEngine] = None,
    ):
        self.metadata_analyzer = metadata_analyzer or MetadataAnalyzer()
        self.typosquat_detector = typosquat_detector or TyposquattingDetector()
        self.python_analyzer = python_analyzer or PythonASTAnalyzer()
        self.js_analyzer = js_analyzer or JavaScriptASTAnalyzer()
        self.entropy_analyzer = entropy_analyzer or EntropyAnalyzer()
        self.scoring_engine = scoring_engine or RiskScoringEngine()

    def analyze(
        self,
        ingest_result: IngestionResult,
        job_id: str = "local-job",
        registry_metadata: Optional[Dict[str, Any]] = None,
    ) -> AnalysisVerdictReport:
        start_time = time.time()
        findings: List[SecurityFinding] = []
        coverage: Dict[str, str] = {}

        workspace = ingest_result.extracted_workspace
        coords = ingest_result.coordinates

        # -------------------------------------------------------------
        # 1. Module A: Metadata & Publisher Analysis
        # -------------------------------------------------------------
        try:
            manifest_data = self._load_manifest(workspace, coords.ecosystem)
            meta_findings = self.metadata_analyzer.analyze(
                coords,
                registry_metadata=registry_metadata,
                manifest_data=manifest_data,
            )
            findings.extend(meta_findings)
            coverage["METADATA_ANALYSIS"] = "COMPLETED"
        except Exception as e:
            coverage["METADATA_ANALYSIS"] = f"FAILED: {e}"

        # -------------------------------------------------------------
        # 2. Module B: Typosquatting Detection
        # -------------------------------------------------------------
        try:
            typo_findings = self.typosquat_detector.analyze(coords)
            findings.extend(typo_findings)
            coverage["TYPOSQUATTING_DETECTION"] = "COMPLETED"
        except Exception as e:
            coverage["TYPOSQUATTING_DETECTION"] = f"FAILED: {e}"

        # -------------------------------------------------------------
        # 3. Module C: Static AST Analysis (JS & Python)
        # -------------------------------------------------------------
        try:
            static_findings = self._run_static_ast(workspace, coords.ecosystem)
            findings.extend(static_findings)
            coverage["STATIC_AST_ANALYSIS"] = "COMPLETED"
        except Exception as e:
            coverage["STATIC_AST_ANALYSIS"] = f"FAILED: {e}"

        # -------------------------------------------------------------
        # 4. Module C: Shannon Entropy Analysis
        # -------------------------------------------------------------
        try:
            entropy_findings = self._run_entropy(workspace)
            findings.extend(entropy_findings)
            coverage["ENTROPY_ANALYSIS"] = "COMPLETED"
        except Exception as e:
            coverage["ENTROPY_ANALYSIS"] = f"FAILED: {e}"

        # -------------------------------------------------------------
        # 5. Module G: Risk Scoring & Verdict Generation
        # -------------------------------------------------------------
        duration_ms = int((time.time() - start_time) * 1000)
        report = self.scoring_engine.compute_verdict(
            job_id=job_id,
            raw_findings=findings,
            analysis_coverage=coverage,
            execution_duration_ms=duration_ms,
        )

        return report

    def _load_manifest(self, workspace: str, ecosystem: Ecosystem) -> Dict[str, Any]:
        """Attempts to load package.json for npm packages."""
        if ecosystem == Ecosystem.NPM:
            pkg_json_path = os.path.join(workspace, "package", "package.json")
            if not os.path.exists(pkg_json_path):
                pkg_json_path = os.path.join(workspace, "package.json")
            if os.path.exists(pkg_json_path):
                try:
                    with open(pkg_json_path, "r", encoding="utf-8", errors="ignore") as f:
                        return json.load(f)
                except Exception:
                    pass
        return {}

    def _run_static_ast(self, workspace: str, ecosystem: Ecosystem) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        # If npm, also inspect package.json scripts
        if ecosystem == Ecosystem.NPM:
            pkg_json_path = os.path.join(workspace, "package", "package.json")
            if not os.path.exists(pkg_json_path):
                pkg_json_path = os.path.join(workspace, "package.json")
            if os.path.exists(pkg_json_path):
                try:
                    with open(pkg_json_path, "r", encoding="utf-8", errors="ignore") as f:
                        data = json.load(f)
                    findings.extend(self.js_analyzer.analyze_package_json(data))
                except Exception:
                    pass

        # Traverse source files
        for root, _, files in os.walk(workspace):
            for file in files:
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, workspace).replace("\\", "/")
                ext = os.path.splitext(file)[1].lower()

                # Python AST
                if ext == ".py":
                    try:
                        with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                            source = f.read()
                        findings.extend(self.python_analyzer.analyze_source(source, rel_path))
                    except Exception:
                        pass

                # JavaScript AST
                elif ext in (".js", ".mjs", ".cjs"):
                    try:
                        with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                            source = f.read()
                        findings.extend(self.js_analyzer.analyze_source(source, rel_path))
                    except Exception:
                        pass

        return findings

    def _run_entropy(self, workspace: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        for root, _, files in os.walk(workspace):
            for file in files:
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, workspace).replace("\\", "/")
                findings.extend(self.entropy_analyzer.analyze_file(abs_path, rel_path))
        return findings

