from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from engine.schemas.finding import SecurityFinding


class Verdict(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class AnalysisVerdictReport(BaseModel):
    job_id: str
    status: str = "SUCCESS"
    verdict: Verdict
    risk_score: float = Field(..., ge=0.0, le=100.0)
    raw_score: float = 0.0
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    summary_notes: str
    execution_duration_ms: int = 0
    verdict_reasons: List[str] = Field(default_factory=list)
    analysis_coverage: Dict[str, str] = Field(default_factory=dict)
    findings: List[SecurityFinding] = Field(default_factory=list)
    telemetry: Optional[Dict[str, Any]] = None
