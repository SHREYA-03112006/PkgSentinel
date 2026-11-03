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
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    summary_notes: str
    execution_duration_ms: int
    findings: List[SecurityFinding] = Field(default_factory=list)
    telemetry: Optional[Dict[str, Any]] = None
