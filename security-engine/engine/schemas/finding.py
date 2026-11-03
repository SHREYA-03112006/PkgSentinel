from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingCategory(str, Enum):
    IDENTITY = "IDENTITY"
    STATIC_CODE = "STATIC_CODE"
    INSTALL_SCRIPT = "INSTALL_SCRIPT"
    VERSION_DIFF = "VERSION_DIFF"
    DEPENDENCY_CONFUSION = "DEPENDENCY_CONFUSION"
    DYNAMIC_EXECUTION = "DYNAMIC_EXECUTION"


class SecurityFinding(BaseModel):
    module: str = Field(..., description="Module identifier (e.g. STATIC_ANALYZER)")
    rule_id: str = Field(..., description="Unique rule code")
    category: FindingCategory
    severity: Severity
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    telemetry: Optional[Dict[str, Any]] = None

