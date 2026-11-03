import uuid
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, model_validator


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingCategory(str, Enum):
    METADATA = "METADATA"
    IDENTITY = "IDENTITY"
    TYPOSQUATTING = "TYPOSQUATTING"
    STATIC_CODE = "STATIC_CODE"
    OBFUSCATION = "OBFUSCATION"
    INSTALL_SCRIPT = "INSTALL_SCRIPT"
    VERSION_DIFF = "VERSION_DIFF"
    DEPENDENCY_CONFUSION = "DEPENDENCY_CONFUSION"
    DYNAMIC_EXECUTION = "DYNAMIC_EXECUTION"


class SecurityFinding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    module: str = Field(..., description="Module identifier (e.g. METADATA_ANALYZER, STATIC_ANALYZER)")
    rule_id: str = Field("RULE_GENERIC", description="Unique rule code")
    category: FindingCategory
    severity: Severity
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    title: str
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    affected_file: Optional[str] = None
    affected_line: Optional[int] = None
    detection_method: str = "HEURISTIC"
    references: Optional[List[str]] = Field(default_factory=list)

    # Backwards compatibility / convenience fields
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    telemetry: Optional[Dict[str, Any]] = None

    @model_validator(mode="after")
    def sync_compatibility_fields(self):
        # Sync affected_file and file_path
        if self.affected_file and not self.file_path:
            self.file_path = self.affected_file
        elif self.file_path and not self.affected_file:
            self.affected_file = self.file_path

        # Sync affected_line and line_number
        if self.affected_line is not None and self.line_number is None:
            self.line_number = self.affected_line
        elif self.line_number is not None and self.affected_line is None:
            self.affected_line = self.line_number

        return self
