from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class Ecosystem(str, Enum):
    NPM = "NPM"
    PYPI = "PYPI"


class ScanDepth(str, Enum):
    FAST = "FAST"
    DEEP = "DEEP"


class ScanJobMessage(BaseModel):
    job_id: str = Field(..., alias="jobId")
    ecosystem: Ecosystem
    name: str
    version: str
    scan_depth: ScanDepth = Field(ScanDepth.FAST, alias="scanDepth")
    enqueued_at: Optional[str] = Field(None, alias="enqueuedAt")

    model_config = ConfigDict(populate_by_name=True)
