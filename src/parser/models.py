"""
Data models for parsed CI/CD incident logs.
"""

from pydantic import BaseModel, Field


class ParsedIncident(BaseModel):
    incident_id: str | None = None
    scenario_id: str | None = None
    pipeline_stage: str = Field(..., description="Stage where failure occurred (e.g., test-suite, security-audit)")
    failure_signature: str = Field(..., description="Canonical failure signature pattern")
    error_type: str = Field(..., description="Extracted error class or failure type")
    error_message: str = Field(..., description="Primary error message summary")
    stack_trace: str | None = Field(None, description="Condensed relevant stack trace / logs")
    exit_code: int = Field(1, description="Process exit code")
    keywords: list[str] = Field(default_factory=list, description="Extracted diagnostic keywords")
    raw_log_excerpt: str = Field(..., description="Full or trimmed raw log content")
