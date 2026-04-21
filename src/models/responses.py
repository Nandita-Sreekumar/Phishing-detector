from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from src.models.enums import RiskLevel, ScanType


class HeaderAnalysis(BaseModel):
    """Email header analysis results."""
    spf_result: str | None = None
    dkim_result: str | None = None
    dmarc_result: str | None = None
    return_path_match: bool = True
    reply_to_mismatch: bool = False
    received_chain_anomaly: bool = False
    x_originating_ip: str | None = None
    auth_score: float = Field(ge=0.0, le=1.0)


class ContentAnalysis(BaseModel):
    """NLP-based content analysis results."""
    urgency_score: float = Field(ge=0.0, le=1.0)
    authority_impersonation: float = Field(ge=0.0, le=1.0)
    action_pressure: float = Field(ge=0.0, le=1.0)
    reward_bait: float = Field(ge=0.0, le=1.0)
    threat_language: float = Field(ge=0.0, le=1.0)
    grammar_consistency: float = Field(ge=0.0, le=1.0)
    personal_info_request: float = Field(ge=0.0, le=1.0)
    ai_generated_probability: float = Field(ge=0.0, le=1.0)
    social_engineering_tactics: list[str] = Field(default_factory=list)
    reasoning: str = ""


class LinkAnalysis(BaseModel):
    """Link extraction and analysis results."""
    urls_found: list[str] = Field(default_factory=list)
    suspicious_urls: list[dict[str, Any]] = Field(default_factory=list)
    url_to_text_mismatch: bool = False
    shortened_urls: list[str] = Field(default_factory=list)
    data_uri_present: bool = False


class ThreatSignal(BaseModel):
    """Individual threat signal."""
    name: str
    score: float = Field(ge=0.0, le=100.0)
    weight: float = Field(ge=0.0, le=1.0)
    description: str


class ThreatAssessment(BaseModel):
    """Complete threat assessment result."""
    scan_id: str
    scan_type: ScanType
    timestamp: datetime
    overall_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    signals: list[ThreatSignal]
    iocs: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    raw_analysis: dict[str, Any] = Field(default_factory=dict)


class DashboardStats(BaseModel):
    """Dashboard statistics."""
    total_scans: int
    scans_by_type: dict[str, int]
    scans_by_risk: dict[str, int]
    recent_threats: int
    avg_threat_score: float