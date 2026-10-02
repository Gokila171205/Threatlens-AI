from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class ReportCreate(BaseModel):
    title: str
    type: str = "Malware Classification Report"
    period: str = "Current Incident"
    scan_id: Optional[str] = None
    filename: Optional[str] = None
    sha256: Optional[str] = None
    md5: Optional[str] = None
    threat_score: Optional[int] = 0
    threat_level: Optional[str] = "LOW"
    classification: Optional[str] = "BENIGN"
    confidence: Optional[float] = 0.95
    summary: Optional[str] = None
    key_findings: Optional[List[str]] = Field(default_factory=list)
    recommended_actions: Optional[List[str]] = Field(default_factory=list)
    iocs: Optional[List[str]] = Field(default_factory=list)

class ReportResponse(BaseModel):
    id: str
    title: str
    type: str
    period: str
    status: str = "Generated"
    scan_id: Optional[str] = None
    filename: Optional[str] = None
    sha256: Optional[str] = None
    md5: Optional[str] = None
    threat_score: int = 0
    threat_level: str = "LOW"
    classification: str = "BENIGN"
    confidence: float = 0.95
    threat_count: int = 1
    summary: str
    key_findings: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    iocs: List[str] = Field(default_factory=list)
    generated_by: str
    user_id: Optional[str] = None
    created_at: str
    static_analysis: Optional[Dict[str, Any]] = None
    behavioral_analysis: Optional[Dict[str, Any]] = None
