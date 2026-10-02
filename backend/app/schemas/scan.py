"""
ThreatLens AI - Scan, Alert, and Monitoring Schemas
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TopFeatureContribution(BaseModel):
    feature: str
    value: float
    importance: float
    impact: float


class ModelInfo(BaseModel):
    model_name: str
    algorithm: str
    version: str


class StaticAnalysisReport(BaseModel):
    filename: str
    file_size_kb: float
    is_pe: bool
    subsystem: str
    machine: str
    overall_entropy: float
    sections: List[Dict[str, Any]] = []
    suspicious_apis: Dict[str, List[str]] = {}
    suspicious_strings: List[Dict[str, str]] = []
    indicators: List[Dict[str, Any]] = []
    raw_features: Dict[str, Any] = {}
    feature_names: List[str] = []


class MLPrediction(BaseModel):
    threat_score: int
    classification: str
    threat_level: str
    confidence: float
    probabilities: Dict[str, float]
    top_contributing_features: List[Dict[str, Any]] = []
    model_info: Dict[str, Any]


class BehavioralEvent(BaseModel):
    event_id: str
    scan_id: str
    file_id: Optional[str] = None
    timestamp: str
    event_type: str
    process_name: Optional[str] = None
    parent_process: Optional[str] = None
    target: Optional[str] = None
    source: Optional[str] = None
    destination: Optional[str] = None
    port: Optional[int] = None
    command: Optional[str] = None
    severity: str = "low"  # low, medium, high, critical
    indicator: Optional[str] = None
    description: str
    metadata: Dict[str, Any] = {}


class BehavioralEventSubmission(BaseModel):
    scan_id: str
    file_id: Optional[str] = None
    events: List[BehavioralEvent] = []


class BehavioralAnalysisReport(BaseModel):
    behavioral_score: int
    behavioral_risk_score: Optional[int] = None
    behavioral_risk_level: Optional[str] = None  # LOW, MEDIUM, HIGH, CRITICAL
    behavioral_classification: str
    total_events: int = 0
    suspicious_events_count: int = 0
    severity_distribution: Dict[str, int] = {}
    behavior_categories: Dict[str, int] = {}
    behavioral_indicators: List[Dict[str, Any]] = []
    mitre_attack_techniques: List[Dict[str, Any]] = []
    telemetry_summary: Dict[str, int] = {}
    behavior_summary: Optional[str] = None
    recommended_investigations: List[str] = []
    raw_telemetry: Optional[Dict[str, Any]] = None
    events: List[BehavioralEvent] = []


class BehavioralSummaryResponse(BaseModel):
    scan_id: str
    behavioral_risk_score: int
    behavioral_risk_level: str
    total_events: int
    suspicious_events_count: int
    indicators_count: int
    categories: Dict[str, int] = {}
    summary: str


class CombinedVerdict(BaseModel):
    final_threat_score: int
    threat_risk_score: Optional[int] = None
    final_classification: str
    fusion_mode: str
    static_score: int
    behavioral_score: Optional[int] = None
    static_weight: float
    behavioral_weight: float
    mitre_count: Optional[int] = None


class ScanResponse(BaseModel):
    id: str
    file_id: Optional[str] = None
    user_id: Optional[str] = None
    filename: str
    file_size_bytes: int
    sha256: str
    md5: Optional[str] = None
    scanned_at: str
    status: str = "COMPLETED"
    threat_score: int
    classification: str
    threat_level: str
    confidence: float
    static_analysis: Dict[str, Any]
    ml_prediction: Dict[str, Any]
    behavioral_analysis: Optional[Dict[str, Any]] = None
    combined_verdict: Optional[Dict[str, Any]] = None
    mitre_techniques: List[Dict[str, Any]] = []
    indicators: List[Dict[str, Any]] = []
    model_name: Optional[str] = None
    model_version: Optional[str] = None


class ScanSummary(BaseModel):
    id: str
    filename: str
    sha256: str
    file_size_bytes: int
    scanned_at: str
    threat_score: int
    classification: str
    threat_level: str
    is_pe: bool
    status: str
    model_name: Optional[str] = None


class AlertResponse(BaseModel):
    id: str
    scan_id: str
    filename: str
    sha256: str
    threat_score: int
    threat_level: str
    classification: str
    created_at: str
    status: str = "OPEN"  # OPEN, INVESTIGATING, RESOLVED, DISMISSED
    is_read: bool = False
    title: str
    description: str
    indicators_count: int


class AlertUpdate(BaseModel):
    status: Optional[str] = None
    is_read: Optional[bool] = None


class BehavioralSubmission(BaseModel):
    events: List[Dict[str, Any]] = []
    network_traffic: List[Dict[str, Any]] = []
    file_modifications: List[Dict[str, Any]] = []
    registry_modifications: List[Dict[str, Any]] = []
    spawned_processes: List[Dict[str, Any]] = []


class MonitoringOverview(BaseModel):
    total_scans: int
    malicious_count: int
    suspicious_count: int
    benign_count: int
    open_alerts: int
    avg_threat_score: float
    threat_level_distribution: Dict[str, int]
    recent_scans: List[ScanSummary]
    recent_alerts: List[AlertResponse]


class AnalyticsResponse(BaseModel):
    daily_timeline: List[Dict[str, Any]]
    threat_types: Dict[str, int]
    mitre_attack_distribution: List[Dict[str, Any]]
    entropy_distribution: Dict[str, int]


# Threat Prediction & Risk Analytics Schemas (Milestone 3, Step 5)
class RiskFactorItem(BaseModel):
    factor_id: str
    category: str
    severity: str  # low, medium, high, critical
    title: str
    description: str
    evidence_source: str  # static_pe, behavioral_telemetry, alert_history, re_scan_frequency


class FileRiskHistoryResponse(BaseModel):
    sha256: str
    filename: str
    total_scans: int
    first_seen: str
    last_seen: str
    risk_trajectory: str  # increased, decreased, stable
    classification_history: List[str] = []
    threat_score_history: List[int] = []
    behavioral_score_history: List[Optional[int]] = []
    alert_count: int = 0
    scans_summary: List[Dict[str, Any]] = []


class ThreatTrendResponse(BaseModel):
    time_window: str  # 24h, 7d, 30d
    total_scans: int
    benign_scans: int
    suspicious_scans: int
    malicious_scans: int
    avg_threat_score: float
    highest_threat_score: int
    avg_behavioral_risk_score: float
    high_risk_scan_count: int
    critical_alert_count: int
    timeline: List[Dict[str, Any]] = []
    status: str = "Active"
    message: Optional[str] = None


class ThreatPredictionReport(BaseModel):
    scan_id: str
    filename: str
    sha256: str
    threat_risk_score: int
    threat_risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    threat_classification: str  # BENIGN, SUSPICIOUS, MALICIOUS
    confidence_label: str  # High Confidence, Moderate Confidence, Preliminary Assessment
    static_ml_score: int
    behavioral_risk_score: Optional[int] = None
    primary_risk_factors: List[RiskFactorItem] = []
    behavioral_indicators: List[Dict[str, Any]] = []
    supporting_evidence: Dict[str, Any] = {}
    historical_context: Dict[str, Any] = {}
    trend: Dict[str, Any] = {}
    recommended_actions: List[str] = []

