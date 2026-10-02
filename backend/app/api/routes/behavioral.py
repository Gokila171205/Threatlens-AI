"""
ThreatLens AI - Safe Behavioral Telemetry & Analytics API (Milestone 3, Step 4)
Endpoints for normalized behavioral event ingestion, analytical indicator retrieval,
and behavioral summary reports.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid
from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import get_current_user, require_role
from app.schemas.scan import (
    BehavioralAnalysisReport,
    BehavioralEvent,
    BehavioralEventSubmission,
    BehavioralSummaryResponse,
)
from app.services.behavioral_analysis_service import (
    BehavioralAnalysisEngine,
)
from app.services.db import (
    get_behavioral_events_by_scan_id,
    get_scan_by_id,
    save_alert_record,
    save_behavioral_events,
    save_scan_record,
)

router = APIRouter(prefix="/behavioral", tags=["Behavioral Analytics"])


@router.get("/{scan_id}", response_model=BehavioralAnalysisReport)
async def get_behavioral_report(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Retrieves full behavioral telemetry report, detected indicators,
    severity distributions, and risk scoring for a specific scan.
    """
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID {scan_id} not found."
        )

    # Fetch normalized events from DB
    events = get_behavioral_events_by_scan_id(scan_id)
    
    # If no separate events stored but scan has embedded report, return embedded or run engine
    if not events and scan.get("behavioral_analysis"):
        return scan["behavioral_analysis"]

    report = BehavioralAnalysisEngine.analyze_events(scan_id, events)
    return report


@router.get("/{scan_id}/summary", response_model=BehavioralSummaryResponse)
async def get_behavioral_summary(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Retrieves concise behavioral summary metrics for SOC dashboard and quick-view panels.
    """
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID {scan_id} not found."
        )

    events = get_behavioral_events_by_scan_id(scan_id)
    report = BehavioralAnalysisEngine.analyze_events(scan_id, events)

    return {
        "scan_id": scan_id,
        "behavioral_risk_score": report["behavioral_risk_score"],
        "behavioral_risk_level": report["behavioral_risk_level"],
        "total_events": report["total_events"],
        "suspicious_events_count": report["suspicious_events_count"],
        "indicators_count": len(report.get("behavioral_indicators", [])),
        "categories": report.get("behavior_categories", {}),
        "summary": report.get("behavior_summary", "Routine telemetry evaluated.")
    }


@router.post("/events", response_model=BehavioralAnalysisReport, status_code=status.HTTP_201_CREATED)
async def ingest_behavioral_events(
    payload: BehavioralEventSubmission,
    current_user: dict = Depends(require_role(["Security Analyst", "SOC Team Member", "Administrator"])),
):
    """
    Ingests normalized behavioral event records for a scan without executing files on the host.
    Re-evaluates behavioral indicators, updates the scan's Threat Risk Score, and creates alerts if high-risk.
    """
    scan_id = payload.scan_id
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID {scan_id} not found."
        )

    # Ensure all events have timestamps and IDs
    now_iso = datetime.now(timezone.utc).isoformat()
    raw_events = []
    for ev in payload.events:
        ev_dict = ev.model_dump()
        if not ev_dict.get("event_id"):
            ev_dict["event_id"] = str(uuid.uuid4())
        if not ev_dict.get("timestamp"):
            ev_dict["timestamp"] = now_iso
        ev_dict["scan_id"] = scan_id
        raw_events.append(ev_dict)

    # Persist events to DB
    save_behavioral_events(raw_events)

    # Load all events associated with this scan
    all_events = get_behavioral_events_by_scan_id(scan_id)
    b_report = BehavioralAnalysisEngine.analyze_events(scan_id, all_events)

    # Compute correlated Threat Risk Score
    static_score = scan.get("static_analysis", {}).get("threat_score") or scan.get("threat_score", 0)
    static_class = scan.get("classification", "BENIGN")
    combined = BehavioralAnalysisEngine.correlate_with_static_prediction(static_score, static_class, b_report)

    # Update scan record
    scan["behavioral_analysis"] = b_report
    scan["combined_verdict"] = combined
    scan["mitre_techniques"] = b_report.get("mitre_attack_techniques", [])
    scan["threat_score"] = combined["final_threat_score"]
    scan["classification"] = combined["final_classification"]
    score = combined["final_threat_score"]
    scan["threat_level"] = "CRITICAL" if score >= 85 else ("HIGH" if score >= 70 else ("MEDIUM" if score >= 40 else "LOW"))
    save_scan_record(scan)

    # Trigger behavioral alert if high/critical risk or indicators detected
    if b_report["behavioral_risk_level"] in ["HIGH", "CRITICAL"] or b_report["behavioral_indicators"]:
        alert_id = str(uuid.uuid4())
        top_ind = b_report["behavioral_indicators"][0]["name"] if b_report["behavioral_indicators"] else "Elevated Behavioral Risk"
        alert_title = f"Behavioral Alert: {top_ind} ({scan.get('filename', 'Unknown')})"
        alert_record = {
            "id": alert_id,
            "scan_id": scan_id,
            "user_id": scan.get("user_id"),
            "filename": scan.get("filename", "Unknown"),
            "sha256": scan.get("sha256", ""),
            "threat_score": combined["final_threat_score"],
            "threat_level": b_report["behavioral_risk_level"],
            "classification": combined["final_classification"],
            "created_at": now_iso,
            "status": "OPEN",
            "is_read": False,
            "title": alert_title,
            "description": f"Behavioral indicator detected ({top_ind}). Behavioral risk score: {b_report['behavioral_risk_score']}/100. Action: {b_report['recommended_investigations'][0] if b_report.get('recommended_investigations') else 'Review telemetry'}",
            "indicators_count": len(b_report.get("behavioral_indicators", [])),
        }
        save_alert_record(alert_record)

    return b_report
