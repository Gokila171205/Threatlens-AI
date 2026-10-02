"""
ThreatLens AI - Malware Scanning & Analysis Endpoints
Handles safe static malware scanning, ML classification, scan history, and behavioral telemetry ingestion.
"""

import hashlib
import os
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status

from app.api.deps import get_optional_current_user
from app.schemas.scan import (
    BehavioralSubmission,
    ScanResponse,
    ScanSummary,
)
from app.services.behavioral_service import (
    analyze_behavioral_telemetry,
    compute_combined_threat_score,
)
from app.services.behavioral_analysis_service import convert_legacy_telemetry_to_events
from app.services.classifier_service import classifier_service
from app.services.db import (
    get_db,
    get_scan_by_id,
    get_scan_records,
    save_alert_record,
    save_behavioral_events,
    save_scan_record,
)
from app.services.static_analysis import extract_static_features


router = APIRouter(prefix="/scans", tags=["Scans & Malware Analysis"])


def calculate_hashes(data: bytes):
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    return sha256, md5


@router.post("/file", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def scan_file_upload(
    file: UploadFile = File(...),
    current_user: Optional[dict] = Depends(get_optional_current_user),
):
    """
    Uploads a binary/file and executes complete safe static malware analysis
    and ML Random Forest classification. Generates alerts for suspicious/malicious files.
    NEVER executes the binary.
    """
    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot scan an empty file.",
        )

    filename = file.filename or "unknown_file"
    file_size_bytes = len(file_bytes)
    sha256, md5 = calculate_hashes(file_bytes)

    # 1. Safe Static Feature Extraction
    static_result = extract_static_features(file_bytes, filename=filename)
    raw_features = static_result["raw_features"]
    report = static_result["report"]

    # 2. Machine Learning Inference
    prediction = classifier_service.predict(raw_features)

    threat_score = prediction["threat_score"]
    classification = prediction["classification"]
    threat_level = prediction["threat_level"]
    confidence = prediction["confidence"]

    # 3. Combined Initial Verdict (static-only until behavioral telemetry added)
    combined = compute_combined_threat_score(threat_score, classification, None)

    scan_id = str(uuid.uuid4())
    user_id = current_user.get("id") if current_user else None

    scan_record = {
        "id": scan_id,
        "file_id": None,
        "user_id": user_id,
        "filename": filename,
        "file_size_bytes": file_size_bytes,
        "sha256": sha256,
        "md5": md5,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "status": "COMPLETED",
        "threat_score": threat_score,
        "classification": classification,
        "threat_level": threat_level,
        "confidence": confidence,
        "static_analysis": report,
        "ml_prediction": prediction,
        "behavioral_analysis": None,
        "combined_verdict": combined,
        "mitre_techniques": [],
        "indicators": report.get("indicators", []),
        "model_name": prediction.get("model_info", {}).get("model_name", "EMBER Grouped Random Forest"),
        "model_version": prediction.get("model_info", {}).get("version", "ember-grouped-v1"),
    }

    # Save scan record
    save_scan_record(scan_record)

    # 4. Generate Alert if Suspicious or Malicious
    if threat_score >= 40:
        alert_id = str(uuid.uuid4())
        alert_title = f"{threat_level.upper()} Risk Threat Detected: {filename}"
        desc_parts = [
            f"ML model classified sample as {classification} with {confidence*100:.1f}% confidence.",
            f"Entropy: {report.get('overall_entropy', 0):.2f}/8.0."
        ]
        if report.get("indicators"):
            desc_parts.append(f"Primary indicator: {report['indicators'][0]['description']}")

        alert_record = {
            "id": alert_id,
            "scan_id": scan_id,
            "user_id": user_id,
            "filename": filename,
            "sha256": sha256,
            "threat_score": threat_score,
            "threat_level": threat_level,
            "classification": classification,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "OPEN",
            "is_read": False,
            "title": alert_title,
            "description": " ".join(desc_parts),
            "indicators_count": len(report.get("indicators", [])),
        }
        save_alert_record(alert_record)

    return scan_record


@router.get("", response_model=List[ScanSummary])
async def list_scans(
    limit: int = Query(50, ge=1, le=100),
    classification: Optional[str] = None,
    current_user: Optional[dict] = Depends(get_optional_current_user),
):
    """
    Returns scan history with threat scores and verdicts.
    """
    user_id = current_user.get("id") if current_user else None
    scans = get_scan_records(user_id=user_id, limit=limit)

    summaries = []
    for s in scans:
        if classification and s.get("classification", "").upper() != classification.upper():
            continue
        summaries.append({
            "id": s["id"],
            "filename": s.get("filename", "unknown"),
            "sha256": s.get("sha256", ""),
            "file_size_bytes": s.get("file_size_bytes", 0),
            "scanned_at": s.get("scanned_at", ""),
            "threat_score": s.get("threat_score", 0),
            "classification": s.get("classification", "BENIGN"),
            "threat_level": s.get("threat_level", "LOW"),
            "is_pe": s.get("static_analysis", {}).get("is_pe", False),
            "status": s.get("status", "COMPLETED"),
            "model_name": s.get("model_name"),
        })
    return summaries


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_details(
    scan_id: str,
    current_user: Optional[dict] = Depends(get_optional_current_user),
):
    """
    Retrieves full scan analysis report including static metrics,
    ML predictions, entropy breakdown, indicators, and behavioral analysis.
    """
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan report with ID {scan_id} was not found.",
        )
    return scan


@router.post("/{scan_id}/behavioral", response_model=ScanResponse)
async def ingest_behavioral_telemetry(
    scan_id: str,
    payload: BehavioralSubmission,
    current_user: Optional[dict] = Depends(get_optional_current_user),
):
    """
    Milestone 3: Ingests dynamic sandbox telemetry without executing binaries on host.
    Maps MITRE ATT&CK techniques and calculates combined multi-layer threat score.
    """
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID {scan_id} was not found.",
        )

    # Analyze telemetry
    telemetry_data = payload.model_dump()
    normalized_events = convert_legacy_telemetry_to_events(scan_id, telemetry_data)
    save_behavioral_events(normalized_events)

    b_report = analyze_behavioral_telemetry(telemetry_data, scan_id=scan_id)

    # Recalculate combined Threat Risk Score
    static_score = scan.get("static_analysis", {}).get("threat_score") or scan.get("threat_score", 0)
    static_class = scan.get("classification", "BENIGN")
    combined = compute_combined_threat_score(static_score, static_class, b_report)

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
    if b_report.get("behavioral_risk_level") in ["HIGH", "CRITICAL"] or b_report.get("behavioral_indicators"):
        alert_id = str(uuid.uuid4())
        top_ind = b_report["behavioral_indicators"][0]["name"] if b_report.get("behavioral_indicators") else "Elevated Behavioral Risk"
        alert_title = f"Behavioral Alert: {top_ind} ({scan.get('filename', 'Unknown')})"
        alert_record = {
            "id": alert_id,
            "scan_id": scan_id,
            "user_id": scan.get("user_id"),
            "filename": scan.get("filename", "Unknown"),
            "sha256": scan.get("sha256", ""),
            "threat_score": combined["final_threat_score"],
            "threat_level": b_report.get("behavioral_risk_level", "HIGH"),
            "classification": combined["final_classification"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "OPEN",
            "is_read": False,
            "title": alert_title,
            "description": f"Behavioral indicator detected ({top_ind}). Behavioral risk score: {b_report.get('behavioral_risk_score', 0)}/100. Action: {b_report.get('recommended_investigations', ['Review telemetry'])[0]}",
            "indicators_count": len(b_report.get("behavioral_indicators", [])),
        }
        save_alert_record(alert_record)

    return scan
