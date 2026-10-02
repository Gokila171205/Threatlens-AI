"""
ThreatLens AI - Threat Prediction & Risk Analytics API (Milestone 3, Step 5)
Provides evidence-based threat risk assessments, multi-window trend analysis,
and cross-scan file risk history tracking.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.deps import get_current_user
from app.schemas.scan import (
    FileRiskHistoryResponse,
    ThreatPredictionReport,
    ThreatTrendResponse,
)
from app.services.db import get_scan_by_id
from app.services.threat_prediction_service import ThreatPredictionService

router = APIRouter(prefix="/threat-prediction", tags=["Threat Prediction & Risk Analytics"])


@router.get("/trends", response_model=ThreatTrendResponse)
async def get_threat_trends(
    window: Optional[str] = Query(None, description="Time window for analysis: 24h, 7d, or 30d"),
    time_window: Optional[str] = Query(None, description="Alias for window: 24h, 7d, or 30d"),
    current_user: dict = Depends(get_current_user),
):
    """
    Computes empirical threat metrics and detection trajectories across the specified window.
    Returns 'Insufficient historical data' if no scans exist within the window without faking data.
    """
    selected_window = time_window or window or "7d"
    if selected_window not in ["24h", "7d", "30d"]:
        selected_window = "7d"
    return ThreatPredictionService.analyze_threat_trends(time_window=selected_window)


@router.get("/{scan_id}", response_model=ThreatPredictionReport)
async def get_threat_risk_assessment(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Retrieves full Threat Prediction Assessment report for a specific scan.
    Synthesizes static EMBER ML features, behavioral indicators, alert frequency,
    and historical scan prevalence into explainable risk factors.
    """
    try:
        return ThreatPredictionService.assess_threat_risk(scan_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )


@router.get("/{scan_id}/history", response_model=FileRiskHistoryResponse)
async def get_scan_file_history(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Retrieves chronological scan history for the binary matching the scan's SHA-256 hash.
    Observes changes in risk scores, classifications, and alert generation over time.
    """
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID {scan_id} not found."
        )

    sha256 = scan.get("sha256", "")
    return ThreatPredictionService.get_file_risk_history(sha256)
