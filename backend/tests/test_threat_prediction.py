"""
ThreatLens AI - Threat Prediction & Risk Analytics Test Suite (Milestone 3, Step 5)
Tests:
- Threat Risk Score calculation (static-only baseline vs 50/50 static/behavioral fusion)
- Risk level categorization (LOW, MEDIUM, HIGH, CRITICAL)
- Classification thresholds (BENIGN, SUSPICIOUS, MALICIOUS)
- Traceable Primary Risk Factors identification
- File risk history tracking across multiple scans of the same SHA-256 hash
- Multi-window Threat Trend Analysis (24h, 7d, 30d) and "Insufficient historical data" handling
- REST API endpoint contracts (/api/threat-prediction/{scan_id}, /history, /trends)
"""

import io
import uuid
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.threat_prediction_service import (
    calculate_threat_risk_score,
    map_risk_level,
    map_threat_classification,
    assess_threat_risk,
    analyze_threat_trends,
    get_file_risk_history,
)
from app.services.db import get_db

from app.core.security import create_access_token

_analyst_jwt = create_access_token({
    "sub": "analyst@threatlens.ai",
    "id": "test-analyst-id",
    "email": "analyst@threatlens.ai",
    "role": "Security Analyst",
    "name": "Security Analyst",
})
client = TestClient(app, headers={"Authorization": f"Bearer {_analyst_jwt}"})


def test_threat_risk_score_static_only():
    """Verify that Threat Risk Score equals static ML score when no behavioral data exists."""
    assert calculate_threat_risk_score(static_score=80, behavioral_score=None) == 80
    assert calculate_threat_risk_score(static_score=15, behavioral_score=None) == 15
    assert calculate_threat_risk_score(static_score=50, behavioral_score=None) == 50


def test_threat_risk_score_with_behavioral_telemetry():
    """Verify 50% static ML + 50% behavioral risk score fusion."""
    # 80 static + 40 behavioral -> round(40 + 20) = 60
    assert calculate_threat_risk_score(static_score=80, behavioral_score=40) == 60
    # 20 static + 90 behavioral -> round(10 + 45) = 55
    assert calculate_threat_risk_score(static_score=20, behavioral_score=90) == 55
    # Bounds clamping (0 to 100)
    assert calculate_threat_risk_score(static_score=100, behavioral_score=100) == 100
    assert calculate_threat_risk_score(static_score=0, behavioral_score=0) == 0


def test_risk_level_mapping():
    """Verify risk levels: LOW (0-39), MEDIUM (40-69), HIGH (70-84), CRITICAL (85-100)."""
    assert map_risk_level(0) == "LOW"
    assert map_risk_level(39) == "LOW"
    assert map_risk_level(40) == "MEDIUM"
    assert map_risk_level(69) == "MEDIUM"
    assert map_risk_level(70) == "HIGH"
    assert map_risk_level(84) == "HIGH"
    assert map_risk_level(85) == "CRITICAL"
    assert map_risk_level(100) == "CRITICAL"


def test_threat_classification_mapping():
    """Verify threat classifications: BENIGN (<40), SUSPICIOUS (40-69), MALICIOUS (>=70)."""
    assert map_threat_classification(0) == "BENIGN"
    assert map_threat_classification(39) == "BENIGN"
    assert map_threat_classification(40) == "SUSPICIOUS"
    assert map_threat_classification(69) == "SUSPICIOUS"
    assert map_threat_classification(70) == "MALICIOUS"
    assert map_threat_classification(100) == "MALICIOUS"


def test_assess_threat_risk_static_scan():
    """Verify assess_threat_risk produces explainable risk factors on a real scan."""
    dummy_file = io.BytesIO(b"MZ" + b"\x90" * 500 + b"CreateRemoteThread VirtualAlloc malware_test")
    dummy_file.name = "threat_pred_test.exe"
    res = client.post(
        "/api/scans/file",
        files={"file": ("threat_pred_test.exe", dummy_file, "application/octet-stream")},
    )
    assert res.status_code == 201
    scan = res.json()
    scan_id = scan["id"]

    report = assess_threat_risk(scan_id)
    assert report is not None
    assert report["scan_id"] == scan_id
    assert report["threat_risk_score"] == scan["threat_score"]  # Static-only baseline
    assert report["threat_risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert report["threat_classification"] in ["BENIGN", "SUSPICIOUS", "MALICIOUS"]
    assert isinstance(report["primary_risk_factors"], list)
    assert len(report["primary_risk_factors"]) >= 1

    # Check risk factor fields
    factor = report["primary_risk_factors"][0]
    assert factor["factor_id"] != ""
    assert factor["category"] != ""
    assert factor["severity"] in ["low", "medium", "high", "critical"]
    assert factor["title"] != ""
    assert factor["description"] != ""
    assert factor["evidence_source"] in ["static_pe", "behavioral_telemetry", "alert_history", "re_scan_frequency"]


def test_assess_threat_risk_with_behavioral_events():
    """Verify assess_threat_risk incorporates behavioral telemetry when ingested."""
    dummy_file = io.BytesIO(b"MZ" + b"\x90" * 300 + b"sample_behavioral_fusion")
    dummy_file.name = "fusion_test.exe"
    res = client.post(
        "/api/scans/file",
        files={"file": ("fusion_test.exe", dummy_file, "application/octet-stream")},
    )
    scan = res.json()
    scan_id = scan["id"]

    # Ingest critical behavioral event
    ingest_res = client.post(
        "/api/behavioral/events",
        json={
            "scan_id": scan_id,
            "events": [{
                "event_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "timestamp": "2026-09-21T14:30:00Z",
                "event_type": "process_creation",
                "process_name": "powershell.exe",
                "parent_process": "fusion_test.exe",
                "command": "powershell -enc JABzAD0ATgBlAHcA...",
                "severity": "critical",
                "description": "Encoded PowerShell execution indicating fileless code injection",
                "indicator": "T1059.001",
            }]
        },
    )
    assert ingest_res.status_code == 201

    report = assess_threat_risk(scan_id)
    assert report is not None
    assert report["behavioral_risk_score"] is not None
    # Threat Risk Score should be combined (50% static + 50% behavioral)
    expected_score = round(0.5 * report["static_ml_score"] + 0.5 * report["behavioral_risk_score"])
    assert report["threat_risk_score"] == expected_score

    # Check that behavioral risk factors appear
    behavioral_factors = [f for f in report["primary_risk_factors"] if f["evidence_source"] == "behavioral_telemetry"]
    assert len(behavioral_factors) >= 1


def test_file_risk_history_tracking():
    """Verify repeat scans of the same SHA-256 hash track trajectory and scan counts."""
    content = b"MZ" + b"\x90" * 600 + b"repeat_hash_target_content_v1"
    file_bytes = io.BytesIO(content)
    file_bytes.name = "repeat_sample.exe"

    # Scan 1
    res1 = client.post(
        "/api/scans/file",
        files={"file": ("repeat_sample.exe", file_bytes, "application/octet-stream")},
    )
    assert res1.status_code == 201
    scan1 = res1.json()
    sha256 = scan1["sha256"]

    # Scan 2 with same content
    file_bytes2 = io.BytesIO(content)
    res2 = client.post(
        "/api/scans/file",
        files={"file": ("repeat_sample.exe", file_bytes2, "application/octet-stream")},
    )
    assert res2.status_code == 201

    history = get_file_risk_history(sha256)
    assert history is not None
    assert history["total_scans"] >= 2
    assert history["sha256"] == sha256
    assert history["risk_trajectory"] in ["increased", "decreased", "stable"]
    assert len(history["threat_score_history"]) >= 2


def test_threat_trends_insufficient_data_or_aggregates():
    """Verify threat trends across 24h, 7d, 30d windows handle data truthfully without fake numbers."""
    for window in ["24h", "7d", "30d"]:
        trend = analyze_threat_trends(window)
        assert trend["time_window"] == window
        assert trend["total_scans"] >= 0
        if trend["total_scans"] == 0:
            assert trend["status"] == "Insufficient historical data"
            assert trend["timeline"] == []
        else:
            assert trend["status"] == "Active"
            assert isinstance(trend["timeline"], list)
            assert trend["avg_threat_score"] >= 0.0


def test_threat_prediction_api_routes():
    """Verify HTTP endpoints /api/threat-prediction/{scan_id}, /history, and /trends."""
    dummy_file = io.BytesIO(b"MZ" + b"\x90" * 450 + b"api_test_binary_scan")
    dummy_file.name = "api_test.exe"
    res = client.post(
        "/api/scans/file",
        files={"file": ("api_test.exe", dummy_file, "application/octet-stream")},
    )
    assert res.status_code == 201
    scan_id = res.json()["id"]

    # 1. GET /api/threat-prediction/{scan_id}
    res_pred = client.get(f"/api/threat-prediction/{scan_id}")
    assert res_pred.status_code == 200
    pred_data = res_pred.json()
    assert pred_data["scan_id"] == scan_id
    assert "threat_risk_score" in pred_data
    assert "primary_risk_factors" in pred_data
    assert "historical_context" in pred_data

    # 2. GET /api/threat-prediction/{scan_id}/history
    res_hist = client.get(f"/api/threat-prediction/{scan_id}/history")
    assert res_hist.status_code == 200
    hist_data = res_hist.json()
    assert "sha256" in hist_data
    assert "risk_trajectory" in hist_data

    # 3. GET /api/threat-prediction/trends
    res_trend_24h = client.get("/api/threat-prediction/trends?time_window=24h")
    assert res_trend_24h.status_code == 200
    assert res_trend_24h.json()["time_window"] == "24h"

    res_trend_7d = client.get("/api/threat-prediction/trends?time_window=7d")
    assert res_trend_7d.status_code == 200
    assert res_trend_7d.json()["time_window"] == "7d"

    # 4. 404 on nonexistent scan
    res_404 = client.get(f"/api/threat-prediction/{str(uuid.uuid4())}")
    assert res_404.status_code == 404
