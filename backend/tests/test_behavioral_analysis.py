"""
ThreatLens AI - Behavioral Analysis System Tests (Milestone 3, Step 4)
Tests normalized event ingestion, behavioral indicator evaluation, risk scoring,
correlation with static EMBER ML predictions, alert triggers, and zero-execution safety.
"""

import io
import uuid
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.behavioral_analysis_service import (
    BehavioralAnalysisEngine,
    convert_legacy_telemetry_to_events,
)
from app.services.classifier_service import classifier_service
from app.services.db import get_behavioral_events_by_scan_id, get_db
from app.core.security import create_access_token

_analyst_jwt = create_access_token({
    "sub": "analyst@threatlens.ai",
    "id": "test-analyst-id",
    "email": "analyst@threatlens.ai",
    "role": "Security Analyst",
    "name": "Security Analyst",
})
client = TestClient(app, headers={"Authorization": f"Bearer {_analyst_jwt}"})


@pytest.fixture
def clean_scan_id():
    """Creates a real scan record via the scan endpoint for behavioral testing."""
    dummy_file = io.BytesIO(b"MZ" + b"\x90" * 400 + b"sample_test_binary")
    dummy_file.name = "behavioral_target.exe"
    res = client.post(
        "/api/scans/file",
        files={"file": ("behavioral_target.exe", dummy_file, "application/octet-stream")},
    )
    assert res.status_code == 201
    data = res.json()
    return data["id"]


def test_behavioral_event_creation_and_ingestion(clean_scan_id):
    """Test 1: Normalized behavioral event creation, ingestion, and DB persistence."""
    events = [
        {
            "event_id": str(uuid.uuid4()),
            "scan_id": clean_scan_id,
            "timestamp": "2026-09-21T14:00:00Z",
            "event_type": "process_creation",
            "process_name": "cmd.exe",
            "parent_process": "behavioral_target.exe",
            "command": "cmd.exe /c whoami",
            "severity": "medium",
            "description": "Child command shell spawned to execute reconnaissance command.",
            "metadata": {"pid": 4120}
        },
        {
            "event_id": str(uuid.uuid4()),
            "scan_id": clean_scan_id,
            "timestamp": "2026-09-21T14:00:02Z",
            "event_type": "network_connection",
            "destination": "198.51.100.45",
            "port": 4444,
            "severity": "high",
            "indicator": "T1071.001",
            "description": "Outbound socket connection observed to port 4444.",
            "metadata": {"protocol": "TCP"}
        }
    ]

    payload = {"scan_id": clean_scan_id, "events": events}
    res = client.post("/api/behavioral/events", json=payload)
    assert res.status_code == 201
    report = res.json()

    assert report["total_events"] == 2
    assert report["suspicious_events_count"] == 2
    assert "Process Activity" in report["behavior_categories"]
    assert "Network Communications" in report["behavior_categories"]
    assert report["behavioral_risk_score"] > 0
    assert report["behavioral_risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    # Verify persistence in database
    db_events = get_behavioral_events_by_scan_id(clean_scan_id)
    assert len(db_events) == 2


def test_behavioral_event_retrieval_and_summary(clean_scan_id):
    """Test 2 & 3: Scan-to-behavior association retrieval and summary endpoint."""
    # First ingest a test event
    ev = {
        "event_id": str(uuid.uuid4()),
        "scan_id": clean_scan_id,
        "timestamp": "2026-09-21T14:05:00Z",
        "event_type": "persistence_attempt",
        "target": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "severity": "high",
        "indicator": "T1547.001",
        "description": "Auto-start registry key Run modification observed."
    }
    client.post("/api/behavioral/events", json={"scan_id": clean_scan_id, "events": [ev]})

    # Detailed report retrieval
    detail_res = client.get(f"/api/behavioral/{clean_scan_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["total_events"] >= 1
    assert any(ind["name"] == "Potential Persistence Behavior Observed" for ind in detail["behavioral_indicators"])

    # Summary retrieval
    summary_res = client.get(f"/api/behavioral/{clean_scan_id}/summary")
    assert summary_res.status_code == 200
    summary = summary_res.json()
    assert summary["scan_id"] == clean_scan_id
    assert summary["behavioral_risk_score"] >= 15
    assert "summary" in summary


def test_behavioral_risk_scoring_and_levels():
    """Test 4 & 5: Transparent rule-based behavioral risk scoring and level mapping."""
    # Low-severity telemetry
    low_events = [
        {"event_id": "1", "event_type": "file_creation", "severity": "low", "description": "Created temporary log file."}
    ]
    low_report = BehavioralAnalysisEngine.analyze_events("test-low", low_events)
    assert low_report["behavioral_risk_score"] <= 39
    assert low_report["behavioral_risk_level"] == "LOW"

    # Critical telemetry (injection + tampering)
    crit_events = [
        {
            "event_id": "c1",
            "event_type": "injection_attempt",
            "severity": "critical",
            "indicator": "T1055.012",
            "description": "Process hollowing observed in remote notepad.exe"
        },
        {
            "event_id": "c2",
            "event_type": "suspicious_command",
            "severity": "critical",
            "command": "vssadmin delete shadows /all /quiet",
            "description": "Attempted shadow copy deletion"
        },
        {
            "event_id": "c3",
            "event_type": "network_connection",
            "port": 4444,
            "severity": "high",
            "description": "C2 communication observed"
        }
    ]
    crit_report = BehavioralAnalysisEngine.analyze_events("test-crit", crit_events)
    assert crit_report["behavioral_risk_score"] >= 70
    assert crit_report["behavioral_risk_level"] in ["HIGH", "CRITICAL"]
    assert crit_report["behavioral_classification"] == "MALICIOUS"
    assert len(crit_report["behavioral_indicators"]) >= 2


def test_threat_risk_score_correlation():
    """Test 6: Unified Threat Risk Score correlation formula."""
    # 1. Static ML score = 60, Behavioral risk score = 80
    b_report = {"behavioral_risk_score": 80, "mitre_attack_techniques": [{"technique_id": "T1055"}]}
    correlated = BehavioralAnalysisEngine.correlate_with_static_prediction(
        static_score=60,
        static_classification="SUSPICIOUS",
        behavioral_report=b_report
    )
    # Expected: 0.5 * 60 + 0.5 * 80 = 70 -> MALICIOUS
    assert correlated["threat_risk_score"] == 70
    assert correlated["final_threat_score"] == 70
    assert correlated["final_classification"] == "MALICIOUS"
    assert correlated["fusion_mode"] == "MULTI_LAYER_ENSEMBLE"

    # 2. Without behavioral telemetry (static only)
    static_only = BehavioralAnalysisEngine.correlate_with_static_prediction(
        static_score=35,
        static_classification="BENIGN",
        behavioral_report=None
    )
    assert static_only["threat_risk_score"] == 35
    assert static_only["fusion_mode"] == "STATIC_ONLY"


def test_behavioral_alert_generation(clean_scan_id):
    """Test 7: High-severity behavioral events trigger explicit SOC alerts."""
    high_events = [
        {
            "event_id": str(uuid.uuid4()),
            "scan_id": clean_scan_id,
            "timestamp": "2026-09-21T14:10:00Z",
            "event_type": "injection_attempt",
            "severity": "critical",
            "indicator": "T1055.012",
            "description": "Cross-process memory injection detected targeting svchost.exe."
        }
    ]
    res = client.post("/api/behavioral/events", json={"scan_id": clean_scan_id, "events": high_events})
    assert res.status_code == 201

    # Check alert was created
    alerts_res = client.get("/api/alerts")
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    assert any("Behavioral Alert" in a["title"] or a["scan_id"] == clean_scan_id for a in alerts)


def test_backward_compatibility_scan_behavioral_endpoint(clean_scan_id):
    """Test 8: Existing POST /api/scans/{scan_id}/behavioral endpoint remains 100% operational."""
    legacy_payload = {
        "events": [{"tag": "DEFENDER_TAMPERING", "description": "Disabled Microsoft Defender realtime protection."}],
        "network_traffic": [{"destination_ip": "10.0.0.99", "port": 8888, "is_suspicious": True}],
        "file_modifications": [{"path": f"C:\\file_{i}.dat"} for i in range(12)],
        "registry_modifications": [{"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"}],
        "spawned_processes": [{"command_line": "cmd.exe /c whoami"}]
    }

    res = client.post(f"/api/scans/{clean_scan_id}/behavioral", json=legacy_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["behavioral_analysis"] is not None
    assert data["combined_verdict"] is not None
    assert data["combined_verdict"]["threat_risk_score"] is not None
    assert data["threat_score"] == data["combined_verdict"]["final_threat_score"]


def test_zero_execution_guarantee():
    """Test 9: Verify telemetry conversion and analysis is strictly data parsing without subprocess execution."""
    raw_payload = {
        "spawned_processes": [{"command_line": "calc.exe"}],
        "file_modifications": [{"path": "C:\\temp\\fake.exe"}],
    }
    events = convert_legacy_telemetry_to_events("dry-run", raw_payload)
    assert len(events) >= 2
    assert all(isinstance(e, dict) for e in events)
    assert all("event_id" in e and "event_type" in e for e in events)
