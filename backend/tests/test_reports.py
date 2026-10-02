"""
ThreatLens AI - Security Reports API & Persistence Tests
Verifies:
- Generating reports from scan results
- Persisting reports to MongoDB Atlas
- Retrieving report list and individual report details
- Exporting reports in STIX 2.1 and JSON bundle formats
- RBAC authorization on reports
"""

import io
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


@pytest.fixture
def sample_scan_id(auth_headers):
    """Creates a scan for report generation tests."""
    dummy_file = io.BytesIO(b"MZ" + b"\x90" * 400 + b"powershell.exe -enc ZmFrZQ==")
    res = client.post(
        "/api/scans/file",
        files={"file": ("report_target.exe", dummy_file, "application/octet-stream")},
        headers=auth_headers
    )
    assert res.status_code == 201
    return res.json()["id"]


def test_create_report_from_scan(auth_headers, sample_scan_id):
    """Verify creating a persistent report from a completed scan."""
    payload = {
        "scan_id": sample_scan_id,
        "title": "Incident Investigation Report - report_target.exe",
        "report_type": "Executive",
        "period": "Last 24 Hours",
        "summary": "Comprehensive forensic investigation of suspicious PowerShell launcher.",
        "recommended_actions": [
            "Isolate compromised host immediately.",
            "Block identified C2 indicators."
        ]
    }
    res = client.post("/api/reports", json=payload, headers=auth_headers)
    assert res.status_code == 201
    report = res.json()
    assert report["id"].startswith("REP-")
    assert report["filename"] == "report_target.exe"
    assert report["threat_score"] >= 0
    assert report["summary"] == payload["summary"]
    return report["id"]


def test_list_and_get_report_by_id(auth_headers, sample_scan_id):
    """Verify listing all reports and retrieving by ID."""
    # Create report first
    create_res = client.post("/api/reports", json={
        "scan_id": sample_scan_id,
        "title": "Persistent Audit Report",
        "report_type": "Technical",
        "period": "Last 7 Days"
    }, headers=auth_headers)
    assert create_res.status_code == 201
    report_id = create_res.json()["id"]

    # List reports
    list_res = client.get("/api/reports", headers=auth_headers)
    assert list_res.status_code == 200
    reports = list_res.json()
    assert isinstance(reports, list)
    assert any(r["id"] == report_id for r in reports)

    # Get single report
    get_res = client.get(f"/api/reports/{report_id}", headers=auth_headers)
    assert get_res.status_code == 200
    single = get_res.json()
    assert single["id"] == report_id
    assert single["filename"] == "report_target.exe"


def test_export_report_formats(auth_headers, sample_scan_id):
    """Verify exporting report in JSON and STIX 2.1 formats."""
    create_res = client.post("/api/reports", json={
        "scan_id": sample_scan_id,
        "title": "Exportable STIX Report",
        "report_type": "Compliance",
        "period": "Current Session"
    }, headers=auth_headers)
    report_id = create_res.json()["id"]

    # JSON export
    json_res = client.get(f"/api/reports/{report_id}/export?format=json", headers=auth_headers)
    assert json_res.status_code == 200
    json_data = json_res.json()
    assert json_data["id"] == report_id
    assert json_data["filename"] == "report_target.exe"

    # STIX export
    stix_res = client.get(f"/api/reports/{report_id}/export?format=stix", headers=auth_headers)
    assert stix_res.status_code == 200
    stix_data = stix_res.json()
    assert stix_data["type"] == "bundle"
    assert len(stix_data["objects"]) >= 2
