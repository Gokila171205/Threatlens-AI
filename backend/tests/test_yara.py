"""
ThreatLens AI - Real YARA Engine & Signature Matching Tests
Verifies:
- Rule compilation and memory-safe byte inspection (zero-execution)
- Detection of safe demonstration rules (PowerShell commands, Ransomware indicators)
- YARA matches returned alongside heuristic indicators in scan endpoint
- Clear distinction between YARA rules and heuristic indicators
"""

import io
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.yara_service import scan_file_with_yara

client = TestClient(app)


def test_yara_powershell_rule_matching():
    """Verify YARA engine detects Suspicious_PowerShell_Execution rule."""
    payload_bytes = b"MZ\x90\x00powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -encodedcommand ZmFrZQ=="
    matches = scan_file_with_yara(payload_bytes)
    assert len(matches) >= 1
    match_names = [m["rule_name"] for m in matches]
    assert "Suspicious_PowerShell_Execution" in match_names

    ps_match = next(m for m in matches if m["rule_name"] == "Suspicious_PowerShell_Execution")
    assert ps_match["severity"] == "high"
    assert len(ps_match["matched_strings"]) >= 2


def test_yara_shadowcopy_deletion_rule_matching():
    """Verify YARA engine detects Ransomware_ShadowCopy_Deletion rule."""
    payload_bytes = b"MZ\x90\x00vssadmin delete shadows /quiet"
    matches = scan_file_with_yara(payload_bytes)
    assert len(matches) >= 1
    match_names = [m["rule_name"] for m in matches]
    assert "Ransomware_ShadowCopy_Deletion" in match_names


def test_yara_benign_sample_no_false_matches():
    """Verify clean benign byte sample triggers zero YARA hits."""
    clean_bytes = b"MZ\x90\x00Standard benign program text without any suspicious signatures."
    matches = scan_file_with_yara(clean_bytes)
    assert len(matches) == 0


def test_scan_endpoint_includes_real_yara_matches(auth_headers):
    """Verify file upload scan endpoint returns genuine yara_matches field."""
    test_binary = b"MZ" + b"\x90" * 300 + b"powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass"
    res = client.post(
        "/api/scans/file",
        files={"file": ("powershell_sample.exe", io.BytesIO(test_binary), "application/octet-stream")},
        headers=auth_headers
    )
    assert res.status_code == 201
    data = res.json()
    assert "yara_matches" in data
    assert len(data["yara_matches"]) >= 1
    assert data["yara_matches"][0]["rule_name"] == "Suspicious_PowerShell_Execution"

    # Verify indicators and yara_matches are separate fields
    assert "indicators" in data
    assert isinstance(data["indicators"], list)
