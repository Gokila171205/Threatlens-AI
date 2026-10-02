"""
ThreatLens AI - Authentication & Role-Based Access Control (RBAC) Tests
Verifies:
- Valid login generates JWT access token
- Invalid credentials return 401 Unauthorized
- Missing tokens return 401 Unauthorized across protected endpoints
- Unauthorized roles return 403 Forbidden
- Authorized roles succeed
- /api/auth/me returns authenticated user identity
"""

import io
import pytest
from fastapi.testclient import TestClient
from app.main import app

unauthed_client = TestClient(app)


def test_auth_login_valid_credentials():
    """Verify valid login returns JWT access token and user profile."""
    res = unauthed_client.post("/api/auth/login", json={
        "email": "analyst@threatlens.ai",
        "password": "analyst123"
    })
    assert res.status_code == 200
    data = res.json()
    assert "token" in data or "access_token" in data
    assert "user" in data
    assert data["user"]["email"] == "analyst@threatlens.ai"
    assert data["user"]["role"] == "Security Analyst"


def test_auth_login_invalid_password():
    """Verify invalid password returns 401."""
    res = unauthed_client.post("/api/auth/login", json={
        "email": "analyst@threatlens.ai",
        "password": "WrongPassword999!"
    })
    assert res.status_code == 401
    assert "Invalid email or password" in str(res.json())


def test_auth_me_with_valid_token(auth_headers):
    """Verify /api/auth/me resolves the current authenticated user."""
    res = unauthed_client.get("/api/auth/me", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["user"]["email"] == "analyst@threatlens.ai"
    assert data["user"]["role"] == "Security Analyst"


def test_unauthorized_access_missing_token():
    """Verify missing Authorization header produces 401 on protected endpoints."""
    # Scans
    res = unauthed_client.get("/api/scans")
    assert res.status_code == 401

    # Alerts
    res = unauthed_client.get("/api/alerts")
    assert res.status_code == 401

    # Monitoring
    res = unauthed_client.get("/api/monitoring/overview")
    assert res.status_code == 401

    # Reports
    res = unauthed_client.get("/api/reports")
    assert res.status_code == 401

    # Admin
    res = unauthed_client.get("/api/admin/users")
    assert res.status_code == 401


def test_rbac_file_upload_forbidden_for_soc_role(soc_headers):
    """
    Verify SOC Team Member cannot directly upload malware files
    (Only Security Analyst, Researcher, Administrator are authorized).
    """
    dummy_file = io.BytesIO(b"MZ" + b"\x90" * 200)
    res = unauthed_client.post(
        "/api/scans/file",
        files={"file": ("test.exe", dummy_file, "application/octet-stream")},
        headers=soc_headers
    )
    assert res.status_code == 403
    assert "Forbidden" in str(res.json()) or "Access denied" in str(res.json()) or "role" in str(res.json()).lower()


def test_rbac_file_upload_allowed_for_analyst(auth_headers):
    """Verify Security Analyst can upload and scan files."""
    dummy_file = io.BytesIO(b"MZ" + b"\x90" * 300 + b"analyst_allowed_test")
    res = unauthed_client.post(
        "/api/scans/file",
        files={"file": ("test.exe", dummy_file, "application/octet-stream")},
        headers=auth_headers
    )
    assert res.status_code == 201
    assert "id" in res.json()


def test_rbac_admin_endpoint_forbidden_for_analyst(auth_headers):
    """Verify Security Analyst cannot access Administrator endpoints (returns 403)."""
    res = unauthed_client.get("/api/admin/users", headers=auth_headers)
    assert res.status_code == 403


def test_rbac_admin_endpoint_allowed_for_admin(admin_headers):
    """Verify Administrator can access admin user management endpoints."""
    res = unauthed_client.get("/api/admin/users", headers=admin_headers)
    assert res.status_code == 200
    data = res.json()
    assert "users" in data
