"""
ThreatLens AI - Admin User Management API & RBAC Authorization Tests
Verifies:
- Only Administrator role can access admin endpoints
- Other roles (Security Analyst, SOC Member, Researcher) receive 403 Forbidden
- Admin can list all users
- Admin can create new users
- Admin can update user role and active status
- Admin can delete users
- Password hashes are strictly omitted from responses
"""

import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_admin_access_forbidden_for_non_admins(auth_headers, soc_headers, researcher_headers):
    """Verify non-admin roles receive 403 Forbidden on all admin endpoints."""
    # Security Analyst
    assert client.get("/api/admin/users", headers=auth_headers).status_code == 403
    # SOC Team Member
    assert client.get("/api/admin/users", headers=soc_headers).status_code == 403
    # Threat Researcher
    assert client.get("/api/admin/users", headers=researcher_headers).status_code == 403


def test_admin_list_users(admin_headers):
    """Verify Administrator can list all platform users without password hashes."""
    res = client.get("/api/admin/users", headers=admin_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert "users" in data
    assert len(data["users"]) >= 1

    # Security check: verify no password hashes exposed
    for u in data["users"]:
        assert "password" not in u
        assert "password_hash" not in u
        assert "hashed_password" not in u


def test_admin_create_update_delete_user_lifecycle(admin_headers):
    """Verify full CRUD lifecycle for administrator user management."""
    test_email = f"newanalyst_{uuid.uuid4().hex[:6]}@threatlens.ai"
    
    # 1. Create User
    create_res = client.post("/api/admin/users", json={
        "name": "Jane Analyst",
        "email": test_email,
        "password": "SecurePassword123!",
        "role": "Security Analyst",
        "department": "SOC Tier 2"
    }, headers=admin_headers)
    assert create_res.status_code == 201
    created_user = create_res.json()["user"]
    user_id = created_user["id"]
    assert created_user["email"] == test_email
    assert created_user["role"] == "Security Analyst"

    # 2. Update User Role and Status
    patch_res = client.patch(f"/api/admin/users/{user_id}", json={
        "role": "SOC Team Member",
        "status": "Inactive"
    }, headers=admin_headers)
    assert patch_res.status_code == 200
    updated_user = patch_res.json()["user"]
    assert updated_user["role"] == "SOC Team Member"
    assert updated_user["is_active"] is False

    # 3. Delete User
    del_res = client.delete(f"/api/admin/users/{user_id}", headers=admin_headers)
    assert del_res.status_code == 200
    assert del_res.json()["success"] is True
