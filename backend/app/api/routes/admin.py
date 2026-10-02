"""
ThreatLens AI - Enterprise Platform Administration Endpoints
Provides administrative user lifecycle management, role delegation,
and platform metrics protected strictly by Administrator authorization.
"""

from typing import List, Optional
from pydantic import BaseModel, EmailStr
from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import require_role
from app.services.user_service import (
    create_user,
    delete_user_by_id,
    find_user_by_id,
    list_all_users,
    normalize_role,
    update_user_fields
)

router = APIRouter(prefix="/admin", tags=["Platform Administration"])


class AdminUserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str = "Security Analyst"
    department: Optional[str] = "SOC Operations"


class AdminUserUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    department: Optional[str] = None
    status: Optional[str] = None
    password: Optional[str] = None


@router.get("/users")
async def get_all_users(
    current_user: dict = Depends(require_role(["Administrator"])),
):
    """
    Lists all platform user accounts with roles and activity statuses.
    Password hashes are strictly sanitized from response.
    """
    users = list_all_users()
    return {"success": True, "users": users}


@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_platform_user(
    payload: AdminUserCreate,
    current_user: dict = Depends(require_role(["Administrator"])),
):
    """
    Provisions a new analyst, SOC operator, or researcher account.
    """
    try:
        new_u = create_user(
            name=payload.name,
            email=payload.email,
            plain_password=payload.password,
            role=payload.role,
            department=payload.department or "SOC Operations",
        )
        safe_user = dict(new_u)
        safe_user.pop("passwordHash", None)
        return {"success": True, "message": "User created successfully", "user": safe_user}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )


@router.patch("/users/{user_id}")
async def update_platform_user(
    user_id: str,
    payload: AdminUserUpdate,
    current_user: dict = Depends(require_role(["Administrator"])),
):
    """
    Modifies account properties including role elevation or account deactivation.
    """
    updates = payload.model_dump(exclude_unset=True)
    updated = update_user_fields(user_id, updates)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found.",
        )
    updated["is_active"] = (updated.get("status") != "Inactive")
    return {"success": True, "message": "User updated successfully", "user": updated}


@router.delete("/users/{user_id}")
async def delete_platform_user(
    user_id: str,
    current_user: dict = Depends(require_role(["Administrator"])),
):
    """
    Deactivates and removes an account. Prevents administrator from deleting their own active session.
    """
    if current_user.get("id") == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete currently active administrator session.",
        )
    success = delete_user_by_id(user_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found.",
        )
    return {"success": True, "message": f"User {user_id} removed successfully."}
