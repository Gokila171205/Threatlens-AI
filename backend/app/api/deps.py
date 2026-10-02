from typing import Optional, List
from fastapi import Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.core.security import decode_access_token
from app.services.user_service import find_user_by_id, find_user_by_email, normalize_role

security = HTTPBearer(auto_error=False)

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(security)) -> dict:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id = payload.get("id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token format",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    user = find_user_by_id(user_id)
    if not user and payload.get("email"):
        user = find_user_by_email(payload["email"])
    if not user and payload.get("sub"):
        user = find_user_by_email(payload["sub"])

    if not user:
        email = payload.get("email") or payload.get("sub")
        role = payload.get("role")
        if email and role:
            user = {
                "id": user_id,
                "email": email,
                "name": payload.get("name", email.split("@")[0]),
                "role": normalize_role(role),
                "is_active": True,
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authenticated user no longer exists",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    # Ensure role is standardized
    user["role"] = normalize_role(user.get("role"))
    return user

def get_optional_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(security)) -> Optional[dict]:
    if not credentials:
        return None
    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload:
        return None
    user_id = payload.get("id")
    if not user_id:
        return None
    user = find_user_by_id(user_id)
    if user:
        user["role"] = normalize_role(user.get("role"))
    return user

def require_role(roles: List[str]):
    """
    Enforces RBAC permissions.
    Administrator always possesses superuser authorization across all platform operations.
    """
    normalized_allowed = [normalize_role(r) for r in roles]
    
    def role_checker(current_user: dict = Depends(get_current_user)):
        user_role = normalize_role(current_user.get("role"))
        # Administrator has access across all operations
        if user_role == "Administrator":
            return current_user
        if user_role not in normalized_allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Insufficient role permissions. Required one of: {', '.join(normalized_allowed)}",
            )
        return current_user
    return role_checker
