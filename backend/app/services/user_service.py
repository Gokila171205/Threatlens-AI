import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from app.services.db import get_db, save_db
from app.core.security import get_password_hash

ROLE_MAP = {
    "ADMIN": "Administrator",
    "ADMINISTRATOR": "Administrator",
    "SECURITY_ANALYST": "Security Analyst",
    "SECURITY ANALYST": "Security Analyst",
    "SOC_ANALYST": "SOC Team Member",
    "SOC TEAM MEMBER": "SOC Team Member",
    "SOC_TEAM_MEMBER": "SOC Team Member",
    "RESEARCHER": "Researcher",
    "USER": "Security Analyst",
}

def normalize_role(role: Optional[str]) -> str:
    if not role:
        return "Security Analyst"
    clean = str(role).strip().upper()
    return ROLE_MAP.get(clean, role)

def find_user_by_email(email: str) -> Optional[dict]:
    db = get_db()
    clean_email = email.strip().lower()
    for u in db.get("users", []):
        if u.get("email", "").strip().lower() == clean_email:
            u_clean = dict(u)
            u_clean["role"] = normalize_role(u_clean.get("role"))
            return u_clean
    return None

def find_user_by_id(user_id: str) -> Optional[dict]:
    db = get_db()
    for u in db.get("users", []):
        if u.get("id") == user_id:
            u_clean = dict(u)
            u_clean["role"] = normalize_role(u_clean.get("role"))
            return u_clean
    return None

def create_user(name: str, email: str, plain_password: str, role: str = "Security Analyst", department: str = "SOC Operations") -> dict:
    db = get_db()
    
    clean_email = email.strip().lower()
    if find_user_by_email(clean_email):
        raise ValueError("Email already registered")
        
    password_hash = get_password_hash(plain_password)
    now_iso = datetime.now(timezone.utc).isoformat()
    
    new_user = {
        "id": str(uuid.uuid4()),
        "name": name,
        "email": clean_email,
        "passwordHash": password_hash,
        "role": normalize_role(role),
        "department": department,
        "status": "Active",
        "createdAt": now_iso,
        "updatedAt": now_iso
    }
    
    users = db.get("users", [])
    users.append(new_user)
    db["users"] = users
    save_db(db)
    
    return new_user

def list_all_users() -> List[dict]:
    db = get_db()
    users = db.get("users", [])
    cleaned = []
    for u in users:
        u_dict = dict(u)
        u_dict.pop("passwordHash", None)
        u_dict["role"] = normalize_role(u_dict.get("role"))
        cleaned.append(u_dict)
    return cleaned

def update_user_fields(user_id: str, updates: dict) -> Optional[dict]:
    db = get_db()
    users = db.get("users", [])
    target = None
    for u in users:
        if u.get("id") == user_id:
            target = u
            break
    if not target:
        return None
    
    if "role" in updates and updates["role"]:
        target["role"] = normalize_role(updates["role"])
    if "name" in updates and updates["name"]:
        target["name"] = updates["name"]
    if "department" in updates:
        target["department"] = updates["department"]
    if "status" in updates:
        target["status"] = updates["status"]
    if "password" in updates and updates["password"]:
        target["passwordHash"] = get_password_hash(updates["password"])
        
    target["updatedAt"] = datetime.now(timezone.utc).isoformat()
    db["users"] = users
    save_db(db)
    
    res = dict(target)
    res.pop("passwordHash", None)
    return res

def delete_user_by_id(user_id: str) -> bool:
    db = get_db()
    users = db.get("users", [])
    init_len = len(users)
    users = [u for u in users if u.get("id") != user_id]
    if len(users) < init_len:
        db["users"] = users
        save_db(db)
        return True
    return False

def get_user_count():
    db = get_db()
    return len(db.get("users", []))

def seed_admin_if_empty():
    """Seeds standard role accounts if missing, ensuring seamless authentication."""
    default_accounts = [
        ("Marcus Vance", "admin@threatlens.ai", "admin123", "Administrator", "Cyber Infrastructure"),
        ("Alex Rivera", "analyst@threatlens.ai", "analyst123", "Security Analyst", "Tier 3 Incident Response"),
        ("Sarah Chen", "soc@threatlens.ai", "soc123", "SOC Team Member", "Global SOC Operations"),
        ("Dr. Elena Rostova", "researcher@threatlens.ai", "research123", "Researcher", "AI Malware Lab"),
        # Also seed demo email aliases for instant compatibility
        ("Alex Rivera", "a.rivera@defense.threatlens.ai", "analyst123", "Security Analyst", "Tier 3 Incident Response"),
        ("Sarah Chen", "s.chen@soc.threatlens.ai", "soc123", "SOC Team Member", "Global SOC Operations"),
        ("Marcus Vance", "m.vance@admin.threatlens.ai", "admin123", "Administrator", "Cyber Infrastructure"),
        ("Dr. Elena Rostova", "e.rostova@lab.threatlens.ai", "research123", "Researcher", "AI Malware Lab"),
    ]
    
    for name, email, pwd, role, dept in default_accounts:
        if not find_user_by_email(email):
            try:
                create_user(name, email, pwd, role, dept)
            except Exception:
                pass
