import uuid
from datetime import datetime
from app.services.db import get_db, save_db
from app.core.security import get_password_hash

def find_user_by_email(email: str):
    db = get_db()
    for u in db.get("users", []):
        if u.get("email") == email:
            return u
    return None

def find_user_by_id(user_id: str):
    db = get_db()
    for u in db.get("users", []):
        if u.get("id") == user_id:
            return u
    return None

def create_user(name: str, email: str, plain_password: str, role: str = "USER"):
    db = get_db()
    
    if find_user_by_email(email):
        raise ValueError("Email already registered")
        
    password_hash = get_password_hash(plain_password)
    
    new_user = {
        "id": str(uuid.uuid4()),
        "name": name,
        "email": email,
        "passwordHash": password_hash,
        "role": role,
        "createdAt": datetime.utcnow().isoformat() + "Z",
        "updatedAt": datetime.utcnow().isoformat() + "Z"
    }
    
    db["users"].append(new_user)
    save_db(db)
    
    return new_user

def get_user_count():
    db = get_db()
    return len(db.get("users", []))

def seed_admin_if_empty():
    db = get_db()
    if not db.get("users"):
        print("Database empty, seeding default ADMIN user...")
        create_user("Admin User", "admin@threatlens.ai", "admin123", "ADMIN")
        create_user("SOC Analyst", "soc@threatlens.ai", "soc123", "SOC_ANALYST")
