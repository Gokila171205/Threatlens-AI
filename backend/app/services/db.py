import json
import os
from pathlib import Path

DB_PATH = Path("storage/db.json")

def get_db():
    if not DB_PATH.parent.exists():
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not DB_PATH.exists():
        with open(DB_PATH, "w") as f:
            json.dump({"files": [], "users": []}, f)
            
    with open(DB_PATH, "r") as f:
        data = json.load(f)
        
    if "users" not in data:
        data["users"] = []
        save_db(data)
        
    return data

def save_db(data):
    with open(DB_PATH, "w") as f:
        json.dump(data, f, indent=2)
