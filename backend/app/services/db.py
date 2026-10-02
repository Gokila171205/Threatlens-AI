"""
ThreatLens AI - Enterprise Database Layer (MongoDB Atlas Single Source of Truth)

=============================================================================
BACKUP ARTIFACT NOTICE:
'storage/db.json' is retained strictly as an offline historical backup/migration
artifact. It is NOT accessed, read, or modified during normal application requests.
MongoDB Atlas is the single and exclusive source of truth for all application
persistence, threat analytics, scan history, alerts, and user accounts.
=============================================================================

Credential Safety Guarantee:
MongoDB connection strings and credentials are NEVER logged, printed, or exposed.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import pymongo
from pymongo import MongoClient
from pymongo.database import Database

from app.core.config import settings

logger = logging.getLogger("threatlens.db")

# Historical migration/backup artifact path (NOT used during normal runtime)
DB_BACKUP_PATH = Path("storage/db.json")

# Global singleton client & database instances
_mongo_client: Optional[MongoClient] = None
_mongo_db: Optional[Database] = None
_migration_checked: bool = False


class DatabaseConnectionError(RuntimeError):
    """Raised when MongoDB Atlas is unreachable or unconfigured, refusing stale local fallback."""
    pass


def clean_doc(doc: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Strips MongoDB internal _id (ObjectId) to prevent serialization/validation errors."""
    if not doc:
        return None
    cleaned = dict(doc)
    cleaned.pop("_id", None)
    return cleaned


def clean_docs(docs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Strips MongoDB internal _id from a list of documents."""
    return [clean_doc(d) for d in docs if d is not None]


def get_mongo_client() -> MongoClient:
    """
    Retrieves or initializes the MongoDB client singleton with 5-second timeouts.
    Raises DatabaseConnectionError if MongoDB Atlas cannot be reached.
    """
    global _mongo_client
    if _mongo_client is not None:
        return _mongo_client

    if not settings.mongo_uri:
        raise DatabaseConnectionError(
            "MongoDB Atlas URI is not configured in backend/.env. MongoDB is required as the single source of truth."
        )

    try:
        client = MongoClient(
            settings.mongo_uri,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
            socketTimeoutMS=10000,
            appname=settings.app_name,
        )
        # Verify cluster ping immediately
        client.admin.command("ping")
        _mongo_client = client
        return _mongo_client
    except Exception as exc:
        logger.error(f"[Database] MongoDB Atlas connection failed ({exc.__class__.__name__}). Stale local fallback is disabled.")
        raise DatabaseConnectionError(
            f"MongoDB Atlas is unreachable ({exc.__class__.__name__}). Refusing fallback to local files to maintain single source of truth."
        ) from exc


def get_mongo_db() -> Database:
    """
    Returns the target MongoDB database instance with case-insensitive resolution.
    Raises DatabaseConnectionError if unavailable.
    """
    global _mongo_db
    if _mongo_db is not None:
        return _mongo_db

    client = get_mongo_client()
    target_name = settings.mongo_db_name
    try:
        existing_dbs = client.list_database_names()
        for db_name in existing_dbs:
            if db_name.lower() == target_name.lower():
                target_name = db_name
                break
    except Exception:
        pass

    _mongo_db = client[target_name]
    return _mongo_db


def is_mongo_active() -> bool:
    """Checks if MongoDB is currently available and authenticated."""
    try:
        client = get_mongo_client()
        client.admin.command("ping")
        return True
    except Exception:
        return False


def init_db_and_migrate():
    """
    Initializes indexes and performs a ONE-TIME migration from db.json ONLY if
    the database is completely empty. If scans already exist, migration is permanently skipped.
    """
    global _migration_checked
    if _migration_checked:
        return

    db = get_mongo_db()

    try:
        # Create performance and uniqueness indexes
        db.users.create_index([("email", pymongo.ASCENDING)], unique=True, sparse=True)
        db.users.create_index([("id", pymongo.ASCENDING)], unique=True, sparse=True)

        db.scans.create_index([("id", pymongo.ASCENDING)], unique=True)
        db.scans.create_index([("sha256", pymongo.ASCENDING)])
        db.scans.create_index([("user_id", pymongo.ASCENDING)])
        db.scans.create_index([("scanned_at", pymongo.DESCENDING)])

        db.alerts.create_index([("id", pymongo.ASCENDING)], unique=True)
        db.alerts.create_index([("scan_id", pymongo.ASCENDING)])
        db.alerts.create_index([("user_id", pymongo.ASCENDING)])

        db.behavioral_events.create_index([("event_id", pymongo.ASCENDING)], unique=True)
        db.behavioral_events.create_index([("scan_id", pymongo.ASCENDING)])

        db.reports.create_index([("id", pymongo.ASCENDING)], unique=True)
        db.reports.create_index([("created_at", pymongo.DESCENDING)])

        db.files.create_index([("id", pymongo.ASCENDING)], unique=True, sparse=True)

        # Check existing records to prevent duplicate migration
        existing_scans_count = db.scans.count_documents({})
        if existing_scans_count > 0:
            # Already migrated; never re-migrate
            _migration_checked = True
            return

        # Perform initial migration only if database is completely empty and backup exists
        if existing_scans_count == 0 and DB_BACKUP_PATH.exists():
            with open(DB_BACKUP_PATH, "r", encoding="utf-8") as f:
                local_data = json.load(f)

            for u in local_data.get("users", []):
                if u.get("id"):
                    db.users.replace_one({"id": u["id"]}, u, upsert=True)

            for s in local_data.get("scans", []):
                if s.get("id"):
                    db.scans.replace_one({"id": s["id"]}, s, upsert=True)

            for a in local_data.get("alerts", []):
                if a.get("id"):
                    db.alerts.replace_one({"id": a["id"]}, a, upsert=True)

            for ev in local_data.get("behavioral_events", []):
                if ev.get("event_id"):
                    db.behavioral_events.replace_one({"event_id": ev["event_id"]}, ev, upsert=True)

            for f in local_data.get("files", []):
                if f.get("id"):
                    db.files.replace_one({"id": f["id"]}, f, upsert=True)

        _migration_checked = True
    except Exception as exc:
        logger.warning(f"[Database] Index check: {exc.__class__.__name__}")
        _migration_checked = True


# =====================================================================
# MongoDB Single Source of Truth Interface
# =====================================================================

def get_db() -> Dict[str, Any]:
    """
    Returns application database snapshot from MongoDB Atlas ONLY.
    Refuses local fallback if MongoDB is unavailable.
    """
    init_db_and_migrate()
    db = get_mongo_db()
    return {
        "files": clean_docs(list(db.files.find())),
        "users": clean_docs(list(db.users.find())),
        "scans": clean_docs(list(db.scans.find().sort("scanned_at", pymongo.DESCENDING))),
        "alerts": clean_docs(list(db.alerts.find().sort("created_at", pymongo.DESCENDING))),
        "behavioral_events": clean_docs(list(db.behavioral_events.find())),
    }


def save_db(data: Dict[str, Any]):
    """
    Persists data dictionary strictly to MongoDB Atlas.
    Does NOT write to storage/db.json during normal application operations.
    """
    db = get_mongo_db()
    for u in data.get("users", []):
        if u.get("id"):
            db.users.replace_one({"id": u["id"]}, u, upsert=True)
    for s in data.get("scans", []):
        if s.get("id"):
            db.scans.replace_one({"id": s["id"]}, s, upsert=True)
    for a in data.get("alerts", []):
        if a.get("id"):
            db.alerts.replace_one({"id": a["id"]}, a, upsert=True)
    for ev in data.get("behavioral_events", []):
        if ev.get("event_id"):
            db.behavioral_events.replace_one({"event_id": ev["event_id"]}, ev, upsert=True)
    for f in data.get("files", []):
        if f.get("id"):
            db.files.replace_one({"id": f["id"]}, f, upsert=True)


# =====================================================================
# Scan Operations (MongoDB Atlas ONLY)
# =====================================================================

def save_scan_record(scan_dict: dict) -> dict:
    """Saves or updates a scan record exclusively in MongoDB Atlas."""
    init_db_and_migrate()
    db = get_mongo_db()
    db.scans.replace_one({"id": scan_dict["id"]}, scan_dict, upsert=True)
    return scan_dict


def get_scan_records(user_id: str = None, limit: int = 100) -> List[dict]:
    """Retrieves scans exclusively from MongoDB Atlas sorted chronologically descending."""
    init_db_and_migrate()
    db = get_mongo_db()
    query = {"user_id": user_id} if user_id else {}
    cursor = db.scans.find(query).sort("scanned_at", pymongo.DESCENDING).limit(limit)
    return clean_docs(list(cursor))


def get_scan_by_id(scan_id: str) -> Optional[dict]:
    """Finds a scan by its unique ID exclusively from MongoDB Atlas."""
    init_db_and_migrate()
    db = get_mongo_db()
    doc = db.scans.find_one({"id": scan_id})
    return clean_doc(doc)


# =====================================================================
# Alert Operations (MongoDB Atlas ONLY)
# =====================================================================

def save_alert_record(alert_dict: dict) -> dict:
    """Saves or updates an alert record exclusively in MongoDB Atlas."""
    init_db_and_migrate()
    db = get_mongo_db()
    db.alerts.replace_one({"id": alert_dict["id"]}, alert_dict, upsert=True)
    return alert_dict


def get_alert_records(user_id: str = None, limit: int = 100) -> List[dict]:
    """Retrieves alerts exclusively from MongoDB Atlas sorted chronologically descending."""
    init_db_and_migrate()
    db = get_mongo_db()
    query = {"user_id": user_id} if user_id else {}
    cursor = db.alerts.find(query).sort("created_at", pymongo.DESCENDING).limit(limit)
    return clean_docs(list(cursor))


def update_alert_record(alert_id: str, updates: dict) -> Optional[dict]:
    """Updates fields on an existing alert exclusively in MongoDB Atlas."""
    init_db_and_migrate()
    db = get_mongo_db()
    db.alerts.update_one({"id": alert_id}, {"$set": updates})
    doc = db.alerts.find_one({"id": alert_id})
    return clean_doc(doc)


# =====================================================================
# Behavioral Event Operations (MongoDB Atlas ONLY)
# =====================================================================

def save_behavioral_event(event_dict: dict) -> dict:
    """Saves or updates a normalized behavioral event exclusively in MongoDB Atlas."""
    init_db_and_migrate()
    db = get_mongo_db()
    db.behavioral_events.replace_one({"event_id": event_dict["event_id"]}, event_dict, upsert=True)
    return event_dict


def save_behavioral_events(events: list) -> list:
    """Batch saves normalized behavioral events exclusively in MongoDB Atlas."""
    init_db_and_migrate()
    db = get_mongo_db()
    for event_dict in events:
        if event_dict.get("event_id"):
            db.behavioral_events.replace_one({"event_id": event_dict["event_id"]}, event_dict, upsert=True)
    return events


def get_behavioral_events_by_scan_id(scan_id: str) -> list:
    """Retrieves normalized behavioral events exclusively from MongoDB Atlas."""
    init_db_and_migrate()
    db = get_mongo_db()
    cursor = db.behavioral_events.find({"scan_id": scan_id})
    return clean_docs(list(cursor))


def get_all_behavioral_events(limit: int = 500) -> list:
    """Returns stored behavioral events exclusively from MongoDB Atlas up to limit."""
    init_db_and_migrate()
    db = get_mongo_db()
    cursor = db.behavioral_events.find({}).limit(limit)
    return clean_docs(list(cursor))


# =====================================================================
# Report Operations (MongoDB Atlas ONLY)
# =====================================================================

def save_report_record(report_dict: dict) -> dict:
    """Saves or updates an investigation report exclusively in MongoDB Atlas."""
    init_db_and_migrate()
    db = get_mongo_db()
    db.reports.replace_one({"id": report_dict["id"]}, report_dict, upsert=True)
    return report_dict


def get_report_records(user_id: str = None, limit: int = 100) -> List[dict]:
    """Retrieves saved reports from MongoDB Atlas sorted chronologically descending."""
    init_db_and_migrate()
    db = get_mongo_db()
    query = {"user_id": user_id} if user_id else {}
    cursor = db.reports.find(query).sort("created_at", pymongo.DESCENDING).limit(limit)
    return clean_docs(list(cursor))


def get_report_by_id(report_id: str) -> Optional[dict]:
    """Finds an investigation report by unique ID from MongoDB Atlas."""
    init_db_and_migrate()
    db = get_mongo_db()
    doc = db.reports.find_one({"id": report_id})
    return clean_doc(doc)


def delete_report_by_id(report_id: str) -> bool:
    """Deletes an investigation report by unique ID from MongoDB Atlas."""
    init_db_and_migrate()
    db = get_mongo_db()
    res = db.reports.delete_one({"id": report_id})
    return res.deleted_count > 0
