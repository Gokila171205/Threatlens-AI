"""
ThreatLens AI - Threat Monitoring & Analytics Endpoints
Provides live aggregated security metrics, time-series detection graphs,
and MITRE ATT&CK coverage statistics calculated strictly from real scan data.
"""

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends

from app.api.deps import get_optional_current_user
from app.schemas.scan import AnalyticsResponse, MonitoringOverview
from app.services.db import get_alert_records, get_scan_records


router = APIRouter(prefix="/monitoring", tags=["Threat Monitoring & Analytics"])


@router.get("/overview", response_model=MonitoringOverview)
async def get_monitoring_overview(
    current_user: Optional[dict] = Depends(get_optional_current_user),
):
    """
    Returns real-time aggregated metrics for the SOC Dashboard.
    All data is computed dynamically from real completed scans and alerts.
    """
    user_id = current_user.get("id") if current_user else None
    scans = get_scan_records(user_id=user_id, limit=200)
    alerts = get_alert_records(user_id=user_id, limit=200)

    total_scans = len(scans)
    malicious_count = sum(1 for s in scans if s.get("classification") == "MALICIOUS")
    suspicious_count = sum(1 for s in scans if s.get("classification") == "SUSPICIOUS")
    benign_count = sum(1 for s in scans if s.get("classification") == "BENIGN")

    open_alerts = sum(1 for a in alerts if a.get("status") == "OPEN")

    scores = [s.get("threat_score", 0) for s in scans]
    avg_threat_score = round(sum(scores) / len(scores), 1) if scores else 0.0

    threat_level_dist = {
        "LOW": sum(1 for s in scans if s.get("threat_level") == "LOW"),
        "MEDIUM": sum(1 for s in scans if s.get("threat_level") == "MEDIUM"),
        "HIGH": sum(1 for s in scans if s.get("threat_level") == "HIGH"),
        "CRITICAL": sum(1 for s in scans if s.get("threat_level") == "CRITICAL"),
    }

    recent_scans = []
    for s in scans[:8]:
        recent_scans.append({
            "id": s["id"],
            "filename": s.get("filename", "unknown"),
            "sha256": s.get("sha256", ""),
            "file_size_bytes": s.get("file_size_bytes", 0),
            "scanned_at": s.get("scanned_at", ""),
            "threat_score": s.get("threat_score", 0),
            "classification": s.get("classification", "BENIGN"),
            "threat_level": s.get("threat_level", "LOW"),
            "is_pe": s.get("static_analysis", {}).get("is_pe", False),
            "status": s.get("status", "COMPLETED"),
        })

    recent_alerts = alerts[:8]

    return {
        "total_scans": total_scans,
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "benign_count": benign_count,
        "open_alerts": open_alerts,
        "avg_threat_score": avg_threat_score,
        "threat_level_distribution": threat_level_dist,
        "recent_scans": recent_scans,
        "recent_alerts": recent_alerts,
    }


@router.get("/analytics", response_model=AnalyticsResponse)
async def get_monitoring_analytics(
    current_user: Optional[dict] = Depends(get_optional_current_user),
):
    """
    Provides multi-day detection timeline, threat classifications,
    and MITRE ATT&CK technique distribution.
    """
    user_id = current_user.get("id") if current_user else None
    scans = get_scan_records(user_id=user_id, limit=300)

    # 1. Timeline aggregation (last 7 days)
    today = datetime.now(timezone.utc).date()
    timeline_map = {}
    for i in range(6, -1, -1):
        day_str = (today - timedelta(days=i)).strftime("%Y-%m-%d")
        timeline_map[day_str] = {"date": day_str, "total": 0, "malicious": 0, "clean": 0}

    for s in scans:
        scanned_at_str = s.get("scanned_at", "")
        if scanned_at_str:
            try:
                date_part = scanned_at_str.split("T")[0]
                if date_part in timeline_map:
                    timeline_map[date_part]["total"] += 1
                    if s.get("classification") == "MALICIOUS":
                        timeline_map[date_part]["malicious"] += 1
                    else:
                        timeline_map[date_part]["clean"] += 1
            except Exception:
                pass

    daily_timeline = list(timeline_map.values())

    # 2. Threat types categorization
    threat_types = Counter()
    for s in scans:
        cls = s.get("classification", "BENIGN")
        threat_types[cls] += 1

    # 3. MITRE ATT&CK technique breakdown
    mitre_counter = Counter()
    for s in scans:
        for m in s.get("mitre_techniques", []):
            label = f"{m.get('technique_id')} - {m.get('technique_name')}"
            mitre_counter[label] += 1

    mitre_attack_distribution = [
        {"technique": k, "count": v}
        for k, v in mitre_counter.most_common(8)
    ]

    # 4. Shannon Entropy distribution buckets
    entropy_buckets = {"< 4.0": 0, "4.0 - 6.0": 0, "6.0 - 7.0": 0, ">= 7.0": 0}
    for s in scans:
        ent = s.get("static_analysis", {}).get("overall_entropy", 0.0)
        if ent < 4.0:
            entropy_buckets["< 4.0"] += 1
        elif ent < 6.0:
            entropy_buckets["4.0 - 6.0"] += 1
        elif ent < 7.0:
            entropy_buckets["6.0 - 7.0"] += 1
        else:
            entropy_buckets[">= 7.0"] += 1

    return {
        "daily_timeline": daily_timeline,
        "threat_types": dict(threat_types),
        "mitre_attack_distribution": mitre_attack_distribution,
        "entropy_distribution": entropy_buckets,
    }
