"""
ThreatLens AI - Threat Prediction & Risk Analytics Engine (Milestone 3, Step 5)
Synthesizes static ML evidence, behavioral indicators, historical scans, and alert telemetry
into explainable threat-risk assessments, multi-window trend analytics, and file risk trajectories.

Zero Machine-Learning Retraining & Passive Evaluation Guarantee:
This service does not train black-box models or claim probabilistic certainty.
All threat assessments are deterministic, explainable risk assessments derived from stored evidence.
"""

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import uuid

from app.services.db import get_alert_records, get_scan_by_id, get_scan_records


def calculate_threat_risk_score(static_score: int, behavioral_score: Optional[int] = None) -> int:
    """
    Computes Threat Risk Score (0-100).
    When behavioral telemetry exists: 50% static ML + 50% behavioral risk score.
    When static only: 100% static ML score.
    """
    if behavioral_score is not None:
        raw = (0.5 * static_score) + (0.5 * behavioral_score)
        return max(0, min(100, int(round(raw))))
    return max(0, min(100, int(round(static_score))))


def map_risk_level(score: int) -> str:
    """Maps score to risk level: LOW (0-39), MEDIUM (40-69), HIGH (70-84), CRITICAL (85-100)."""
    if score >= 85:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    return "LOW"


def map_threat_classification(score: int) -> str:
    """Maps score to classification: BENIGN (<40), SUSPICIOUS (40-69), MALICIOUS (>=70)."""
    if score >= 70:
        return "MALICIOUS"
    elif score >= 40:
        return "SUSPICIOUS"
    return "BENIGN"


class ThreatPredictionService:
    """
    Core analytics service providing threat risk assessments, explainable risk factors,
    multi-window trend analytics, and cross-scan file risk histories.
    """

    @classmethod
    def get_file_risk_history(cls, sha256: str) -> Dict[str, Any]:
        """
        Gathers chronological scan records for a specific SHA-256 hash.
        Identifies risk trajectory changes (increased, decreased, stable) and classification shifts.
        """
        all_scans = get_scan_records(limit=500)
        matching_scans = [
            s for s in all_scans if s.get("sha256", "").lower() == (sha256 or "").lower()
        ]
        
        all_alerts = get_alert_records(limit=500)
        matching_alerts = [
            a for a in all_alerts if a.get("sha256", "").lower() == (sha256 or "").lower()
        ]

        if not matching_scans:
            return {
                "sha256": sha256,
                "filename": "unknown",
                "total_scans": 0,
                "first_seen": "N/A",
                "last_seen": "N/A",
                "risk_trajectory": "stable",
                "classification_history": [],
                "threat_score_history": [],
                "behavioral_score_history": [],
                "alert_count": len(matching_alerts),
                "scans_summary": []
            }

        # Sort chronologically ascending
        def parse_date(iso_str: str) -> datetime:
            try:
                return datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
            except Exception:
                return datetime.min.replace(tzinfo=timezone.utc)

        sorted_scans = sorted(matching_scans, key=lambda s: parse_date(s.get("scanned_at", "")))

        first_scan = sorted_scans[0]
        last_scan = sorted_scans[-1]

        scores = [s.get("threat_score", 0) for s in sorted_scans]
        classes = [s.get("classification", "BENIGN") for s in sorted_scans]
        b_scores = [
            s.get("behavioral_analysis", {}).get("behavioral_risk_score")
            if s.get("behavioral_analysis") else None
            for s in sorted_scans
        ]

        # Calculate risk trajectory
        first_score = scores[0]
        last_score = scores[-1]
        if last_score > first_score + 5:
            trajectory = "increased"
        elif last_score < first_score - 5:
            trajectory = "decreased"
        else:
            trajectory = "stable"

        scans_summary = []
        for s in sorted_scans:
            scans_summary.append({
                "scan_id": s.get("id"),
                "scanned_at": s.get("scanned_at"),
                "threat_score": s.get("threat_score", 0),
                "classification": s.get("classification", "BENIGN"),
                "has_behavioral": s.get("behavioral_analysis") is not None
            })

        return {
            "sha256": sha256,
            "filename": last_scan.get("filename", "unknown"),
            "total_scans": len(sorted_scans),
            "first_seen": first_scan.get("scanned_at", "N/A"),
            "last_seen": last_scan.get("scanned_at", "N/A"),
            "risk_trajectory": trajectory,
            "classification_history": classes,
            "threat_score_history": scores,
            "behavioral_score_history": b_scores,
            "alert_count": len(matching_alerts),
            "scans_summary": scans_summary
        }

    @classmethod
    def analyze_threat_trends(cls, time_window: str = "7d") -> Dict[str, Any]:
        """
        Computes empirical security metrics across specified time windows (24h, 7d, 30d).
        If insufficient historical data exists, returns a clear status message rather than fake data.
        """
        now = datetime.now(timezone.utc)
        if time_window == "24h":
            delta = timedelta(hours=24)
            bucket_format = "%H:00"
            bucket_count = 24
        elif time_window == "30d":
            delta = timedelta(days=30)
            bucket_format = "%Y-%m-%d"
            bucket_count = 30
        else:  # default 7d
            time_window = "7d"
            delta = timedelta(days=7)
            bucket_format = "%Y-%m-%d"
            bucket_count = 7

        cutoff = now - delta

        def parse_date(iso_str: str) -> Optional[datetime]:
            try:
                return datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
            except Exception:
                return None

        all_scans = get_scan_records(limit=500)
        window_scans = []
        for s in all_scans:
            dt = parse_date(s.get("scanned_at", ""))
            if dt and dt >= cutoff:
                window_scans.append((dt, s))

        all_alerts = get_alert_records(limit=500)
        window_alerts = []
        for a in all_alerts:
            dt = parse_date(a.get("created_at", ""))
            if dt and dt >= cutoff:
                window_alerts.append(a)

        # Insufficient data check
        if not window_scans:
            return {
                "time_window": time_window,
                "total_scans": 0,
                "benign_scans": 0,
                "suspicious_scans": 0,
                "malicious_scans": 0,
                "avg_threat_score": 0.0,
                "highest_threat_score": 0,
                "avg_behavioral_risk_score": 0.0,
                "high_risk_scan_count": 0,
                "critical_alert_count": 0,
                "timeline": [],
                "status": "Insufficient historical data",
                "message": f"Insufficient historical data recorded for the {time_window} time window."
            }

        scans_list = [item[1] for item in window_scans]
        total_scans = len(scans_list)
        benign_scans = sum(1 for s in scans_list if s.get("classification") == "BENIGN")
        suspicious_scans = sum(1 for s in scans_list if s.get("classification") == "SUSPICIOUS")
        malicious_scans = sum(1 for s in scans_list if s.get("classification") == "MALICIOUS")

        scores = [s.get("threat_score", 0) for s in scans_list]
        avg_threat = round(sum(scores) / len(scores), 1) if scores else 0.0
        highest_threat = max(scores) if scores else 0

        b_scores = [
            s.get("behavioral_analysis", {}).get("behavioral_risk_score")
            for s in scans_list
            if s.get("behavioral_analysis") and s.get("behavioral_analysis", {}).get("behavioral_risk_score") is not None
        ]
        avg_b_score = round(sum(b_scores) / len(b_scores), 1) if b_scores else 0.0

        high_risk_count = sum(1 for s in scans_list if s.get("threat_score", 0) >= 70)
        crit_alerts = sum(1 for a in window_alerts if a.get("threat_level") in ["HIGH", "CRITICAL"])

        # Construct time buckets for timeline
        timeline_buckets: Dict[str, Dict[str, Any]] = {}
        for dt, s in window_scans:
            bucket_key = dt.strftime(bucket_format)
            if bucket_key not in timeline_buckets:
                timeline_buckets[bucket_key] = {
                    "timestamp": bucket_key,
                    "scans": 0,
                    "malicious": 0,
                    "behavioral_events": 0
                }
            timeline_buckets[bucket_key]["scans"] += 1
            if s.get("classification") == "MALICIOUS":
                timeline_buckets[bucket_key]["malicious"] += 1
            if s.get("behavioral_analysis"):
                timeline_buckets[bucket_key]["behavioral_events"] += s.get("behavioral_analysis", {}).get("total_events", 0)

        timeline = sorted(list(timeline_buckets.values()), key=lambda b: b["timestamp"])

        return {
            "time_window": time_window,
            "total_scans": total_scans,
            "benign_scans": benign_scans,
            "suspicious_scans": suspicious_scans,
            "malicious_scans": malicious_scans,
            "avg_threat_score": avg_threat,
            "highest_threat_score": highest_threat,
            "avg_behavioral_risk_score": avg_b_score,
            "high_risk_scan_count": high_risk_count,
            "critical_alert_count": crit_alerts,
            "timeline": timeline,
            "status": "Active",
            "message": None
        }

    @classmethod
    def assess_threat_risk(cls, scan_id: str) -> Dict[str, Any]:
        """
        Performs a full Threat Risk Assessment on a scan by correlating static EMBER ML evidence,
        behavioral telemetry indicators, historical scan occurrences, and active alert frequency.
        """
        scan = get_scan_by_id(scan_id)
        if not scan:
            raise ValueError(f"Scan with ID {scan_id} not found.")

        filename = scan.get("filename", "unknown")
        sha256 = scan.get("sha256", "")
        static_analysis = scan.get("static_analysis", {})
        ml_prediction = scan.get("ml_prediction", {})
        behavioral_analysis = scan.get("behavioral_analysis")

        # 1. Base scores
        static_score = static_analysis.get("threat_score") or ml_prediction.get("threat_score") or scan.get("threat_score", 0)
        static_class = ml_prediction.get("classification") or scan.get("classification", "BENIGN")

        b_score = None
        b_level = None
        b_indicators = []
        if behavioral_analysis:
            b_score = behavioral_analysis.get("behavioral_risk_score", behavioral_analysis.get("behavioral_score", 0))
            b_level = behavioral_analysis.get("behavioral_risk_level", "LOW")
            b_indicators = behavioral_analysis.get("behavioral_indicators", [])

        # 2. Unified Threat Risk Score Calculation
        if b_score is not None:
            threat_risk_score = int(round((0.5 * static_score) + (0.5 * b_score)))
        else:
            threat_risk_score = static_score

        # 3. Threat Risk Level Mapping
        if threat_risk_score >= 85:
            threat_risk_level = "CRITICAL"
            threat_classification = "MALICIOUS"
        elif threat_risk_score >= 70:
            threat_risk_level = "HIGH"
            threat_classification = "MALICIOUS"
        elif threat_risk_score >= 40:
            threat_risk_level = "MEDIUM"
            threat_classification = "SUSPICIOUS"
        else:
            threat_risk_level = "LOW"
            threat_classification = "BENIGN"

        # 4. File Risk History & Alerts Context
        file_history = cls.get_file_risk_history(sha256)
        all_alerts = get_alert_records(limit=200)
        matching_alerts = [a for a in all_alerts if a.get("scan_id") == scan_id or (sha256 and a.get("sha256") == sha256)]

        # 5. Determine Confidence Label based on evidence completeness
        has_static = bool(static_analysis and ml_prediction)
        has_behavioral = bool(behavioral_analysis and behavioral_analysis.get("total_events", 0) > 0)
        has_history = file_history["total_scans"] > 1

        if has_static and has_behavioral and has_history:
            confidence_label = "High Confidence Assessment (Static + Behavioral + Historical Evidence)"
        elif has_static and has_behavioral:
            confidence_label = "Moderate-to-High Confidence (Multi-Layer Static & Behavioral Verification)"
        elif has_static:
            confidence_label = "Preliminary Static Assessment (EMBER PE Feature Profile Only)"
        else:
            confidence_label = "Low Confidence Assessment (Limited Telemetry Available)"

        # 6. Generate Explainable Primary Risk Factors (Traceable to empirical data)
        primary_risk_factors: List[Dict[str, Any]] = []

        # Factor A: Static ML Detection
        if static_score >= 70:
            primary_risk_factors.append({
                "factor_id": "RF-STAT-001",
                "category": "Machine Learning Prediction",
                "severity": "high" if static_score < 85 else "critical",
                "title": "Elevated Static ML Structural Threat Score",
                "description": f"Grouped EMBER Random Forest model assigned a high threat score ({static_score}/100) based on PE header and section features.",
                "evidence_source": "static_pe"
            })
        elif static_score >= 40:
            primary_risk_factors.append({
                "factor_id": "RF-STAT-002",
                "category": "Machine Learning Prediction",
                "severity": "medium",
                "title": "Moderate Static Structural Anomalies Detected",
                "description": f"Static ML model detected suspicious binary characteristics (threat score: {static_score}/100).",
                "evidence_source": "static_pe"
            })

        # Factor B: High Shannon Entropy
        entropy = static_analysis.get("overall_entropy", 0.0)
        if entropy >= 7.0:
            primary_risk_factors.append({
                "factor_id": "RF-ENTR-001",
                "category": "Binary Characteristics",
                "severity": "high",
                "title": "High Shannon Entropy Indicative of Packing",
                "description": f"Overall file entropy measured at {entropy:.2f}/8.0, indicating possible encryption, compression, or packing mechanisms.",
                "evidence_source": "static_pe"
            })

        # Factor C: Suspicious Win32 APIs
        susp_apis_count = sum(len(v) for v in static_analysis.get("suspicious_apis", {}).values())
        if susp_apis_count >= 3:
            primary_risk_factors.append({
                "factor_id": "RF-API-001",
                "category": "Import Table Analysis",
                "severity": "medium",
                "title": "Presence of High-Risk Windows API Imports",
                "description": f"Binary imports {susp_apis_count} sensitive APIs across process manipulation, evasion, or networking categories.",
                "evidence_source": "static_pe"
            })

        # Factor D: Behavioral Risk Factors
        if b_score is not None and b_score > 0:
            if b_score >= 70:
                primary_risk_factors.append({
                    "factor_id": "RF-BEHAV-001",
                    "category": "Runtime Behavioral Telemetry",
                    "severity": "critical" if b_score >= 85 else "high",
                    "title": "Elevated Behavioral Risk Score",
                    "description": f"Runtime telemetry evaluation produced an elevated behavioral risk score of {b_score}/100.",
                    "evidence_source": "behavioral_telemetry"
                })
            elif b_score >= 40:
                primary_risk_factors.append({
                    "factor_id": "RF-BEHAV-002",
                    "category": "Runtime Behavioral Telemetry",
                    "severity": "medium",
                    "title": "Suspicious Runtime Activity Recorded",
                    "description": f"Runtime telemetry evaluation recorded suspicious behavioral activity (behavioral risk score: {b_score}/100).",
                    "evidence_source": "behavioral_telemetry"
                })
            else:
                primary_risk_factors.append({
                    "factor_id": "RF-BEHAV-003",
                    "category": "Runtime Behavioral Telemetry",
                    "severity": "low",
                    "title": "Low-Severity Runtime Activity Recorded",
                    "description": f"Runtime telemetry evaluation recorded minor behavioral activity (behavioral risk score: {b_score}/100).",
                    "evidence_source": "behavioral_telemetry"
                })

        for ind in b_indicators:
            primary_risk_factors.append({
                "factor_id": f"RF-{ind.get('indicator_id', 'IND')}",
                "category": ind.get("category", "Behavioral"),
                "severity": ind.get("severity", "high"),
                "title": ind.get("name", "Behavioral Indicator Observed"),
                "description": ind.get("description", "Suspicious runtime behavior recorded in telemetry."),
                "evidence_source": "behavioral_telemetry"
            })

        # Factor E: High Alert Frequency
        if len(matching_alerts) >= 2:
            primary_risk_factors.append({
                "factor_id": "RF-ALERT-001",
                "category": "SOC Alert Intelligence",
                "severity": "medium",
                "title": "Recurring Security Alert Frequency",
                "description": f"This sample or scan has generated {len(matching_alerts)} security alerts across detection pipelines.",
                "evidence_source": "alert_history"
            })

        # Factor F: Repeated Historical Detections
        if file_history["total_scans"] > 1:
            mal_history = sum(1 for c in file_history["classification_history"] if c in ["MALICIOUS", "SUSPICIOUS"])
            if mal_history > 1:
                primary_risk_factors.append({
                    "factor_id": "RF-HIST-001",
                    "category": "Historical Prevalence",
                    "severity": "high",
                    "title": "Persistent Threat Classification Across Re-Scans",
                    "description": f"File hash has been submitted {file_history['total_scans']} times and flagged suspicious/malicious in {mal_history} previous assessments.",
                    "evidence_source": "re_scan_frequency"
                })

        # Ensure at least one explainable baseline factor is present for clean/low-risk files
        if not primary_risk_factors:
            primary_risk_factors.append({
                "factor_id": "RF-BASE-001",
                "category": "Baseline Assessment",
                "severity": "low",
                "title": "Clean Static Structural Profile",
                "description": f"No high-entropy sections, suspicious API clusters, or anomalous PE characteristics detected (static threat score: {static_score}/100).",
                "evidence_source": "static_pe"
            })

        # 7. Actionable Recommendations grounded in evidence
        recommended_actions: List[str] = []
        if threat_risk_score >= 70:
            recommended_actions.append("Quarantine the affected binary and add its SHA-256 hash to endpoint protection blocklists.")
            if any(f["category"] == "Network Communications" for f in primary_risk_factors):
                recommended_actions.append("Block outbound traffic to flagged C2 IP addresses and audit firewall egress logs.")
            if any(f["category"] in ["Persistence & Auto-Start", "Registry & Configuration"] for f in primary_risk_factors):
                recommended_actions.append("Audit endpoint Registry Run/RunOnce keys and scheduled tasks for unauthorized auto-start entries.")
            if any(f["category"] in ["Privilege & Defense Evasion", "Process Activity"] for f in primary_risk_factors):
                recommended_actions.append("Perform memory dump analysis on parent and child process trees to check for active code injection.")
        elif threat_risk_score >= 40:
            recommended_actions.append("Submit binary for secondary tier-2 SOC sandbox evaluation and behavioral monitoring.")
            recommended_actions.append("Verify code signing authenticity with the software vendor.")
        else:
            recommended_actions.append("No immediate containment required. Continue baseline security monitoring.")

        # Supporting evidence summary
        supporting_evidence = {
            "file_size_kb": static_analysis.get("file_size_kb", 0),
            "is_pe": static_analysis.get("is_pe", False),
            "shannon_entropy": entropy,
            "suspicious_apis_count": susp_apis_count,
            "yara_rule_matches": len(static_analysis.get("indicators", [])),
            "behavioral_events_evaluated": behavioral_analysis.get("total_events", 0) if behavioral_analysis else 0,
            "mitre_techniques_mapped": len(b_indicators),
            "historical_scans_recorded": file_history["total_scans"],
            "alerts_linked": len(matching_alerts)
        }

        # Contextual trend
        trend_summary = {
            "file_risk_trajectory": file_history["risk_trajectory"],
            "first_scanned": file_history["first_seen"],
            "last_scanned": file_history["last_seen"],
            "prior_scores": file_history["threat_score_history"][:-1] if len(file_history["threat_score_history"]) > 1 else []
        }

        return {
            "scan_id": scan_id,
            "filename": filename,
            "sha256": sha256,
            "threat_risk_score": threat_risk_score,
            "threat_risk_level": threat_risk_level,
            "threat_classification": threat_classification,
            "confidence_label": confidence_label,
            "static_ml_score": static_score,
            "behavioral_risk_score": b_score,
            "primary_risk_factors": primary_risk_factors,
            "behavioral_indicators": b_indicators,
            "supporting_evidence": supporting_evidence,
            "historical_context": file_history,
            "trend": trend_summary,
            "recommended_actions": recommended_actions
        }


# Module-level function aliases for convenient access
get_file_risk_history = ThreatPredictionService.get_file_risk_history
analyze_threat_trends = ThreatPredictionService.analyze_threat_trends
assess_threat_risk = ThreatPredictionService.assess_threat_risk
