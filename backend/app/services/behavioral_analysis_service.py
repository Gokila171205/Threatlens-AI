"""
ThreatLens AI - Safe Behavioral Analysis Engine (Milestone 3, Step 4)
Telemetry-driven security analytics service. Analyzes runtime and security telemetry
into structured behavioral indicators, computes rule-based behavioral risk scores,
and correlates findings with static ML predictions into a unified Threat Risk Score.

Zero Host Execution Guarantee:
This service does NOT execute binaries or detonate files on the host system.
All operations evaluate pre-recorded or supplied telemetry as structured data.
"""

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

# Normalized Event Category Classification
EVENT_CATEGORY_MAP = {
    "process_creation": "Process Activity",
    "process_termination": "Process Activity",
    "suspicious_command": "Process Activity",
    "file_creation": "File System Activity",
    "file_modification": "File System Activity",
    "file_deletion": "File System Activity",
    "registry_modification": "Registry & Configuration",
    "service_creation": "Registry & Configuration",
    "network_connection": "Network Communications",
    "dns_request": "Network Communications",
    "persistence_attempt": "Persistence & Auto-Start",
    "privilege_escalation": "Privilege & Defense Evasion",
    "injection_attempt": "Privilege & Defense Evasion",
    "suspicious_api": "Privilege & Defense Evasion",
}

# Rule-Based Severity Point Weights
SEVERITY_WEIGHTS = {
    "low": 5,
    "medium": 15,
    "high": 25,
    "critical": 35,
}

# Analytical Behavioral Indicator Rules (Objective Non-Definitive Terminology)
BEHAVIORAL_INDICATOR_RULES = [
    {
        "indicator_id": "IND-PROC-001",
        "name": "Unusual Process Spawning Observed",
        "category": "Process Activity",
        "severity": "high",
        "mitre_id": "T1055",
        "condition": lambda ev: ev.get("event_type") == "process_creation" and any(
            bad in (ev.get("command") or "").lower() for bad in ["powershell -enc", "cmd.exe /c whoami", "vssadmin delete"]
        ),
        "description": "Detected behavioral indicator: Child process spawned under unexpected parameters or command flags requiring investigation."
    },
    {
        "indicator_id": "IND-PROC-002",
        "name": "Process Injection Indicator Observed",
        "category": "Privilege & Defense Evasion",
        "severity": "critical",
        "mitre_id": "T1055.012",
        "condition": lambda ev: ev.get("event_type") == "injection_attempt" or "hollowing" in (ev.get("description") or "").lower() or (ev.get("indicator") == "T1055.012"),
        "description": "Process injection indicator observed: Cross-process memory manipulation or process hollowing behavior recorded in telemetry."
    },
    {
        "indicator_id": "IND-PERS-001",
        "name": "Potential Persistence Behavior Observed",
        "category": "Persistence & Auto-Start",
        "severity": "high",
        "mitre_id": "T1547.001",
        "condition": lambda ev: ev.get("event_type") in ["persistence_attempt", "registry_modification"] and any(
            rk in (ev.get("target") or ev.get("description") or "").lower() for rk in ["currentversion\\run", "runonce", "startup"]
        ),
        "description": "Potential persistence behavior: Auto-start registry run key or scheduled startup modification observed."
    },
    {
        "indicator_id": "IND-NET-001",
        "name": "Suspicious Outbound Network Connection Observed",
        "category": "Network Communications",
        "severity": "high",
        "mitre_id": "T1071.001",
        "condition": lambda ev: ev.get("event_type") in ["network_connection", "dns_request"] and (
            ev.get("port") in [4444, 1337, 8888, 6667, 9001] or ev.get("severity") in ["high", "critical"]
        ),
        "description": "Suspicious outbound network connection observed contacting non-standard communication port or flagged C2 infrastructure."
    },
    {
        "indicator_id": "IND-FILE-001",
        "name": "High-Frequency File Modification Indicator",
        "category": "File System Activity",
        "severity": "critical",
        "mitre_id": "T1486",
        "condition": lambda ev: ev.get("event_type") == "file_modification" and (
            "encrypt" in (ev.get("description") or "").lower() or ev.get("severity") in ["high", "critical"]
        ),
        "description": "High-frequency file modification indicator observed: Rapid file state mutations or potential bulk data alteration observed."
    },
    {
        "indicator_id": "IND-EVAS-001",
        "name": "Potential Security Control Tampering",
        "category": "Privilege & Defense Evasion",
        "severity": "critical",
        "mitre_id": "T1562.001",
        "condition": lambda ev: any(
            kw in (ev.get("command") or ev.get("description") or "").lower() for kw in ["shadow copy", "vssadmin", "disable", "tamper", "antivirus"]
        ),
        "description": "Potential security control tampering observed: System recovery inhibition or telemetry suppression indicator detected."
    },
]


def convert_legacy_telemetry_to_events(scan_id: str, telemetry: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Converts legacy structured telemetry format into normalized BehavioralEvent records.
    Ensures 100% backward compatibility with existing telemetry ingest endpoints.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    events = []

    # 1. Process spawned processes
    for proc in telemetry.get("spawned_processes", []):
        events.append({
            "event_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "timestamp": now_iso,
            "event_type": "process_creation",
            "process_name": proc.get("process_name") or "cmd.exe",
            "parent_process": proc.get("parent_process") or "host.exe",
            "command": proc.get("command_line") or proc.get("command"),
            "severity": "medium" if "whoami" in str(proc) else "low",
            "description": f"Process creation observed: {proc.get('command_line') or proc.get('command')}",
            "metadata": proc
        })

    # 2. File modifications
    file_mods = telemetry.get("file_modifications", [])
    if len(file_mods) >= 10:
        events.append({
            "event_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "timestamp": now_iso,
            "event_type": "file_modification",
            "target": file_mods[0].get("path", "bulk_files") if file_mods else "files",
            "severity": "critical",
            "indicator": "T1486",
            "description": f"Bulk file modification observed across {len(file_mods)} paths within recorded telemetry window.",
            "metadata": {"count": len(file_mods)}
        })
    else:
        for f in file_mods:
            events.append({
                "event_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "timestamp": now_iso,
                "event_type": "file_modification",
                "target": f.get("path"),
                "severity": "medium",
                "description": f"File modification observed: {f.get('path')}",
                "metadata": f
            })

    # 3. Registry modifications
    for reg in telemetry.get("registry_modifications", []):
        key = reg.get("key", "")
        is_pers = "currentversion\\run" in key.lower() or "runonce" in key.lower()
        events.append({
            "event_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "timestamp": now_iso,
            "event_type": "persistence_attempt" if is_pers else "registry_modification",
            "target": key,
            "severity": "high" if is_pers else "low",
            "indicator": "T1547.001" if is_pers else None,
            "description": f"Registry configuration modification observed: {key}",
            "metadata": reg
        })

    # 4. Network traffic
    for net in telemetry.get("network_traffic", []):
        ip = net.get("destination_ip", "")
        port = net.get("port", 80)
        is_susp = port in [4444, 1337, 8888, 6667, 9001] or net.get("is_suspicious", False)
        events.append({
            "event_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "timestamp": now_iso,
            "event_type": "network_connection",
            "destination": ip,
            "port": port,
            "severity": "high" if is_susp else "low",
            "indicator": "T1071.001" if is_susp else None,
            "description": f"Outbound network socket connection observed to {ip}:{port}",
            "metadata": net
        })

    # 5. Generic tagged events
    for ev in telemetry.get("events", []):
        tag = ev.get("tag", "").upper()
        severity = "critical" if tag in ["PROCESS_HOLLOWING", "SHADOW_COPY_DELETION", "DEFENDER_TAMPERING", "FILE_ENCRYPTED"] else (
            "high" if tag in ["REGISTRY_RUN_KEY", "KEYLOGGER_HOOK", "SUSPICIOUS_C2_CONNECTION"] else "medium"
        )
        event_type = "injection_attempt" if tag == "PROCESS_HOLLOWING" else (
            "persistence_attempt" if tag == "REGISTRY_RUN_KEY" else "suspicious_command"
        )
        events.append({
            "event_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "timestamp": now_iso,
            "event_type": event_type,
            "severity": severity,
            "indicator": tag,
            "description": ev.get("description", f"Observed event with indicator {tag}"),
            "metadata": ev
        })

    return events


class BehavioralAnalysisEngine:
    """
    Evaluates behavioral events into normalized security indicators,
    calculates transparent behavioral risk scores, and derives recommended investigation steps.
    """

    @staticmethod
    def calculate_behavioral_risk_score(events: List[Dict[str, Any]], indicators: List[Dict[str, Any]]) -> int:
        """
        Calculates a rule-based behavioral risk score (0-100).
        Formula:
          Base Points = Sum of Event Severity Weights (with category saturation)
          Indicator Points = Sum of Detected Indicators (each 15-25 pts)
          Final Score = min(100, Base Points + Indicator Points)
        """
        if not events and not indicators:
            return 0

        # Severity accumulation
        severity_points = 0
        for ev in events:
            sev = ev.get("severity", "low").lower()
            severity_points += SEVERITY_WEIGHTS.get(sev, 5)

        # Indicator accumulation
        indicator_points = 0
        for ind in indicators:
            sev = ind.get("severity", "low").lower()
            if sev == "critical":
                indicator_points += 25
            elif sev == "high":
                indicator_points += 15
            elif sev == "medium":
                indicator_points += 10
            else:
                indicator_points += 5

        # Weighted calculation with saturation cap
        raw_score = int(round(0.4 * severity_points + 0.6 * indicator_points))
        return max(0, min(100, raw_score))

    @staticmethod
    def derive_risk_level(risk_score: int) -> str:
        """Maps risk score 0-100 into standard SOC risk level."""
        if risk_score >= 85:
            return "CRITICAL"
        elif risk_score >= 70:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        return "LOW"

    @classmethod
    def analyze_events(cls, scan_id: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Main analysis pipeline:
        1. Categorizes events
        2. Evaluates behavioral indicator rules
        3. Computes severity distribution and statistics
        4. Calculates behavioral risk score and level
        5. Synthesizes investigation recommendations
        """
        total_events = len(events)
        severity_counter = Counter(ev.get("severity", "low").lower() for ev in events)
        category_counter = Counter(EVENT_CATEGORY_MAP.get(ev.get("event_type", ""), "Other Activity") for ev in events)

        # Evaluate behavioral indicator rules
        detected_indicators: List[Dict[str, Any]] = []
        for rule in BEHAVIORAL_INDICATOR_RULES:
            matching_events = [ev for ev in events if rule["condition"](ev)]
            if matching_events:
                detected_indicators.append({
                    "indicator_id": rule["indicator_id"],
                    "name": rule["name"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "mitre_id": rule["mitre_id"],
                    "description": rule["description"],
                    "matched_events_count": len(matching_events),
                    "sample_match": matching_events[0].get("description", "")
                })

        suspicious_events = [ev for ev in events if ev.get("severity") in ["medium", "high", "critical"]]
        suspicious_events_count = len(suspicious_events)

        # Risk scoring
        b_risk_score = cls.calculate_behavioral_risk_score(events, detected_indicators)
        b_risk_level = cls.derive_risk_level(b_risk_score)
        b_classification = "MALICIOUS" if b_risk_score >= 70 else ("SUSPICIOUS" if b_risk_score >= 40 else "BENIGN")

        # Derive recommended investigation actions
        recommendations = []
        if any(ind["category"] == "Process Activity" for ind in detected_indicators):
            recommendations.append("Inspect memory space and handle tables of spawned child processes for injected code.")
        if any(ind["category"] == "Network Communications" for ind in detected_indicators):
            recommendations.append("Review firewall and DNS egress logs for communication attempts to destination IPs/domains.")
        if any(ind["category"] == "Persistence & Auto-Start" for ind in detected_indicators):
            recommendations.append("Audit startup folder and Registry Run/RunOnce keys for unauthorized persistence entries.")
        if any(ind["category"] == "File System Activity" for ind in detected_indicators):
            recommendations.append("Verify endpoint file system integrity and review recent file modifications for encryption patterns.")
        if not recommendations:
            recommendations.append("No immediate high-risk behavioral anomalies observed. Continue standard baseline monitoring.")

        # Summary narrative
        if b_risk_score >= 70:
            summary = f"High-risk behavioral activity observed: {len(detected_indicators)} suspicious indicator(s) identified across {total_events} recorded telemetry events."
        elif b_risk_score >= 40:
            summary = f"Moderate behavioral anomalies observed: {len(detected_indicators)} indicator(s) identified requiring SOC review."
        else:
            summary = f"Routine behavioral telemetry: {total_events} events evaluated with no high-severity indicators detected."

        # MITRE ATT&CK formatted techniques
        mitre_techniques = []
        for ind in detected_indicators:
            mitre_techniques.append({
                "technique_id": ind["mitre_id"],
                "technique_name": ind["name"],
                "tactic": ind["category"],
                "severity": ind["severity"],
                "details": ind["description"]
            })

        return {
            "behavioral_score": b_risk_score,
            "behavioral_risk_score": b_risk_score,
            "behavioral_risk_level": b_risk_level,
            "behavioral_classification": b_classification,
            "total_events": total_events,
            "suspicious_events_count": suspicious_events_count,
            "severity_distribution": dict(severity_counter),
            "behavior_categories": dict(category_counter),
            "behavioral_indicators": detected_indicators,
            "mitre_attack_techniques": mitre_techniques,
            "telemetry_summary": {
                "total_file_modifications": category_counter.get("File System Activity", 0),
                "total_registry_modifications": category_counter.get("Registry & Configuration", 0),
                "total_network_connections": category_counter.get("Network Communications", 0),
                "total_spawned_processes": category_counter.get("Process Activity", 0),
            },
            "behavior_summary": summary,
            "recommended_investigations": recommendations,
            "events": events
        }

    @staticmethod
    def correlate_with_static_prediction(
        static_score: int,
        static_classification: str,
        behavioral_report: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Fuses static EMBER prediction with behavioral analytics into a unified 'Threat Risk Score'.
        Formula:
          If behavioral telemetry is provided:
             Threat Risk Score = round(0.5 * static_score + 0.5 * behavioral_risk_score)
          If behavioral telemetry is not provided:
             Threat Risk Score = static_score
        """
        if behavioral_report is None or "behavioral_risk_score" not in behavioral_report:
            return {
                "final_threat_score": static_score,
                "threat_risk_score": static_score,
                "final_classification": static_classification,
                "fusion_mode": "STATIC_ONLY",
                "static_score": static_score,
                "behavioral_score": None,
                "static_weight": 1.0,
                "behavioral_weight": 0.0,
                "mitre_count": 0
            }

        b_score = behavioral_report.get("behavioral_risk_score", 0)
        w_static = 0.5
        w_behavioral = 0.5
        threat_risk_score = int(round((w_static * static_score) + (w_behavioral * b_score)))

        if threat_risk_score >= 70:
            final_class = "MALICIOUS"
        elif threat_risk_score >= 40:
            final_class = "SUSPICIOUS"
        else:
            final_class = "BENIGN"

        return {
            "final_threat_score": threat_risk_score,
            "threat_risk_score": threat_risk_score,
            "final_classification": final_class,
            "fusion_mode": "MULTI_LAYER_ENSEMBLE",
            "static_score": static_score,
            "behavioral_score": b_score,
            "static_weight": w_static,
            "behavioral_weight": w_behavioral,
            "mitre_count": len(behavioral_report.get("mitre_attack_techniques", []))
        }
