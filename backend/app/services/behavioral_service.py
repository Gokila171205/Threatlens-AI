"""
ThreatLens AI - Safe Behavioral Telemetry & Combined AI Prediction Service (Milestone 3)
Zero host binary execution guarantee: Decouples dynamic sandbox analysis via
a structured telemetry ingestion contract, MITRE ATT&CK behavior mapping,
and dynamic combined multi-layer threat score fusion.
"""

from typing import Any, Dict, List, Optional


MITRE_BEHAVIOR_MAPPINGS = {
    "FILE_ENCRYPTED": {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "severity": "critical",
        "risk_weight": 35
    },
    "SHADOW_COPY_DELETION": {
        "technique_id": "T1490",
        "technique_name": "Inhibit System Recovery",
        "tactic": "Impact",
        "severity": "critical",
        "risk_weight": 30
    },
    "REGISTRY_RUN_KEY": {
        "technique_id": "T1547.001",
        "technique_name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "severity": "high",
        "risk_weight": 20
    },
    "PROCESS_HOLLOWING": {
        "technique_id": "T1055.012",
        "technique_name": "Process Hollowing",
        "tactic": "Defense Evasion / Privilege Escalation",
        "severity": "critical",
        "risk_weight": 35
    },
    "KEYLOGGER_HOOK": {
        "technique_id": "T1056.001",
        "technique_name": "Keylogging",
        "tactic": "Credential Access / Collection",
        "severity": "high",
        "risk_weight": 25
    },
    "SUSPICIOUS_C2_CONNECTION": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "severity": "high",
        "risk_weight": 25
    },
    "COMMAND_LINE_SPOOFING": {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell Scripting",
        "tactic": "Execution",
        "severity": "medium",
        "risk_weight": 15
    },
    "DEFENDER_TAMPERING": {
        "technique_id": "T1562.001",
        "technique_name": "Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "severity": "critical",
        "risk_weight": 30
    },
    "SYSTEM_INFO_DISCOVERY": {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "Discovery",
        "severity": "low",
        "risk_weight": 5
    }
}


from app.services.behavioral_analysis_service import (
    BehavioralAnalysisEngine,
    convert_legacy_telemetry_to_events,
)


def analyze_behavioral_telemetry(telemetry: Dict[str, Any], scan_id: str = "scan-telemetry") -> Dict[str, Any]:
    """
    Evaluates sandbox telemetry events, maps MITRE ATT&CK techniques,
    and calculates behavioral threat score (0-100).
    Powered by BehavioralAnalysisEngine (Milestone 3, Step 4).
    """
    events = convert_legacy_telemetry_to_events(scan_id, telemetry)
    engine_report = BehavioralAnalysisEngine.analyze_events(scan_id, events)
    engine_report["raw_telemetry"] = telemetry
    return engine_report


def compute_combined_threat_score(
    static_score: int,
    static_classification: str,
    behavioral_result: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Fuses static ML prediction and behavioral sandbox telemetry into an ensemble verdict.
    Computes unified 'Threat Risk Score'.
    """
    return BehavioralAnalysisEngine.correlate_with_static_prediction(
        static_score=static_score,
        static_classification=static_classification,
        behavioral_report=behavioral_result
    )
