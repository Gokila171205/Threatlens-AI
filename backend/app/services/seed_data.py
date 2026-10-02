"""
ThreatLens AI - Seed Baseline Data for SOC Monitoring & Scans
Provides initial realistic scan history and alerts when the database is empty.
"""

from datetime import datetime, timedelta, timezone
from app.services.db import get_db, save_alert_record, save_scan_record


def seed_scans_and_alerts_if_empty():
    db = get_db()
    existing_scans = db.get("scans", [])
    if existing_scans and len(existing_scans) > 0:
        return

    existing_ids = {s.get("id") for s in existing_scans}
    now = datetime.now(timezone.utc)

    sample_scans = [
        {
            "id": "scan-demo-001",
            "filename": "svchost_updater.exe",
            "file_size_bytes": 1048576,
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "scanned_at": (now - timedelta(hours=2)).isoformat(),
            "status": "COMPLETED",
            "threat_score": 94,
            "classification": "MALICIOUS",
            "threat_level": "CRITICAL",
            "confidence": 0.98,
            "static_analysis": {
                "filename": "svchost_updater.exe",
                "file_size_kb": 1024.0,
                "is_pe": True,
                "subsystem": "WINDOWS_GUI",
                "machine": "0x8664",
                "overall_entropy": 7.72,
                "sections": [
                    {"name": ".upx0", "virtual_size": 320000, "raw_size": 0, "entropy": 0.0, "is_packed": True, "is_suspicious": True},
                    {"name": ".upx1", "virtual_size": 240000, "raw_size": 235000, "entropy": 7.85, "is_packed": True, "is_suspicious": True},
                    {"name": ".rsrc", "virtual_size": 4096, "raw_size": 2048, "entropy": 4.12, "is_packed": False, "is_suspicious": False}
                ],
                "suspicious_apis": {
                    "process_injection": ["virtualallocex", "writeprocessmemory", "createremotethread"],
                    "evasion_anti_debug": ["isdebuggerpresent"]
                },
                "suspicious_strings": [{"pattern": "powershell", "sample": "powershell.exe -enc AAAA..."}],
                "indicators": [
                    {"type": "PACKED_SECTION", "severity": "critical", "description": "Known UPX packed sections detected with entropy 7.85."},
                    {"type": "PROCESS_INJECTION_CAPABLE", "severity": "critical", "description": "Memory manipulation APIs discovered: virtualallocex, writeprocessmemory."},
                    {"type": "UNSIGNED_BINARY", "severity": "medium", "description": "Binary lacks valid digital signature."}
                ]
            },
            "ml_prediction": {
                "threat_score": 94,
                "classification": "MALICIOUS",
                "threat_level": "CRITICAL",
                "confidence": 0.98,
                "probabilities": {"benign": 0.02, "malicious": 0.98},
                "top_contributing_features": [
                    {"feature": "max_section_entropy", "value": 7.85, "importance": 0.251, "impact": 1.97},
                    {"feature": "has_high_entropy_section", "value": 1.0, "importance": 0.102, "impact": 0.102},
                    {"feature": "has_injection_api", "value": 1.0, "importance": 0.015, "impact": 0.015}
                ],
                "model_info": {"model_name": "ThreatLens-RandomForest-PE", "version": "2.0.0"}
            },
            "behavioral_analysis": {
                "behavioral_score": 90,
                "behavioral_classification": "MALICIOUS",
                "mitre_attack_techniques": [
                    {"technique_id": "T1055.012", "technique_name": "Process Hollowing", "tactic": "Defense Evasion", "severity": "critical", "details": "Injected code into legitimate svchost.exe"},
                    {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact", "tactic": "Impact", "severity": "critical", "details": "Attempted rapid file renaming and encryption"}
                ],
                "telemetry_summary": {"total_file_modifications": 42, "total_registry_modifications": 4, "total_network_connections": 1, "total_spawned_processes": 2}
            },
            "combined_verdict": {
                "final_threat_score": 92,
                "final_classification": "MALICIOUS",
                "fusion_mode": "MULTI_LAYER_ENSEMBLE",
                "static_score": 94,
                "behavioral_score": 90,
                "static_weight": 0.5,
                "behavioral_weight": 0.5
            },
            "mitre_techniques": [
                {"technique_id": "T1055.012", "technique_name": "Process Hollowing", "tactic": "Defense Evasion", "severity": "critical"},
                {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact", "tactic": "Impact", "severity": "critical"}
            ],
            "indicators": [
                {"type": "PACKED_SECTION", "severity": "critical", "description": "Known UPX packed sections detected with entropy 7.85."},
                {"type": "PROCESS_INJECTION_CAPABLE", "severity": "critical", "description": "Memory manipulation APIs discovered: virtualallocex, writeprocessmemory."}
            ]
        },
        {
            "id": "scan-demo-002",
            "filename": "invoice_march2026.pdf.exe",
            "file_size_bytes": 524288,
            "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
            "md5": "b10a8db164e0754105b7a99be72e3fe5",
            "scanned_at": (now - timedelta(hours=6)).isoformat(),
            "status": "COMPLETED",
            "threat_score": 86,
            "classification": "MALICIOUS",
            "threat_level": "HIGH",
            "confidence": 0.94,
            "static_analysis": {
                "filename": "invoice_march2026.pdf.exe",
                "file_size_kb": 512.0,
                "is_pe": True,
                "subsystem": "WINDOWS_GUI",
                "machine": "0x14c",
                "overall_entropy": 7.34,
                "sections": [
                    {"name": ".text", "virtual_size": 210000, "raw_size": 210000, "entropy": 7.42, "is_packed": True, "is_suspicious": False},
                    {"name": ".data", "virtual_size": 8000, "raw_size": 8192, "entropy": 3.8, "is_packed": False, "is_suspicious": False}
                ],
                "suspicious_apis": {
                    "keylogging_spyware": ["getasynckeystate", "setwindowshookex"],
                    "network_c2": ["urldownloadtofile", "connect"]
                },
                "suspicious_strings": [{"pattern": "http", "sample": "http://185.220.101.5/beacon"}],
                "indicators": [
                    {"type": "SURVEILLANCE_CAPABLE", "severity": "high", "description": "Keystroke interception APIs discovered: getasynckeystate."},
                    {"type": "HIGH_ENTROPY", "severity": "high", "description": "High Shannon Entropy (7.34/8.0)."},
                    {"type": "UNSIGNED_BINARY", "severity": "medium", "description": "Unsigned binary masquerading as PDF."}
                ]
            },
            "ml_prediction": {
                "threat_score": 86,
                "classification": "MALICIOUS",
                "threat_level": "HIGH",
                "confidence": 0.94,
                "probabilities": {"benign": 0.06, "malicious": 0.94},
                "top_contributing_features": [
                    {"feature": "max_section_entropy", "value": 7.42, "importance": 0.251, "impact": 1.86},
                    {"feature": "num_suspicious_imports", "value": 3.0, "importance": 0.071, "impact": 0.213}
                ],
                "model_info": {"model_name": "ThreatLens-RandomForest-PE", "version": "2.0.0"}
            },
            "behavioral_analysis": None,
            "combined_verdict": None,
            "mitre_techniques": [
                {"technique_id": "T1056.001", "technique_name": "Keylogging", "tactic": "Collection", "severity": "high"}
            ],
            "indicators": [
                {"type": "SURVEILLANCE_CAPABLE", "severity": "high", "description": "Keystroke interception APIs discovered: getasynckeystate."}
            ]
        },
        {
            "id": "scan-demo-003",
            "filename": "chrome_enterprise_setup.exe",
            "file_size_bytes": 4194304,
            "sha256": "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d",
            "md5": "c4ca4238a0b923820dcc509a6f75849b",
            "scanned_at": (now - timedelta(days=1)).isoformat(),
            "status": "COMPLETED",
            "threat_score": 8,
            "classification": "BENIGN",
            "threat_level": "LOW",
            "confidence": 0.99,
            "static_analysis": {
                "filename": "chrome_enterprise_setup.exe",
                "file_size_kb": 4096.0,
                "is_pe": True,
                "subsystem": "WINDOWS_GUI",
                "machine": "0x8664",
                "overall_entropy": 5.92,
                "sections": [
                    {"name": ".text", "virtual_size": 2500000, "raw_size": 2500000, "entropy": 6.12, "is_packed": False, "is_suspicious": False},
                    {"name": ".rdata", "virtual_size": 800000, "raw_size": 800000, "entropy": 5.4, "is_packed": False, "is_suspicious": False},
                    {"name": ".data", "virtual_size": 40000, "raw_size": 32000, "entropy": 3.2, "is_packed": False, "is_suspicious": False},
                    {"name": ".rsrc", "virtual_size": 120000, "raw_size": 120000, "entropy": 4.8, "is_packed": False, "is_suspicious": False}
                ],
                "suspicious_apis": {},
                "suspicious_strings": [],
                "indicators": []
            },
            "ml_prediction": {
                "threat_score": 8,
                "classification": "BENIGN",
                "threat_level": "LOW",
                "confidence": 0.99,
                "probabilities": {"benign": 0.99, "malicious": 0.01},
                "top_contributing_features": [],
                "model_info": {"model_name": "ThreatLens-RandomForest-PE", "version": "2.0.0"}
            },
            "behavioral_analysis": None,
            "combined_verdict": None,
            "mitre_techniques": [],
            "indicators": []
        },
        {
            "id": "scan-demo-004",
            "filename": "sysinternals_procmon.exe",
            "file_size_bytes": 2097152,
            "sha256": "a3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b899",
            "md5": "e2fc714c4727ee9395f324cd2e7f331f",
            "scanned_at": (now - timedelta(days=2)).isoformat(),
            "status": "COMPLETED",
            "threat_score": 14,
            "classification": "BENIGN",
            "threat_level": "LOW",
            "confidence": 0.95,
            "static_analysis": {
                "filename": "sysinternals_procmon.exe",
                "file_size_kb": 2048.0,
                "is_pe": True,
                "subsystem": "WINDOWS_GUI",
                "machine": "0x8664",
                "overall_entropy": 6.15,
                "sections": [
                    {"name": ".text", "virtual_size": 1500000, "raw_size": 1500000, "entropy": 6.25, "is_packed": False, "is_suspicious": False},
                    {"name": ".rdata", "virtual_size": 400000, "raw_size": 400000, "entropy": 5.1, "is_packed": False, "is_suspicious": False}
                ],
                "suspicious_apis": {},
                "suspicious_strings": [],
                "indicators": []
            },
            "ml_prediction": {
                "threat_score": 14,
                "classification": "BENIGN",
                "threat_level": "LOW",
                "confidence": 0.95,
                "probabilities": {"benign": 0.95, "malicious": 0.05},
                "top_contributing_features": [],
                "model_info": {"model_name": "ThreatLens-RandomForest-PE", "version": "2.0.0"}
            },
            "behavioral_analysis": None,
            "combined_verdict": None,
            "mitre_techniques": [],
            "indicators": []
        }
    ]

    for s in sample_scans:
        save_scan_record(s)

    # Seed corresponding alerts for the 2 malicious files
    save_alert_record({
        "id": "alert-demo-001",
        "scan_id": "scan-demo-001",
        "filename": "svchost_updater.exe",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "threat_score": 94,
        "threat_level": "CRITICAL",
        "classification": "MALICIOUS",
        "created_at": (now - timedelta(hours=2)).isoformat(),
        "status": "OPEN",
        "is_read": False,
        "title": "CRITICAL Risk Threat Detected: svchost_updater.exe",
        "description": "ML model classified sample as MALICIOUS with 98.0% confidence. Memory injection APIs and UPX packing detected.",
        "indicators_count": 3
    })

    save_alert_record({
        "id": "alert-demo-002",
        "scan_id": "scan-demo-002",
        "filename": "invoice_march2026.pdf.exe",
        "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        "threat_score": 86,
        "threat_level": "HIGH",
        "classification": "MALICIOUS",
        "created_at": (now - timedelta(hours=6)).isoformat(),
        "status": "OPEN",
        "is_read": False,
        "title": "HIGH Risk Threat Detected: invoice_march2026.pdf.exe",
        "description": "ML model classified sample as MALICIOUS with 94.0% confidence. Keystroke logging surveillance APIs present.",
        "indicators_count": 2
    })

    print("[ThreatLens AI] Seeding completed successfully.")
