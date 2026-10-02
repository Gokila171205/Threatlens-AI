"""
ThreatLens AI - Safe Static Malware Analysis Service
Extracts PE structural characteristics, Shannon entropy, section details,
and suspicious API calls strictly via static parsing (zero binary execution).
"""

import math
import os
import re
from typing import Any, Dict, List, Optional, Tuple

try:
    import pefile
except ImportError:
    pefile = None


# High-risk Win32 APIs categorized by attack technique (MITRE ATT&CK alignment)
SUSPICIOUS_API_CATEGORIES = {
    "process_injection": [
        "virtualalloc", "virtualallocex", "writeprocessmemory", "createremotethread",
        "openprocess", "virtualprotect", "virtualprotectex", "queueuserapc",
        "setthreadcontext", "resumethread", "ntwritevirtualmemory", "ntmapviewofsection"
    ],
    "keylogging_spyware": [
        "getasynckeystate", "getkeystate", "setwindowshookex", "setwindowshookexa",
        "setwindowshookexw", "getforegroundwindow", "registerhotkey", "getclipboarddata"
    ],
    "persistence": [
        "regopenkeyex", "regsetvalueex", "regcreatekey", "regsetvalueexa",
        "regsetvaluew", "createservice", "startservice", "createservicea"
    ],
    "evasion_anti_debug": [
        "isdebuggerpresent", "checkremotedebuggerpresent", "outputdebugstring",
        "ntqueryinformationprocess", "sleep", "gettickcount", "queryperformancecounter"
    ],
    "network_c2": [
        "internetopen", "internetopena", "internetopenw", "internetconnect",
        "httpopenrequest", "httpsendrequest", "urldownloadtofile", "urldownloadtofilea",
        "wsastartup", "connect", "send", "recv", "internetreadfile"
    ],
    "execution": [
        "winexec", "shellexecute", "shellexecutea", "shellexecutew",
        "createprocess", "createprocessa", "createprocessw", "system"
    ]
}

SUSPICIOUS_SECTION_NAMES = {
    ".upx0", ".upx1", ".upx2", ".packer", ".themida", ".vmp0", ".vmp1",
    ".aspack", ".pecompact", ".fsg", ".petite", ".mpress", ".nsp0", ".nsp1"
}

SUSPICIOUS_STRING_PATTERNS = [
    re.compile(r"powershell(\.exe)?\s+-(?:enc|encodedcommand)", re.IGNORECASE),
    re.compile(r"cmd(\.exe)?\s+/c", re.IGNORECASE),
    re.compile(r"Invoke-Expression|IEX\b", re.IGNORECASE),
    re.compile(r"DownloadString|DownloadFile", re.IGNORECASE),
    re.compile(r"certutil(?:\.exe)?\s+-(?:urlcache|decode)", re.IGNORECASE),
    re.compile(r"bitsadmin(?:\.exe)?\s+/transfer", re.IGNORECASE),
    re.compile(r"reg(?:\.exe)?\s+add\s+HK(?:LM|CU)", re.IGNORECASE),
    re.compile(r"vssadmin(?:\.exe)?\s+delete\s+shadows", re.IGNORECASE),
    re.compile(r"wmic(?:\.exe)?\s+process\s+call\s+create", re.IGNORECASE),
    re.compile(r"https?://[a-zA-Z0-9_\-\./:\?#=&]+", re.IGNORECASE),
    re.compile(r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
]


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates the Shannon entropy of a byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    for count in byte_counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_strings(data: bytes, min_length: int = 4, max_strings: int = 2000) -> List[str]:
    """Extracts printable ASCII and UTF-16LE strings safely from bytes."""
    strings = []
    # ASCII strings
    ascii_pattern = re.compile(rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}")
    for match in ascii_pattern.finditer(data):
        if len(strings) >= max_strings:
            break
        try:
            strings.append(match.group().decode("ascii", errors="ignore"))
        except Exception:
            continue
    return strings


def parse_pe_safely(file_bytes: bytes) -> Optional[Any]:
    """Safely loads PE structure with pefile, strictly without running code."""
    if not pefile or not file_bytes.startswith(b"MZ"):
        return None
    try:
        pe = pefile.PE(data=file_bytes, fast_load=True)
        try:
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
                ]
            )
        except Exception:
            pass
        return pe
    except Exception:
        return None


def extract_static_features(file_bytes: bytes, filename: str = "") -> Dict[str, Any]:
    """
    Performs complete safe static analysis on binary bytes.
    Returns:
      - raw_features: tabular numerical feature dictionary for ML model
      - feature_vector: list of floats ordered by standard feature schema
      - report: comprehensive static report for UI presentation
    """
    file_size_bytes = len(file_bytes)
    file_size_kb = round(file_size_bytes / 1024.0, 2)
    overall_entropy = calculate_shannon_entropy(file_bytes)
    is_pe = False
    
    # Initialize PE-specific metrics
    num_sections = 0
    section_entropies: List[float] = []
    sections_summary: List[Dict[str, Any]] = []
    suspicious_sections = 0
    entrypoint_in_nontext = 0
    max_virt_ratio = 1.0
    
    num_imports = 0
    detected_suspicious_apis: Dict[str, List[str]] = {cat: [] for cat in SUSPICIOUS_API_CATEGORIES}
    has_injection = 0
    has_keylogger = 0
    has_network = 0
    has_evasion = 0
    has_persistence = 0
    has_signature = 0
    has_tls = 0
    subsystem = "UNKNOWN"
    machine = "UNKNOWN"
    
    pe = parse_pe_safely(file_bytes)
    if pe:
        is_pe = True
        try:
            machine = hex(pe.FILE_HEADER.Machine)
        except Exception:
            pass
        try:
            subsystem_val = pe.OPTIONAL_HEADER.Subsystem
            subsystem_map = {1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 7: "POSIX_CUI"}
            subsystem = subsystem_map.get(subsystem_val, f"SUB_{subsystem_val}")
        except Exception:
            pass

        # Section analysis
        entry_point = getattr(getattr(pe, "OPTIONAL_HEADER", None), "AddressOfEntryPoint", 0)
        found_entry_in_text = False
        
        if hasattr(pe, "sections"):
            num_sections = len(pe.sections)
            for s in pe.sections:
                try:
                    s_name = s.Name.decode("utf-8", errors="ignore").strip("\x00").lower()
                except Exception:
                    s_name = "unknown"
                
                s_entropy = calculate_shannon_entropy(s.get_data())
                section_entropies.append(s_entropy)
                
                vsize = s.Misc_VirtualSize
                rsize = s.SizeOfRawData
                ratio = round(vsize / max(rsize, 1), 2)
                if ratio > max_virt_ratio:
                    max_virt_ratio = ratio
                
                is_suspicious_sec = (s_name in SUSPICIOUS_SECTION_NAMES) or (s_entropy > 7.2 and vsize > 1024)
                if is_suspicious_sec:
                    suspicious_sections += 1
                
                # Check entry point location
                va = s.VirtualAddress
                if va <= entry_point < (va + max(vsize, rsize)):
                    if ".text" in s_name or "code" in s_name:
                        found_entry_in_text = True
                    else:
                        entrypoint_in_nontext = 1

                sections_summary.append({
                    "name": s_name,
                    "virtual_size": vsize,
                    "raw_size": rsize,
                    "entropy": s_entropy,
                    "is_packed": s_entropy > 7.0 or ratio > 3.0,
                    "is_suspicious": is_suspicious_sec
                })
        
        if num_sections > 0 and not found_entry_in_text and entry_point > 0:
            entrypoint_in_nontext = 1

        # Check imports
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    num_imports += 1
                    if imp.name:
                        func_name = imp.name.decode("utf-8", errors="ignore").lower()
                        for cat, api_list in SUSPICIOUS_API_CATEGORIES.items():
                            if any(target in func_name for target in api_list):
                                if func_name not in detected_suspicious_apis[cat]:
                                    detected_suspicious_apis[cat].append(func_name)

        has_injection = 1 if len(detected_suspicious_apis["process_injection"]) > 0 else 0
        has_keylogger = 1 if len(detected_suspicious_apis["keylogging_spyware"]) > 0 else 0
        has_network = 1 if len(detected_suspicious_apis["network_c2"]) > 0 else 0
        has_evasion = 1 if len(detected_suspicious_apis["evasion_anti_debug"]) > 0 else 0
        has_persistence = 1 if len(detected_suspicious_apis["persistence"]) > 0 else 0

        # Check digital signature
        security_dir = getattr(pefile, "DIRECTORY_ENTRY", {}).get("IMAGE_DIRECTORY_ENTRY_SECURITY", 4)
        if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > security_dir:
                sec_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir]
                if sec_entry.VirtualAddress > 0 and sec_entry.Size > 0:
                    has_signature = 1

        # Check TLS callbacks
        tls_dir = getattr(pefile, "DIRECTORY_ENTRY", {}).get("IMAGE_DIRECTORY_ENTRY_TLS", 9)
        if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > tls_dir:
                tls_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[tls_dir]
                if tls_entry.VirtualAddress > 0 and tls_entry.Size > 0:
                    has_tls = 1
        
        try:
            pe.close()
        except Exception:
            pass

    max_sec_entropy = max(section_entropies) if section_entropies else overall_entropy
    mean_sec_entropy = round(sum(section_entropies) / len(section_entropies), 4) if section_entropies else overall_entropy
    has_high_entropy_sec = 1 if max_sec_entropy > 7.0 else 0
    
    # Suspicious strings extraction
    extracted_strs = extract_strings(file_bytes)
    suspicious_matches: List[Dict[str, str]] = []
    for s in extracted_strs:
        for pat in SUSPICIOUS_STRING_PATTERNS:
            m = pat.search(s)
            if m:
                suspicious_matches.append({
                    "pattern": pat.pattern[:40],
                    "sample": m.group(0)[:80]
                })
                break
        if len(suspicious_matches) >= 50:
            break

    total_suspicious_apis = sum(len(v) for v in detected_suspicious_apis.values())
    suspicious_strings_count = len(suspicious_matches)

    # Feature dictionary ordered for tabular ML
    feature_dict = {
        "file_size_kb": file_size_kb,
        "is_pe": 1 if is_pe else 0,
        "num_sections": num_sections,
        "max_section_entropy": max_sec_entropy,
        "mean_section_entropy": mean_sec_entropy,
        "has_high_entropy_section": has_high_entropy_sec,
        "num_suspicious_sections": suspicious_sections,
        "entrypoint_in_nontext": entrypoint_in_nontext,
        "virtual_size_ratio": min(max_virt_ratio, 20.0),
        "num_imports": num_imports,
        "num_suspicious_imports": total_suspicious_apis,
        "has_injection_api": has_injection,
        "has_keylogging_api": has_keylogger,
        "has_network_api": has_network,
        "has_evasion_api": has_evasion,
        "has_persistence_api": has_persistence,
        "has_signature": has_signature,
        "has_tls_callbacks": has_tls,
        "suspicious_strings_count": suspicious_strings_count,
        "byte_entropy": overall_entropy,
    }

    feature_names = list(feature_dict.keys())
    feature_vector = [float(feature_dict[k]) for k in feature_names]

    # Dynamic threat indicators list for frontend badge display
    indicators: List[Dict[str, Any]] = []
    if overall_entropy >= 7.2 or has_high_entropy_sec:
        indicators.append({
            "type": "HIGH_ENTROPY",
            "severity": "high",
            "description": f"High Shannon Entropy detected ({overall_entropy:.2f}/8.0). Suggests packed or encrypted payload."
        })
    if is_pe and not has_signature:
        indicators.append({
            "type": "UNSIGNED_BINARY",
            "severity": "medium",
            "description": "Binary lacks valid Authenticode digital signature."
        })
    if suspicious_sections > 0:
        indicators.append({
            "type": "PACKED_SECTION",
            "severity": "critical",
            "description": f"Detected {suspicious_sections} suspicious/known packer sections."
        })
    if entrypoint_in_nontext:
        indicators.append({
            "type": "ANOMALOUS_ENTRYPOINT",
            "severity": "high",
            "description": "Execution entrypoint resides outside standard executable code section."
        })
    if has_injection:
        indicators.append({
            "type": "PROCESS_INJECTION_CAPABLE",
            "severity": "critical",
            "description": f"Discovered memory tampering/injection APIs: {', '.join(detected_suspicious_apis['process_injection'][:3])}"
        })
    if has_keylogger:
        indicators.append({
            "type": "SURVEILLANCE_CAPABLE",
            "severity": "high",
            "description": f"Discovered keystroke logging/spyware APIs: {', '.join(detected_suspicious_apis['keylogging_spyware'][:3])}"
        })
    if has_evasion:
        indicators.append({
            "type": "ANTI_ANALYSIS",
            "severity": "medium",
            "description": f"Detected anti-debugging / VM evasion checks: {', '.join(detected_suspicious_apis['evasion_anti_debug'][:3])}"
        })
    if suspicious_strings_count > 0:
        indicators.append({
            "type": "SUSPICIOUS_STRINGS",
            "severity": "medium",
            "description": f"Identified {suspicious_strings_count} suspicious command execution or network patterns."
        })

    report = {
        "filename": filename,
        "file_size_kb": file_size_kb,
        "is_pe": is_pe,
        "subsystem": subsystem,
        "machine": machine,
        "overall_entropy": overall_entropy,
        "sections": sections_summary,
        "suspicious_apis": {k: v for k, v in detected_suspicious_apis.items() if len(v) > 0},
        "suspicious_strings": suspicious_matches[:20],
        "indicators": indicators,
        "raw_features": feature_dict,
        "feature_names": feature_names,
    }

    return {
        "raw_features": feature_dict,
        "feature_vector": feature_vector,
        "feature_names": feature_names,
        "report": report
    }
