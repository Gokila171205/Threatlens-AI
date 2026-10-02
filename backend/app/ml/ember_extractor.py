"""
ThreatLens AI - Official EMBER Dataset Stream Extractor
Streams parsed PE records line-by-line from official EMBER 2018 distribution,
distills the 20-feature ThreatLens tabular representation, and validates data integrity.
Zero host binary execution; streaming memory consumption < 50MB.
"""

import json
import os
import sys
import tarfile
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple
import httpx
import numpy as np

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from app.services.static_analysis import (
    SUSPICIOUS_API_CATEGORIES,
    SUSPICIOUS_SECTION_NAMES,
)

FEATURE_NAMES = [
    "file_size_kb",
    "is_pe",
    "num_sections",
    "max_section_entropy",
    "mean_section_entropy",
    "has_high_entropy_section",
    "num_suspicious_sections",
    "entrypoint_in_nontext",
    "virtual_size_ratio",
    "num_imports",
    "num_suspicious_imports",
    "has_injection_api",
    "has_keylogging_api",
    "has_network_api",
    "has_evasion_api",
    "has_persistence_api",
    "has_signature",
    "has_tls_callbacks",
    "suspicious_strings_count",
    "byte_entropy",
]

OFFICIAL_EMBER_URL = "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2"


class HTTPTarStream:
    """Provides a streaming read interface for tarfile over an HTTP response stream."""
    def __init__(self, response: httpx.Response, chunk_size: int = 65536):
        self.response = response
        self.iterator = response.iter_bytes(chunk_size=chunk_size)

    def read(self, size: int = -1) -> bytes:
        try:
            return next(self.iterator)
        except StopIteration:
            return b""


def extract_features_from_ember_record(record: Dict[str, Any]) -> Optional[List[float]]:
    """
    Transforms a single raw EMBER 2018 JSON record into the ThreatLens 20-feature vector.
    Returns None if the record is structurally malformed.
    """
    try:
        general = record.get("general", {})
        if not general or "size" not in general:
            return None

        # 0. file_size_kb
        size_bytes = float(general.get("size", 0))
        file_size_kb = round(size_bytes / 1024.0, 2)

        # 1. is_pe (all EMBER records are valid PE binaries)
        is_pe = 1.0

        # Section metrics
        section_data = record.get("section", {})
        sections = section_data.get("sections", []) if isinstance(section_data, dict) else []
        num_sections = float(len(sections))

        entropies = [float(s.get("entropy", 0.0)) for s in sections if isinstance(s, dict)]
        max_sec_entropy = max(entropies) if entropies else 0.0
        mean_sec_entropy = sum(entropies) / len(entropies) if entropies else 0.0
        has_high_ent = 1.0 if max_sec_entropy >= 7.1 else 0.0

        suspicious_sec_count = 0
        ratios = []
        for s in sections:
            if not isinstance(s, dict):
                continue
            name = str(s.get("name", "")).strip("\x00").lower()
            if any(susp in name for susp in SUSPICIOUS_SECTION_NAMES) or (s.get("entropy", 0.0) > 7.3 and s.get("size", 0) > 1024):
                suspicious_sec_count += 1
            raw_s = max(float(s.get("size", 0)), 1.0)
            virt_s = float(s.get("vsize", 0))
            ratios.append(virt_s / raw_s)

        num_suspicious_sections = float(suspicious_sec_count)
        virtual_size_ratio = min(max(ratios) if ratios else 1.0, 20.0)

        # Entry point anomaly
        entry_sec = str(section_data.get("entry", "")).lower() if isinstance(section_data, dict) else ""
        if entry_sec and entry_sec not in [".text", "code", "text", ".code"]:
            entrypoint_nontext = 1.0
        else:
            entrypoint_nontext = 0.0

        # Import analysis
        num_imports = float(general.get("imports", 0))
        imports_dict = record.get("imports", {})
        imported_funcs = set()
        if isinstance(imports_dict, dict):
            for lib, funcs in imports_dict.items():
                if isinstance(funcs, list):
                    for f in funcs:
                        if isinstance(f, str):
                            imported_funcs.add(f.lower())

        susp_imports = 0
        has_injection = 0.0
        has_keylogger = 0.0
        has_network = 0.0
        has_evasion = 0.0
        has_persistence = 0.0

        for func in imported_funcs:
            for cat, api_list in SUSPICIOUS_API_CATEGORIES.items():
                if any(target in func for target in api_list):
                    susp_imports += 1
                    if cat == "process_injection":
                        has_injection = 1.0
                    elif cat == "keylogging_spyware":
                        has_keylogger = 1.0
                    elif cat == "network_c2":
                        has_network = 1.0
                    elif cat == "evasion_anti_debug":
                        has_evasion = 1.0
                    elif cat == "persistence":
                        has_persistence = 1.0

        num_suspicious_imports = float(susp_imports)

        # Header characteristics
        has_sig = float(1 if general.get("has_signature", 0) else 0)
        has_tls = float(1 if general.get("has_tls", 0) else 0)

        # Strings proxy (documented EMBER URLs + registry keys count)
        strings_dict = record.get("strings", {})
        if isinstance(strings_dict, dict):
            urls_cnt = int(strings_dict.get("urls", 0) or 0)
            reg_cnt = int(strings_dict.get("registry", 0) or 0)
            suspicious_strings_count = float(urls_cnt + reg_cnt)
        else:
            suspicious_strings_count = 0.0

        # Overall byte entropy surrogate (weighted section entropy)
        total_sec_bytes = sum(max(float(s.get("size", 0)), 1.0) for s in sections if isinstance(s, dict))
        if total_sec_bytes > 0 and entropies:
            weighted_ent = sum(float(s.get("entropy", 0.0)) * max(float(s.get("size", 0)), 1.0) for s in sections if isinstance(s, dict)) / total_sec_bytes
            byte_entropy = min(max(round(weighted_ent, 4), 0.0), 8.0)
        else:
            byte_entropy = min(max(round(max_sec_entropy, 4), 0.0), 8.0)

        # Assemble exact 20-feature vector
        feature_vector = [
            file_size_kb,
            is_pe,
            num_sections,
            max_sec_entropy,
            mean_sec_entropy,
            has_high_ent,
            num_suspicious_sections,
            entrypoint_nontext,
            virtual_size_ratio,
            num_imports,
            num_suspicious_imports,
            has_injection,
            has_keylogger,
            has_network,
            has_evasion,
            has_persistence,
            has_sig,
            has_tls,
            suspicious_strings_count,
            byte_entropy,
        ]

        # Validation: check for NaN or Inf
        if any(np.isnan(v) or np.isinf(v) for v in feature_vector):
            return None

        return feature_vector

    except Exception:
        return None


def stream_ember_records(local_path: Optional[str] = None) -> Iterator[Tuple[Dict[str, Any], str]]:
    """
    Yields (parsed_json_dict, source_info) line-by-line.
    If local_path exists, reads from local file; otherwise streams from official Elastic tar.bz2.
    """
    if local_path and os.path.exists(local_path):
        print(f"[EMBER Extractor] Reading from local file: {local_path}")
        with open(local_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.strip():
                    try:
                        yield json.loads(line), f"local:{local_path}"
                    except Exception:
                        continue
        return

    print(f"[EMBER Extractor] Connecting to official stream: {OFFICIAL_EMBER_URL}")
    client = httpx.Client(follow_redirects=True, timeout=60.0)
    with client.stream("GET", OFFICIAL_EMBER_URL) as response:
        if response.status_code != 200:
            raise RuntimeError(f"HTTP {response.status_code} failed to connect to {OFFICIAL_EMBER_URL}")

        stream = HTTPTarStream(response)
        with tarfile.open(mode="r|bz2", fileobj=stream) as tar:
            for member in tar:
                if member.name.endswith(".jsonl") and "features" in member.name:
                    print(f"[EMBER Extractor] Unpacking member: {member.name} ({member.size / 1e6:.1f} MB)...")
                    f = tar.extractfile(member)
                    if not f:
                        continue
                    for line in f:
                        if line.strip():
                            try:
                                yield json.loads(line.decode("utf-8", errors="ignore")), f"official:{member.name}"
                            except Exception:
                                continue


def extract_ember_dataset(
    target_benign: int = 5000,
    target_malicious: int = 5000,
    local_path: Optional[str] = None,
    output_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Acquires and validates exactly target_benign and target_malicious samples.
    Saves ember_features.npy, ember_labels.npy, and ember_dataset_metadata.json.
    """
    if output_dir is None:
        output_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
    os.makedirs(output_dir, exist_ok=True)

    benign_features: List[List[float]] = []
    malicious_features: List[List[float]] = []

    total_processed = 0
    unlabeled_skipped = 0
    invalid_skipped = 0
    source_datasets_used = set()

    print(f"[EMBER Extractor] Starting stream extraction: target={target_benign} benign, {target_malicious} malicious...")

    for record, source_info in stream_ember_records(local_path):
        total_processed += 1
        source_datasets_used.add(source_info)

        raw_label = record.get("label", -1)
        if raw_label == -1 or raw_label is None:
            unlabeled_skipped += 1
            continue

        label = int(raw_label)
        if label not in (0, 1):
            invalid_skipped += 1
            continue

        # Check if this class is already full
        if label == 0 and len(benign_features) >= target_benign:
            continue
        if label == 1 and len(malicious_features) >= target_malicious:
            continue

        # Extract 20-feature vector
        feat_vector = extract_features_from_ember_record(record)
        if feat_vector is None or len(feat_vector) != 20:
            invalid_skipped += 1
            continue

        if label == 0:
            benign_features.append(feat_vector)
        else:
            malicious_features.append(feat_vector)

        # Progress log
        collected = len(benign_features) + len(malicious_features)
        if collected % 1000 == 0:
            print(f"  [Progress] Collected {collected}/10000 (Benign: {len(benign_features)}/{target_benign}, Malicious: {len(malicious_features)}/{target_malicious}) | Processed: {total_processed}")

        if len(benign_features) >= target_benign and len(malicious_features) >= target_malicious:
            print("[EMBER Extractor] Reached exact target: 5,000 benign and 5,000 malicious samples.")
            break

    # Build arrays
    X_benign = np.array(benign_features, dtype=np.float64)
    y_benign = np.zeros(len(benign_features), dtype=np.int64)

    X_mal = np.array(malicious_features, dtype=np.float64)
    y_mal = np.ones(len(malicious_features), dtype=np.int64)

    X = np.vstack([X_benign, X_mal])
    y = np.concatenate([y_benign, y_mal])

    # Shuffle synchronously with fixed seed for deterministic order
    rng = np.random.RandomState(42)
    indices = rng.permutation(len(y))
    X = X[indices]
    y = y[indices]

    # VALIDATION
    assert X.shape == (target_benign + target_malicious, 20), f"Invalid shape: {X.shape}"
    assert y.shape == (target_benign + target_malicious,), f"Invalid label shape: {y.shape}"
    assert not np.isnan(X).any(), "NaN detected in feature matrix!"
    assert not np.isinf(X).any(), "Inf detected in feature matrix!"
    assert int(np.sum(y == 0)) == target_benign, f"Mismatch benign count: {np.sum(y == 0)}"
    assert int(np.sum(y == 1)) == target_malicious, f"Mismatch malicious count: {np.sum(y == 1)}"

    # Compute per-feature statistics
    feature_stats = {}
    for i, name in enumerate(FEATURE_NAMES):
        vals = X[:, i]
        feature_stats[name] = {
            "min": round(float(np.min(vals)), 4),
            "max": round(float(np.max(vals)), 4),
            "mean": round(float(np.mean(vals)), 4),
            "std": round(float(np.std(vals)), 4),
        }

    # Save NumPy artifacts
    features_path = os.path.join(output_dir, "ember_features.npy")
    labels_path = os.path.join(output_dir, "ember_labels.npy")
    np.save(features_path, X)
    np.save(labels_path, y)
    print(f"[EMBER Extractor] Saved feature array: {features_path} ({os.path.getsize(features_path) / 1024:.1f} KB)")
    print(f"[EMBER Extractor] Saved labels array:  {labels_path} ({os.path.getsize(labels_path) / 1024:.1f} KB)")

    # Metadata
    metadata = {
        "source_dataset": list(source_datasets_used),
        "total_samples": len(y),
        "benign_count": int(np.sum(y == 0)),
        "malicious_count": int(np.sum(y == 1)),
        "feature_count": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "extraction_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_records_processed": total_processed,
        "unlabeled_records_skipped": unlabeled_skipped,
        "invalid_corrupt_records_skipped": invalid_skipped,
        "feature_statistics": feature_stats,
        "files": {
            "features_file": features_path,
            "labels_file": labels_path,
        }
    }

    metadata_path = os.path.join(output_dir, "ember_dataset_metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"[EMBER Extractor] Saved metadata: {metadata_path}")

    return metadata


if __name__ == "__main__":
    extract_ember_dataset()
