"""
ThreatLens AI - Leakage-Resistant Grouped Evaluation (Step 2.5)
Identifies identical 20-feature vectors across the 10,000 EMBER samples,
creates a strictly disjoint Group-Stratified Train/Test split (0 feature overlap),
trains a separate grouped model, and evaluates true leakage-free generalization.
Zero modification to existing Milestone 2 models or pipelines.
"""

import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
import joblib
import numpy as np

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from app.ml.random_forest import RandomForestMalwareClassifier


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


def identify_feature_groups(X: np.ndarray, y: np.ndarray) -> Tuple[Dict[bytes, List[int]], Dict[str, Any]]:
    """
    Groups indices of identical 20-feature vectors.
    """
    groups: Dict[bytes, List[int]] = defaultdict(list)
    for idx in range(len(X)):
        # Exact byte representation of the float64 vector
        key = X[idx].tobytes()
        groups[key].append(idx)

    multi_sample_groups = {k: v for k, v in groups.items() if len(v) > 1}
    max_group_size = max(len(v) for v in groups.values())

    # Check for conflicting labels within identical feature vectors
    conflicting_label_groups = 0
    for indices in groups.values():
        labels = y[indices]
        if len(set(labels)) > 1:
            conflicting_label_groups += 1

    stats = {
        "total_samples": len(X),
        "total_unique_feature_groups": len(groups),
        "groups_with_multiple_samples": len(multi_sample_groups),
        "single_sample_groups": len(groups) - len(multi_sample_groups),
        "largest_group_size": max_group_size,
        "groups_with_conflicting_labels": conflicting_label_groups,
    }
    return groups, stats


def group_stratified_split(
    groups: Dict[bytes, List[int]],
    y: np.ndarray,
    target_test_fraction: float = 0.20,
    random_seed: int = 42,
) -> Tuple[List[int], List[int], Dict[str, Any]]:
    """
    Splits groups such that all instances of an identical feature vector
    are strictly contained in either Train OR Test, while preserving class balance.
    """
    rng = np.random.RandomState(random_seed)

    # Classify groups by their dominant label
    benign_groups = []
    malicious_groups = []
    mixed_groups = []

    for group_key, indices in groups.items():
        labels = y[indices]
        b_count = int(np.sum(labels == 0))
        m_count = int(np.sum(labels == 1))
        if b_count > 0 and m_count == 0:
            benign_groups.append((group_key, indices, b_count, 0))
        elif m_count > 0 and b_count == 0:
            malicious_groups.append((group_key, indices, 0, m_count))
        else:
            mixed_groups.append((group_key, indices, b_count, m_count))

    # Shuffle groups
    rng.shuffle(benign_groups)
    rng.shuffle(malicious_groups)
    rng.shuffle(mixed_groups)

    total_benign = sum(g[2] for g in benign_groups + mixed_groups)
    total_malicious = sum(g[3] for g in malicious_groups + mixed_groups)
    target_test_benign = int(total_benign * target_test_fraction)
    target_test_malicious = int(total_malicious * target_test_fraction)

    train_indices: List[int] = []
    test_indices: List[int] = []

    train_group_keys = set()
    test_group_keys = set()

    curr_test_b = 0
    curr_test_m = 0

    # 1. Distribute benign groups
    for g_key, idxs, b_cnt, m_cnt in benign_groups:
        if curr_test_b + b_cnt <= target_test_benign:
            test_indices.extend(idxs)
            test_group_keys.add(g_key)
            curr_test_b += b_cnt
        else:
            train_indices.extend(idxs)
            train_group_keys.add(g_key)

    # 2. Distribute malicious groups
    for g_key, idxs, b_cnt, m_cnt in malicious_groups:
        if curr_test_m + m_cnt <= target_test_malicious:
            test_indices.extend(idxs)
            test_group_keys.add(g_key)
            curr_test_m += m_cnt
        else:
            train_indices.extend(idxs)
            train_group_keys.add(g_key)

    # 3. Distribute mixed groups
    for g_key, idxs, b_cnt, m_cnt in mixed_groups:
        if (curr_test_b + b_cnt <= target_test_benign + 50) and (curr_test_m + m_cnt <= target_test_malicious + 50):
            test_indices.extend(idxs)
            test_group_keys.add(g_key)
            curr_test_b += b_cnt
            curr_test_m += m_cnt
        else:
            train_indices.extend(idxs)
            train_group_keys.add(g_key)

    # Validation: zero group overlap
    overlap = train_group_keys.intersection(test_group_keys)
    assert len(overlap) == 0, f"Critical error: {len(overlap)} groups cross train/test boundary!"

    split_meta = {
        "train_samples_total": len(train_indices),
        "test_samples_total": len(test_indices),
        "train_benign": int(np.sum(y[train_indices] == 0)),
        "train_malicious": int(np.sum(y[train_indices] == 1)),
        "test_benign": int(np.sum(y[test_indices] == 0)),
        "test_malicious": int(np.sum(y[test_indices] == 1)),
        "train_unique_groups": len(train_group_keys),
        "test_unique_groups": len(test_group_keys),
        "group_overlap_count": len(overlap),
    }

    return train_indices, test_indices, split_meta


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, Any]:
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))

    total = len(y_true)
    accuracy = round((tp + tn) / max(total, 1), 4)

    # Malicious
    p_mal = round(tp / max(tp + fp, 1), 4)
    r_mal = round(tp / max(tp + fn, 1), 4)
    f1_mal = round(2 * p_mal * r_mal / max(p_mal + r_mal, 1e-6), 4)

    # Benign
    p_ben = round(tn / max(tn + fn, 1), 4)
    r_ben = round(tn / max(tn + fp, 1), 4)
    f1_ben = round(2 * p_ben * r_ben / max(p_ben + r_ben, 1e-6), 4)

    return {
        "accuracy": accuracy,
        "malware_precision": p_mal,
        "malware_recall": r_mal,
        "malware_f1": f1_mal,
        "benign_precision": p_ben,
        "benign_recall": r_ben,
        "benign_f1": f1_ben,
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "confusion_matrix": [
            [tn, fp],
            [fn, tp],
        ],
    }


def run_grouped_evaluation():
    base_dir = os.path.dirname(__file__)
    data_dir = os.path.join(base_dir, "data")
    models_dir = os.path.join(base_dir, "models")

    features_path = os.path.join(data_dir, "ember_features.npy")
    labels_path = os.path.join(data_dir, "ember_labels.npy")

    if not os.path.exists(features_path) or not os.path.exists(labels_path):
        raise FileNotFoundError("Missing ember_features.npy or ember_labels.npy.")

    X = np.load(features_path)
    y = np.load(labels_path)

    print("=" * 75)
    print("ThreatLens AI - Leakage-Resistant Grouped Evaluation (Step 2.5)")
    print("=" * 75)

    # 1. Identify groups
    groups, group_stats = identify_feature_groups(X, y)
    print(f"[Group Analysis] Total samples: {group_stats['total_samples']}")
    print(f"[Group Analysis] Total unique feature groups: {group_stats['total_unique_feature_groups']}")
    print(f"[Group Analysis] Groups with multiple samples: {group_stats['groups_with_multiple_samples']}")
    print(f"[Group Analysis] Largest duplicate cluster size: {group_stats['largest_group_size']}")
    print(f"[Group Analysis] Groups with conflicting labels: {group_stats['groups_with_conflicting_labels']}")

    # 2. Perform Group-Stratified Split (0 Group Overlap)
    train_idx, test_idx, split_meta = group_stratified_split(groups, y, target_test_fraction=0.20, random_seed=42)

    X_train, y_train = X[train_idx], y[train_idx]
    X_test, y_test = X[test_idx], y[test_idx]

    print(f"\n[Grouped Split] Train Set: {len(X_train)} samples (Benign: {split_meta['train_benign']}, Malicious: {split_meta['train_malicious']})")
    print(f"[Grouped Split] Test Set:  {len(X_test)} samples (Benign: {split_meta['test_benign']}, Malicious: {split_meta['test_malicious']})")
    print(f"[Grouped Split] Group Overlap: {split_meta['group_overlap_count']} (Strictly 0)")

    # 3. Methodological Assessment of the Existing Model
    existing_model_path = os.path.join(models_dir, "malware_classifier_ember.joblib")
    legitimate_to_evaluate_existing = False
    existing_eval_on_new_test = None

    if os.path.exists(existing_model_path):
        print("\n[Methodological Assessment]")
        print(">> Question: Can the existing 'malware_classifier_ember.joblib' be legitimately evaluated on this grouped test set?")
        print(">> Answer: NO. The existing model was trained on the Step 2 80% partition, which contained samples belonging")
        print("   to groups that are now placed in this new test partition. Evaluating the existing model on this test set would")
        print("   STILL suffer from training memory on those groups. To achieve a valid, leakage-free evaluation,")
        print("   RETRAINING ON THE GROUPED TRAINING PARTITION IS REQUIRED.")

        # Compute for reporting only
        try:
            old_clf = joblib.load(existing_model_path)
            old_preds = (old_clf.predict_proba(X_test)[:, 1] >= 0.5).astype(int)
            existing_eval_on_new_test = compute_metrics(y_test, old_preds)
        except Exception:
            pass

    # 4. Train Separate Grouped Model
    hyperparameters = {
        "n_estimators": 45,
        "max_depth": 9,
        "min_samples_split": 4,
        "random_state": 42,
    }

    print(f"\n[Retraining Experiment] Training separate grouped model on {len(X_train)} leakage-free training samples...")
    start_t = datetime.now(timezone.utc)
    clf_grouped = RandomForestMalwareClassifier(**hyperparameters)
    clf_grouped.fit(X_train, y_train, feature_names=FEATURE_NAMES)
    training_duration_sec = (datetime.now(timezone.utc) - start_t).total_seconds()
    print(f"[Retraining Experiment] Completed in {training_duration_sec:.2f} seconds.")

    # 5. Evaluate Grouped Model on Held-out Grouped Test Set
    probs_grouped = clf_grouped.predict_proba(X_test)
    preds_grouped = (probs_grouped[:, 1] >= 0.5).astype(int)

    metrics_grouped = compute_metrics(y_test, preds_grouped)

    print("\n" + "=" * 50)
    print("ACTUAL MEASURED GROUPED EVALUATION RESULTS")
    print("=" * 50)
    print(f"Accuracy:           {metrics_grouped['accuracy'] * 100:.2f}%")
    print(f"Malware Precision:  {metrics_grouped['malware_precision'] * 100:.2f}%")
    print(f"Malware Recall:     {metrics_grouped['malware_recall'] * 100:.2f}%")
    print(f"Malware F1:         {metrics_grouped['malware_f1'] * 100:.2f}%")
    print(f"Benign Precision:   {metrics_grouped['benign_precision'] * 100:.2f}%")
    print(f"Benign Recall:      {metrics_grouped['benign_recall'] * 100:.2f}%")
    print(f"Benign F1:          {metrics_grouped['benign_f1'] * 100:.2f}%")
    print(f"Confusion Matrix:   TP={metrics_grouped['true_positives']}, TN={metrics_grouped['true_negatives']}, FP={metrics_grouped['false_positives']}, FN={metrics_grouped['false_negatives']}")
    print("=" * 50)

    # 6. Save Model Artifacts
    grouped_model_path = os.path.join(models_dir, "malware_classifier_ember_grouped.joblib")
    joblib.dump(clf_grouped, grouped_model_path)
    print(f"\n[Artifact] Saved separate grouped model: {grouped_model_path}")

    # Comparison data
    comparison = {
        "step_2_random_split": {
            "model": "malware_classifier_ember.joblib",
            "cross_split_overlapping_vectors": 436,
            "train_samples": 8000,
            "test_samples": 2000,
            "accuracy": 0.8720,
            "malware_precision": 0.9106,
            "malware_recall": 0.8250,
            "malware_f1": 0.8657,
        },
        "step_2_5_grouped_leakage_resistant_split": {
            "model": "malware_classifier_ember_grouped.joblib",
            "cross_split_overlapping_vectors": 0,
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "accuracy": metrics_grouped["accuracy"],
            "malware_precision": metrics_grouped["malware_precision"],
            "malware_recall": metrics_grouped["malware_recall"],
            "malware_f1": metrics_grouped["malware_f1"],
            "delta_accuracy": round(metrics_grouped["accuracy"] - 0.8720, 4),
            "delta_f1": round(metrics_grouped["malware_f1"] - 0.8657, 4),
        },
    }

    report_data = {
        "evaluation_type": "Group-Stratified Leakage-Resistant Evaluation",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "group_statistics": group_stats,
        "split_metadata": split_meta,
        "methodological_note": {
            "evaluated_existing_model_directly": False,
            "reason": "Existing model was trained with samples from groups now in test set; retraining on grouped train partition was required for true leakage-free evaluation.",
            "retrained_model": "malware_classifier_ember_grouped.joblib",
            "training_duration_seconds": training_duration_sec,
        },
        "hyperparameters": hyperparameters,
        "metrics": metrics_grouped,
        "model_comparison": comparison,
    }

    report_path = os.path.join(models_dir, "ember_grouped_evaluation.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    print(f"[Artifact] Saved evaluation report: {report_path}")

    return report_data


if __name__ == "__main__":
    run_grouped_evaluation()
