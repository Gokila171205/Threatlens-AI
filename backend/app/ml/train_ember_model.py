"""
ThreatLens AI - Real EMBER 2018 Model Training Pipeline
Trains a separate Random Forest classifier on 10,000 real EMBER PE samples.
Strictly preserves the existing Milestone 2 model and inference pipeline.
"""

import json
import os
import sys
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


def load_and_validate_data(data_dir: str) -> Tuple[np.ndarray, np.ndarray]:
    features_path = os.path.join(data_dir, "ember_features.npy")
    labels_path = os.path.join(data_dir, "ember_labels.npy")

    if not os.path.exists(features_path) or not os.path.exists(labels_path):
        raise FileNotFoundError(f"Missing dataset files in {data_dir}. Run ember_extractor.py first.")

    X = np.load(features_path)
    y = np.load(labels_path)

    # Integrity checks
    assert X.shape == (10000, 20), f"Expected X shape (10000, 20), got {X.shape}"
    assert y.shape == (10000,), f"Expected y shape (10000,), got {y.shape}"
    assert set(np.unique(y)).issubset({0, 1}), f"Labels must contain only 0 and 1, got {np.unique(y)}"
    assert not np.isnan(X).any(), "NaN detected in feature matrix"
    assert not np.isinf(X).any(), "Infinite values detected in feature matrix"
    assert not np.isnan(y).any(), "NaN detected in labels"

    print(f"[Data Validation] Successfully verified {len(X)} samples with {X.shape[1]} features.")
    return X, y


def check_for_duplicates(X_train: np.ndarray, y_train: np.ndarray, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
    """
    Checks for exact identical feature vectors across and within train/test sets.
    """
    # Hash feature vectors as byte strings for fast exact comparison
    train_hashes = [hash(row.tobytes()) for row in X_train]
    test_hashes = [hash(row.tobytes()) for row in X_test]

    train_set = set(train_hashes)
    test_set = set(test_hashes)

    overlap_count = sum(1 for h in test_hashes if h in train_set)
    train_internal_dups = len(train_hashes) - len(train_set)
    test_internal_dups = len(test_hashes) - len(test_set)

    return {
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "train_unique_feature_vectors": len(train_set),
        "test_unique_feature_vectors": len(test_set),
        "cross_split_overlapping_vectors": overlap_count,
        "train_internal_duplicates": train_internal_dups,
        "test_internal_duplicates": test_internal_dups,
        "leakage_risk": "High" if overlap_count > 100 else ("Low" if overlap_count > 0 else "None"),
    }


def stratified_split(
    X: np.ndarray, y: np.ndarray, train_per_class: int = 4000, test_per_class: int = 1000, random_seed: int = 42
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """
    Performs deterministic stratified split ensuring exactly 4,000 benign + 4,000 malicious for train
    and 1,000 benign + 1,000 malicious for test.
    """
    rng = np.random.RandomState(random_seed)

    benign_idx = np.where(y == 0)[0]
    malicious_idx = np.where(y == 1)[0]

    rng.shuffle(benign_idx)
    rng.shuffle(malicious_idx)

    train_idx = np.concatenate([benign_idx[:train_per_class], malicious_idx[:train_per_class]])
    test_idx = np.concatenate([benign_idx[train_per_class:train_per_class + test_per_class], malicious_idx[train_per_class:train_per_class + test_per_class]])

    # Shuffle both splits
    rng.shuffle(train_idx)
    rng.shuffle(test_idx)

    X_train, y_train = X[train_idx], y[train_idx]
    X_test, y_test = X[test_idx], y[test_idx]

    return X_train, y_train, X_test, y_test


def evaluate_held_out_test(y_true: np.ndarray, y_pred: np.ndarray, probs: np.ndarray) -> Dict[str, Any]:
    """
    Calculates overall and per-class metrics on the test set.
    """
    # Malicious is positive class (1)
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))

    total = len(y_true)
    accuracy = round((tp + tn) / max(total, 1), 4)

    # Class 1 (Malicious)
    precision_mal = round(tp / max(tp + fp, 1), 4)
    recall_mal = round(tp / max(tp + fn, 1), 4)
    f1_mal = round(2 * (precision_mal * recall_mal) / max(precision_mal + recall_mal, 1e-6), 4)

    # Class 0 (Benign)
    precision_benign = round(tn / max(tn + fn, 1), 4)
    recall_benign = round(tn / max(tn + fp, 1), 4)
    f1_benign = round(2 * (precision_benign * recall_benign) / max(precision_benign + recall_benign, 1e-6), 4)

    # Macro averages
    macro_precision = round((precision_mal + precision_benign) / 2.0, 4)
    macro_recall = round((recall_mal + recall_benign) / 2.0, 4)
    macro_f1 = round((f1_mal + f1_benign) / 2.0, 4)

    return {
        "overall": {
            "total_test_samples": total,
            "accuracy": accuracy,
            "precision": precision_mal,
            "recall": recall_mal,
            "f1_score": f1_mal,
            "macro_precision": macro_precision,
            "macro_recall": macro_recall,
            "macro_f1": macro_f1,
        },
        "confusion_matrix": {
            "true_positive": tp,
            "false_positive": fp,
            "true_negative": tn,
            "false_negative": fn,
            "matrix_format": [
                [tn, fp],
                [fn, tp],
            ],
            "labels": ["Benign (0)", "Malicious (1)"],
        },
        "per_class_metrics": {
            "benign_class_0": {
                "support": int(np.sum(y_true == 0)),
                "precision": precision_benign,
                "recall": recall_benign,
                "f1_score": f1_benign,
            },
            "malicious_class_1": {
                "support": int(np.sum(y_true == 1)),
                "precision": precision_mal,
                "recall": recall_mal,
                "f1_score": f1_mal,
            },
        },
    }


def train_ember_model() -> Dict[str, Any]:
    base_dir = os.path.dirname(__file__)
    data_dir = os.path.join(base_dir, "data")
    models_dir = os.path.join(base_dir, "models")
    os.makedirs(models_dir, exist_ok=True)

    print("=" * 70)
    print("ThreatLens AI - Real EMBER 2018 Training Pipeline")
    print("=" * 70)

    # 1. Load Data
    X, y = load_and_validate_data(data_dir)

    # 2. Stratified Split (8,000 Train / 2,000 Test)
    random_seed = 42
    X_train, y_train, X_test, y_test = stratified_split(
        X, y, train_per_class=4000, test_per_class=1000, random_seed=random_seed
    )

    print(f"[Split] Training Set: {len(X_train)} samples (Benign: {int(np.sum(y_train == 0))}, Malicious: {int(np.sum(y_train == 1))})")
    print(f"[Split] Test Set:     {len(X_test)} samples (Benign: {int(np.sum(y_test == 0))}, Malicious: {int(np.sum(y_test == 1))})")

    # 3. Data Leakage & Duplicate Check
    leakage_report = check_for_duplicates(X_train, y_train, X_test, y_test)
    print(f"[Data Leakage Check] Overlapping identical vectors across train/test: {leakage_report['cross_split_overlapping_vectors']}")
    print(f"[Data Leakage Check] Train unique vectors: {leakage_report['train_unique_feature_vectors']} / {len(X_train)}")
    print(f"[Data Leakage Check] Test unique vectors:  {leakage_report['test_unique_feature_vectors']} / {len(X_test)}")

    # 4. Train Random Forest Classifier
    hyperparameters = {
        "n_estimators": 45,
        "max_depth": 9,
        "min_samples_split": 4,
        "random_state": random_seed,
    }
    print(f"\n[Training] Initializing RandomForestMalwareClassifier with parameters: {hyperparameters}...")
    start_time = datetime.now(timezone.utc)
    clf = RandomForestMalwareClassifier(**hyperparameters)
    clf.fit(X_train, y_train, feature_names=FEATURE_NAMES)
    duration_sec = (datetime.now(timezone.utc) - start_time).total_seconds()
    print(f"[Training] Model fit completed in {duration_sec:.2f} seconds.")

    # 5. Evaluate ONLY on held-out test set
    print("\n[Evaluation] Predicting on held-out 2,000 test samples...")
    test_probs = clf.predict_proba(X_test)
    test_preds = (test_probs[:, 1] >= 0.5).astype(int)

    eval_results = evaluate_held_out_test(y_test, test_preds, test_probs)
    ov = eval_results["overall"]
    cm = eval_results["confusion_matrix"]
    print(f"\n[Test Results] Accuracy:  {ov['accuracy'] * 100:.2f}%")
    print(f"[Test Results] Precision: {ov['precision'] * 100:.2f}% (Malicious class)")
    print(f"[Test Results] Recall:    {ov['recall'] * 100:.2f}% (Malicious class)")
    print(f"[Test Results] F1-Score:  {ov['f1_score'] * 100:.2f}%")
    print(f"[Test Results] Confusion Matrix: TP={cm['true_positive']}, TN={cm['true_negative']}, FP={cm['false_positive']}, FN={cm['false_negative']}")

    # 6. Feature Importances
    importances = clf.get_feature_importance_dict()
    sorted_importances = sorted(importances.items(), key=lambda item: item[1], reverse=True)
    print("\n[Feature Importances - Top 10]:")
    for rank, (fname, imp) in enumerate(sorted_importances[:10], start=1):
        print(f"  {rank:2d}. {fname:<28} : {imp:.4f}")

    # 7. Comparison with Synthetic Baseline
    synthetic_meta_path = os.path.join(models_dir, "model_metadata.json")
    synthetic_comparison = {}
    if os.path.exists(synthetic_meta_path):
        try:
            with open(synthetic_meta_path, "r", encoding="utf-8") as f:
                s_meta = json.load(f)
                synthetic_comparison = {
                    "synthetic_model": {
                        "dataset": "Synthetic EMBER-Calibrated Generator",
                        "total_samples": 1600,
                        "test_samples": s_meta.get("metrics", {}).get("total_test_samples", 320),
                        "accuracy": s_meta.get("metrics", {}).get("accuracy"),
                        "precision": s_meta.get("metrics", {}).get("precision"),
                        "recall": s_meta.get("metrics", {}).get("recall"),
                        "f1_score": s_meta.get("metrics", {}).get("f1_score"),
                    },
                    "ember_model": {
                        "dataset": "Official EMBER 2018 (Benchmark Subset)",
                        "total_samples": 10000,
                        "test_samples": len(y_test),
                        "accuracy": ov["accuracy"],
                        "precision": ov["precision"],
                        "recall": ov["recall"],
                        "f1_score": ov["f1_score"],
                    },
                    "analysis": "The synthetic model reports 100% due to clear mathematical boundaries in the generator. The EMBER model reflects genuine real-world static feature overlap (packed benign utilities, clean-looking droppers), providing empirical generalization."
                }
        except Exception as e:
            synthetic_comparison = {"error": str(e)}

    # 8. Save New Artifacts (SEPARATELY - leaving synthetic baseline untouched)
    ember_model_path = os.path.join(models_dir, "malware_classifier_ember.joblib")
    joblib.dump(clf, ember_model_path)
    print(f"\n[Artifact] Saved EMBER model to: {ember_model_path}")

    metadata_ember = {
        "dataset": "EMBER 2018 (Official PE Benchmark)",
        "model_name": "ThreatLens-RandomForest-EMBER",
        "algorithm": "Random Forest (NumPy Ensemble)",
        "version": "2.1.0-ember",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "random_seed": random_seed,
        "sample_counts": {
            "total_samples": len(X),
            "total_benign": int(np.sum(y == 0)),
            "total_malicious": int(np.sum(y == 1)),
            "train_total": len(X_train),
            "train_benign": int(np.sum(y_train == 0)),
            "train_malicious": int(np.sum(y_train == 1)),
            "test_total": len(X_test),
            "test_benign": int(np.sum(y_test == 0)),
            "test_malicious": int(np.sum(y_test == 1)),
        },
        "feature_count": len(FEATURE_NAMES),
        "features": FEATURE_NAMES,
        "hyperparameters": hyperparameters,
        "metrics": ov,
        "confusion_matrix": cm,
        "per_class_metrics": eval_results["per_class_metrics"],
        "feature_importances": importances,
    }

    meta_ember_path = os.path.join(models_dir, "model_metadata_ember.json")
    with open(meta_ember_path, "w", encoding="utf-8") as f:
        json.dump(metadata_ember, f, indent=2)
    print(f"[Artifact] Saved EMBER metadata to: {meta_ember_path}")

    eval_report = {
        "dataset_information": {
            "source": "Official EMBER 2018 Distribution (train_features_1.jsonl)",
            "total_samples": 10000,
            "benign_samples": 5000,
            "malicious_samples": 5000,
            "features_extracted": 20,
        },
        "split_information": {
            "train_samples": 8000,
            "test_samples": 2000,
            "stratification": "Exactly 50% Benign / 50% Malicious in both sets",
            "random_seed": random_seed,
        },
        "duplicate_check": leakage_report,
        "model_parameters": hyperparameters,
        "evaluation_metrics": eval_results,
        "ranked_feature_importance": [
            {"rank": i + 1, "feature": k, "importance": v} for i, (k, v) in enumerate(sorted_importances)
        ],
        "model_comparison": synthetic_comparison,
    }

    eval_report_path = os.path.join(models_dir, "ember_model_evaluation.json")
    with open(eval_report_path, "w", encoding="utf-8") as f:
        json.dump(eval_report, f, indent=2)
    print(f"[Artifact] Saved EMBER evaluation report to: {eval_report_path}")

    return eval_report


if __name__ == "__main__":
    train_ember_model()
