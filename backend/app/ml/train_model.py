"""
ThreatLens AI - Model Training Pipeline
Generates calibrated static PE tabular training set, trains Random Forest Classifier,
evaluates performance metrics (Accuracy, Precision, Recall, F1, Confusion Matrix),
and serializes model artifacts to backend/app/ml/models/.
"""

import json
import os
import sys
from datetime import datetime, timezone
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


def generate_synthetic_pe_dataset(n_samples: int = 1200, random_state: int = 42) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generates realistic benign vs malicious PE static tabular dataset
    modeled after the EMBER and VirusShare benchmark distributions.
    """
    rng = np.random.RandomState(random_state)
    n_benign = n_samples // 2
    n_malicious = n_samples - n_benign

    # 1. Benign distribution
    benign_size = rng.lognormal(mean=6.5, sigma=1.2, size=n_benign)  # ~100KB to 5MB
    benign_is_pe = rng.choice([1, 1, 1, 1, 0], size=n_benign)  # mostly PE
    benign_num_sec = rng.choice([3, 4, 5, 6, 7], size=n_benign, p=[0.1, 0.4, 0.3, 0.15, 0.05])
    benign_max_entropy = rng.normal(loc=6.1, scale=0.45, size=n_benign).clip(3.5, 6.95)
    benign_mean_entropy = (benign_max_entropy - rng.uniform(0.5, 1.5, size=n_benign)).clip(2.0, 6.5)
    benign_high_ent_sec = np.zeros(n_benign, dtype=int)
    benign_susp_sec = np.zeros(n_benign, dtype=int)
    benign_entrypoint_nontext = rng.choice([0, 1], size=n_benign, p=[0.97, 0.03])
    benign_virt_ratio = rng.uniform(1.0, 1.4, size=n_benign)
    benign_num_imports = rng.randint(25, 250, size=n_benign)
    benign_susp_imports = rng.choice([0, 1, 2], size=n_benign, p=[0.85, 0.12, 0.03])
    benign_injection = np.zeros(n_benign, dtype=int)
    benign_keylogger = np.zeros(n_benign, dtype=int)
    benign_network = rng.choice([0, 1], size=n_benign, p=[0.8, 0.2])
    benign_evasion = rng.choice([0, 1], size=n_benign, p=[0.9, 0.1])
    benign_persistence = rng.choice([0, 1], size=n_benign, p=[0.88, 0.12])
    benign_signature = rng.choice([1, 0], size=n_benign, p=[0.78, 0.22])
    benign_tls = rng.choice([0, 1], size=n_benign, p=[0.92, 0.08])
    benign_susp_strings = rng.choice([0, 1, 2], size=n_benign, p=[0.88, 0.1, 0.02])
    benign_byte_entropy = (benign_max_entropy - rng.uniform(0.2, 0.8, size=n_benign)).clip(3.0, 6.8)

    X_benign = np.column_stack([
        benign_size, benign_is_pe, benign_num_sec, benign_max_entropy, benign_mean_entropy,
        benign_high_ent_sec, benign_susp_sec, benign_entrypoint_nontext, benign_virt_ratio,
        benign_num_imports, benign_susp_imports, benign_injection, benign_keylogger,
        benign_network, benign_evasion, benign_persistence, benign_signature,
        benign_tls, benign_susp_strings, benign_byte_entropy
    ])
    y_benign = np.zeros(n_benign, dtype=int)

    # 2. Malicious distribution (Trojans, Ransomware, Stealers, Droppers)
    mal_size = rng.lognormal(mean=5.8, sigma=1.5, size=n_malicious)
    mal_is_pe = rng.choice([1, 1, 1, 0], size=n_malicious)
    mal_num_sec = rng.choice([2, 3, 4, 5, 8], size=n_malicious, p=[0.2, 0.3, 0.25, 0.15, 0.1])
    mal_max_entropy = rng.normal(loc=7.4, scale=0.35, size=n_malicious).clip(6.8, 7.99)
    mal_mean_entropy = rng.normal(loc=6.8, scale=0.4, size=n_malicious).clip(5.5, 7.8)
    mal_high_ent_sec = (mal_max_entropy >= 7.1).astype(int)
    mal_susp_sec = rng.choice([0, 1, 2], size=n_malicious, p=[0.35, 0.5, 0.15])
    mal_entrypoint_nontext = rng.choice([0, 1], size=n_malicious, p=[0.45, 0.55])
    mal_virt_ratio = rng.choice([1.2, 3.5, 6.8, 12.0], size=n_malicious, p=[0.25, 0.4, 0.25, 0.1])
    mal_num_imports = rng.randint(2, 60, size=n_malicious)
    mal_susp_imports = rng.choice([1, 2, 3, 5, 8], size=n_malicious, p=[0.2, 0.3, 0.25, 0.15, 0.1])
    mal_injection = rng.choice([0, 1], size=n_malicious, p=[0.35, 0.65])
    mal_keylogger = rng.choice([0, 1], size=n_malicious, p=[0.65, 0.35])
    mal_network = rng.choice([0, 1], size=n_malicious, p=[0.3, 0.7])
    mal_evasion = rng.choice([0, 1], size=n_malicious, p=[0.25, 0.75])
    mal_persistence = rng.choice([0, 1], size=n_malicious, p=[0.4, 0.6])
    mal_signature = rng.choice([0, 1], size=n_malicious, p=[0.94, 0.06])
    mal_tls = rng.choice([0, 1], size=n_malicious, p=[0.6, 0.4])
    mal_susp_strings = rng.poisson(lam=4.0, size=n_malicious)
    mal_byte_entropy = rng.normal(loc=7.2, scale=0.4, size=n_malicious).clip(6.2, 7.99)

    X_mal = np.column_stack([
        mal_size, mal_is_pe, mal_num_sec, mal_max_entropy, mal_mean_entropy,
        mal_high_ent_sec, mal_susp_sec, mal_entrypoint_nontext, mal_virt_ratio,
        mal_num_imports, mal_susp_imports, mal_injection, mal_keylogger,
        mal_network, mal_evasion, mal_persistence, mal_signature,
        mal_tls, mal_susp_strings, mal_byte_entropy
    ])
    y_mal = np.ones(n_malicious, dtype=int)

    X = np.vstack([X_benign, X_mal])
    y = np.concatenate([y_benign, y_mal])

    # Shuffle
    shuffle_idx = rng.permutation(len(y))
    return X[shuffle_idx], y[shuffle_idx]


def evaluate_model(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, Any]:
    """Calculates Accuracy, Precision, Recall, F1, and Confusion Matrix."""
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))

    accuracy = round((tp + tn) / max(len(y_true), 1), 4)
    precision = round(tp / max(tp + fp, 1), 4)
    recall = round(tp / max(tp + fn, 1), 4)
    f1 = round(2 * (precision * recall) / max(precision + recall, 1e-6), 4)

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "confusion_matrix": {
            "true_positive": tp,
            "false_positive": fp,
            "true_negative": tn,
            "false_negative": fn,
        },
        "total_test_samples": len(y_true),
    }


def train_and_save_model() -> Dict[str, Any]:
    print("Generating calibrated EMBER-style PE tabular dataset...")
    X, y = generate_synthetic_pe_dataset(n_samples=1600, random_state=42)

    # 80/20 train/test split
    n_samples = len(X)
    n_train = int(n_samples * 0.8)
    X_train, X_test = X[:n_train], X[n_train:]
    y_train, y_test = y[:n_train], y[n_train:]

    print(f"Dataset split: {len(X_train)} train, {len(X_test)} test samples.")

    print("Training RandomForestMalwareClassifier...")
    clf = RandomForestMalwareClassifier(
        n_estimators=45,
        max_depth=9,
        min_samples_split=4,
        random_state=42,
    )
    clf.fit(X_train, y_train, feature_names=FEATURE_NAMES)

    # Predictions
    y_pred = clf.predict(X_test, threshold=0.5)
    metrics = evaluate_model(y_test, y_pred)
    importances = clf.get_feature_importance_dict()

    print(f"Training Complete:")
    print(f" - Accuracy:  {metrics['accuracy'] * 100:.2f}%")
    print(f" - Precision: {metrics['precision'] * 100:.2f}%")
    print(f" - Recall:    {metrics['recall'] * 100:.2f}%")
    print(f" - F1 Score:  {metrics['f1_score'] * 100:.2f}%")
    print(f" - Confusion Matrix: {metrics['confusion_matrix']}")

    # Save directory
    models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "models"))
    os.makedirs(models_dir, exist_ok=True)

    model_path = os.path.join(models_dir, "malware_classifier.joblib")
    joblib.dump(clf, model_path)
    print(f"Model serialized successfully to: {model_path}")

    metadata = {
        "model_name": "ThreatLens-RandomForest-PE",
        "algorithm": "Random Forest (NumPy Ensemble)",
        "version": "2.0.0",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "features": FEATURE_NAMES,
        "n_features": len(FEATURE_NAMES),
        "n_estimators": clf.n_estimators,
        "max_depth": clf.max_depth,
        "metrics": metrics,
        "feature_importances": importances,
    }

    metadata_path = os.path.join(models_dir, "model_metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"Model metadata saved to: {metadata_path}")

    return metadata


if __name__ == "__main__":
    train_and_save_model()
