"""
ThreatLens AI - Malware Classifier Inference Service
Loads serialized Random Forest model and provides calibrated threat predictions,
threat levels, confidence scores, and feature impact attributions.
Supports configurable model selection with multi-tier resilient fallback.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional
import joblib
import numpy as np

from app.core.config import settings
from app.ml.random_forest import RandomForestMalwareClassifier

logger = logging.getLogger("threatlens.classifier")

MODEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../ml/models"))
DEFAULT_FALLBACK_MODEL = os.path.join(MODEL_DIR, "malware_classifier.joblib")
DEFAULT_FALLBACK_METADATA = os.path.join(MODEL_DIR, "model_metadata.json")


def resolve_model_path(path_str: str) -> str:
    """Resolves relative or absolute model and metadata file paths."""
    if os.path.isabs(path_str) and os.path.exists(path_str):
        return path_str
    backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    cand1 = os.path.join(backend_root, path_str)
    if os.path.exists(cand1):
        return cand1
    app_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    stripped = path_str
    if stripped.startswith("app/") or stripped.startswith("app\\"):
        stripped = stripped[4:]
    cand2 = os.path.join(app_root, stripped)
    if os.path.exists(cand2):
        return cand2
    basename = os.path.basename(path_str)
    cand3 = os.path.join(MODEL_DIR, basename)
    if os.path.exists(cand3):
        return cand3
    return cand1


class ClassifierService:
    _instance: Optional["ClassifierService"] = None

    def __init__(self):
        self.model: Optional[RandomForestMalwareClassifier] = None
        self.metadata: Dict[str, Any] = {}
        self.feature_names: List[str] = []
        self.active_model_name: str = "EMBER Grouped Random Forest"
        self.active_model_version: str = "ember-grouped-v1"
        self.active_model_type: str = "ember_grouped"
        self._load_model()

    @classmethod
    def get_instance(cls) -> "ClassifierService":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_model(self):
        primary_path = resolve_model_path(settings.threat_model_path)
        primary_metadata_path = resolve_model_path(settings.active_metadata_path)
        fallback_path = resolve_model_path(settings.fallback_model_path)
        fallback_metadata_path = DEFAULT_FALLBACK_METADATA

        loaded_primary = False

        # 1. Attempt loading the primary grouped EMBER model
        if os.path.exists(primary_path):
            try:
                self.model = joblib.load(primary_path)
                loaded_primary = True
                self.active_model_name = "EMBER Grouped Random Forest"
                self.active_model_version = "ember-grouped-v1"
                self.active_model_type = "ember_grouped"
                print(f"[ClassifierService] Successfully loaded primary grouped model: {primary_path}")
            except Exception as e:
                print(f"[ClassifierService] Warning: Failed to load primary model from {primary_path}: {e}")
                self.model = None

        if loaded_primary:
            if os.path.exists(primary_metadata_path):
                try:
                    with open(primary_metadata_path, "r", encoding="utf-8") as f:
                        self.metadata = json.load(f)
                    self.feature_names = self.metadata.get("feature_names") or self.metadata.get("features", [])
                    self.active_model_name = self.metadata.get("active_model_name", self.active_model_name)
                    self.active_model_version = self.metadata.get("model_version", self.active_model_version)
                except Exception as e:
                    print(f"[ClassifierService] Warning: Failed to load active metadata from {primary_metadata_path}: {e}")
            return

        # 2. Fallback to baseline synthetic model if primary failed or not found
        print(f"[ClassifierService] Primary model unavailable. Initiating fallback to baseline model: {fallback_path}")
        if os.path.exists(fallback_path):
            try:
                self.model = joblib.load(fallback_path)
                self.active_model_name = "ThreatLens-RandomForest-PE"
                self.active_model_version = "2.0.0"
                self.active_model_type = "baseline_fallback"
                print(f"[ClassifierService] Successfully loaded fallback baseline model: {fallback_path}")
            except Exception as e:
                print(f"[ClassifierService] Warning: Failed to load fallback model from {fallback_path}: {e}")
                self.model = None

        if os.path.exists(fallback_metadata_path):
            try:
                with open(fallback_metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
                self.feature_names = self.metadata.get("features", [])
                self.active_model_name = self.metadata.get("model_name", self.active_model_name)
                self.active_model_version = self.metadata.get("version", self.active_model_version)
            except Exception as e:
                print(f"[ClassifierService] Warning: Failed to load fallback metadata: {e}")

        # 3. If even fallback failed, set heuristic fallback details
        if self.model is None:
            print("[ClassifierService] Warning: No model file available. Operating in deterministic heuristic mode.")
            self.active_model_name = "ThreatLens-Heuristic-Fallback"
            self.active_model_version = "1.0.0"
            self.active_model_type = "heuristic_fallback"

    def predict(self, feature_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Takes raw static feature dict and returns calibrated threat classification.
        """
        # Fallback heuristic if model is missing
        if self.model is None or not self.feature_names:
            entropy = float(feature_dict.get("byte_entropy", 0.0))
            susp_apis = int(feature_dict.get("num_suspicious_imports", 0))
            susp_strings = int(feature_dict.get("suspicious_strings_count", 0))
            heuristic_score = min(int((entropy / 8.0) * 50 + susp_apis * 10 + susp_strings * 5), 100)
            return {
                "threat_score": heuristic_score,
                "classification": "MALICIOUS" if heuristic_score >= 70 else ("SUSPICIOUS" if heuristic_score >= 40 else "BENIGN"),
                "threat_level": "CRITICAL" if heuristic_score >= 85 else ("HIGH" if heuristic_score >= 70 else ("MEDIUM" if heuristic_score >= 40 else "LOW")),
                "confidence": 0.85,
                "probabilities": {"benign": round(1.0 - heuristic_score / 100.0, 4), "malicious": round(heuristic_score / 100.0, 4)},
                "top_contributing_features": [],
                "model_info": {
                    "model_name": self.active_model_name or "ThreatLens-Heuristic-Fallback",
                    "algorithm": "Rule Heuristics",
                    "version": self.active_model_version or "1.0.0",
                    "model_type": self.active_model_type or "heuristic_fallback",
                    "feature_count": len(self.feature_names) if self.feature_names else 20
                }
            }

        # Build feature vector in exact order
        vector = [float(feature_dict.get(k, 0.0)) for k in self.feature_names]
        X = np.array([vector], dtype=np.float64)

        probs = self.model.predict_proba(X)[0]  # [P(benign), P(malicious)]
        p_malicious = float(probs[1])
        p_benign = float(probs[0])

        # Calibrate threat score 0 - 100
        threat_score = int(round(p_malicious * 100))

        if threat_score >= 70:
            classification = "MALICIOUS"
            threat_level = "CRITICAL" if threat_score >= 85 else "HIGH"
        elif threat_score >= 40:
            classification = "SUSPICIOUS"
            threat_level = "MEDIUM"
        else:
            classification = "BENIGN"
            threat_level = "LOW"

        confidence = round(max(p_malicious, p_benign), 4)

        # Top contributing features
        importances = self.metadata.get("feature_importances", {})
        contributions = []
        for feat, val in feature_dict.items():
            imp = importances.get(feat, 0.0)
            if imp > 0.01 and val > 0:
                contributions.append({
                    "feature": feat,
                    "value": val,
                    "importance": round(imp, 4),
                    "impact": round(imp * min(val, 10.0), 3)
                })
        contributions.sort(key=lambda c: c["impact"], reverse=True)

        return {
            "threat_score": threat_score,
            "classification": classification,
            "threat_level": threat_level,
            "confidence": confidence,
            "probabilities": {
                "benign": round(p_benign, 4),
                "malicious": round(p_malicious, 4)
            },
            "top_contributing_features": contributions[:5],
            "model_info": {
                "model_name": self.active_model_name,
                "algorithm": self.metadata.get("algorithm", "Random Forest (NumPy Ensemble)"),
                "version": self.active_model_version,
                "model_type": self.active_model_type,
                "feature_count": len(self.feature_names),
            }
        }


classifier_service = ClassifierService.get_instance()
