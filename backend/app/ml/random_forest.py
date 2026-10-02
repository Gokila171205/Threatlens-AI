"""
ThreatLens AI - Pure NumPy Random Forest Classifier
Deterministic, high-performance ensemble tree classifier.
Independent of C-extension DLLs to guarantee 100% platform portability and security.
"""

import json
import math
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np


class DecisionNode:
    def __init__(
        self,
        feature_index: Optional[int] = None,
        threshold: Optional[float] = None,
        left: Optional["DecisionNode"] = None,
        right: Optional["DecisionNode"] = None,
        value: Optional[float] = None,
        impurity: float = 0.0,
        n_samples: int = 0,
    ):
        self.feature_index = feature_index
        self.threshold = threshold
        self.left = left
        self.right = right
        self.value = value  # Class probability P(y=1) if leaf
        self.impurity = impurity
        self.n_samples = n_samples

    @property
    def is_leaf(self) -> bool:
        return self.value is not None


class DecisionTreeClassifier:
    def __init__(
        self,
        max_depth: int = 10,
        min_samples_split: int = 2,
        min_samples_leaf: int = 1,
        max_features: Optional[int] = None,
        random_state: Optional[int] = None,
    ):
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.min_samples_leaf = min_samples_leaf
        self.max_features = max_features
        self.random_state = random_state
        self.root: Optional[DecisionNode] = None
        self.feature_importances_: Optional[np.ndarray] = None
        self._rng = np.random.RandomState(random_state)

    def _gini(self, y: np.ndarray) -> float:
        if len(y) == 0:
            return 0.0
        p1 = np.mean(y)
        return 2.0 * p1 * (1.0 - p1)

    def _best_split(
        self, X: np.ndarray, y: np.ndarray, feature_indices: np.ndarray
    ) -> Tuple[Optional[int], Optional[float], float]:
        best_gain = -1.0
        best_feat = None
        best_thresh = None
        n_samples = len(y)
        current_impurity = self._gini(y)

        for feat_idx in feature_indices:
            values = X[:, feat_idx]
            unique_vals = np.unique(values)
            if len(unique_vals) <= 1:
                continue

            # Evaluate split candidates at midpoints
            thresholds = (unique_vals[:-1] + unique_vals[1:]) / 2.0
            if len(thresholds) > 20:
                # Subsample quantiles for efficiency
                thresholds = np.quantile(unique_vals, np.linspace(0.05, 0.95, 20))

            for thresh in thresholds:
                left_mask = values <= thresh
                right_mask = ~left_mask

                n_left = np.sum(left_mask)
                n_right = n_samples - n_left

                if n_left < self.min_samples_leaf or n_right < self.min_samples_leaf:
                    continue

                impurity_left = self._gini(y[left_mask])
                impurity_right = self._gini(y[right_mask])
                weighted_impurity = (n_left * impurity_left + n_right * impurity_right) / n_samples
                gain = current_impurity - weighted_impurity

                if gain > best_gain:
                    best_gain = gain
                    best_feat = feat_idx
                    best_thresh = thresh

        return best_feat, best_thresh, max(best_gain, 0.0)

    def _build_tree(self, X: np.ndarray, y: np.ndarray, depth: int = 0) -> DecisionNode:
        n_samples, n_features = X.shape
        p1 = float(np.mean(y)) if n_samples > 0 else 0.0
        impurity = self._gini(y)

        # Stop criteria
        if (
            depth >= self.max_depth
            or n_samples < self.min_samples_split
            or impurity < 1e-7
            or np.all(y == y[0])
        ):
            return DecisionNode(value=p1, impurity=impurity, n_samples=n_samples)

        # Sample feature subset
        max_feat = self.max_features or int(math.sqrt(n_features))
        max_feat = max(1, min(max_feat, n_features))
        feature_indices = self._rng.choice(n_features, size=max_feat, replace=False)

        best_feat, best_thresh, gain = self._best_split(X, y, feature_indices)

        if best_feat is None or gain <= 1e-7:
            return DecisionNode(value=p1, impurity=impurity, n_samples=n_samples)

        # Track importance
        if self.feature_importances_ is not None:
            self.feature_importances_[best_feat] += gain * n_samples

        left_mask = X[:, best_feat] <= best_thresh
        right_mask = ~left_mask

        left_child = self._build_tree(X[left_mask], y[left_mask], depth + 1)
        right_child = self._build_tree(X[right_mask], y[right_mask], depth + 1)

        return DecisionNode(
            feature_index=best_feat,
            threshold=best_thresh,
            left=left_child,
            right=right_child,
            impurity=impurity,
            n_samples=n_samples,
        )

    def fit(self, X: np.ndarray, y: np.ndarray) -> "DecisionTreeClassifier":
        X = np.asarray(X, dtype=np.float64)
        y = np.asarray(y, dtype=np.float64)
        self.feature_importances_ = np.zeros(X.shape[1], dtype=np.float64)
        self.root = self._build_tree(X, y, depth=0)
        tot = np.sum(self.feature_importances_)
        if tot > 0:
            self.feature_importances_ /= tot
        return self

    def _predict_single(self, node: DecisionNode, x: np.ndarray) -> float:
        if node.is_leaf:
            return node.value or 0.0
        if x[node.feature_index] <= node.threshold:
            return self._predict_single(node.left, x)
        return self._predict_single(node.right, x)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        X = np.asarray(X, dtype=np.float64)
        if self.root is None:
            raise ValueError("Model is not fitted.")
        probs = np.array([self._predict_single(self.root, row) for row in X])
        return probs


class RandomForestMalwareClassifier:
    """
    Ensemble Random Forest for static malware classification.
    Produces calibrated threat probabilities and feature importances.
    """
    def __init__(
        self,
        n_estimators: int = 40,
        max_depth: int = 8,
        min_samples_split: int = 4,
        max_features: Optional[int] = None,
        random_state: int = 42,
    ):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.max_features = max_features
        self.random_state = random_state
        self.trees: List[DecisionTreeClassifier] = []
        self.feature_importances_: Optional[np.ndarray] = None
        self.feature_names: List[str] = []

    def fit(self, X: np.ndarray, y: np.ndarray, feature_names: Optional[List[str]] = None) -> "RandomForestMalwareClassifier":
        X = np.asarray(X, dtype=np.float64)
        y = np.asarray(y, dtype=np.float64)
        n_samples, n_features = X.shape
        self.feature_names = feature_names or [f"feat_{i}" for i in range(n_features)]
        self.trees = []
        importances = np.zeros(n_features, dtype=np.float64)

        rng = np.random.RandomState(self.random_state)

        for i in range(self.n_estimators):
            seed = rng.randint(0, 100000)
            # Bootstrap sample
            boot_indices = rng.choice(n_samples, size=n_samples, replace=True)
            X_b = X[boot_indices]
            y_b = y[boot_indices]

            tree = DecisionTreeClassifier(
                max_depth=self.max_depth,
                min_samples_split=self.min_samples_split,
                max_features=self.max_features,
                random_state=seed,
            )
            tree.fit(X_b, y_b)
            self.trees.append(tree)
            if tree.feature_importances_ is not None:
                importances += tree.feature_importances_

        tot = np.sum(importances)
        self.feature_importances_ = importances / tot if tot > 0 else importances
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Returns array of shape (N, 2): [P(benign), P(malicious)]."""
        X = np.asarray(X, dtype=np.float64)
        if len(X.shape) == 1:
            X = X.reshape(1, -1)
        if not self.trees:
            raise ValueError("Classifier is not fitted.")

        tree_preds = np.zeros((len(self.trees), len(X)))
        for idx, tree in enumerate(self.trees):
            tree_preds[idx] = tree.predict_proba(X)

        mean_malicious = np.mean(tree_preds, axis=0)
        # Clip to avoid pure 0 or 1
        mean_malicious = np.clip(mean_malicious, 0.01, 0.99)
        mean_benign = 1.0 - mean_malicious
        return np.column_stack([mean_benign, mean_malicious])

    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        probs = self.predict_proba(X)
        return (probs[:, 1] >= threshold).astype(int)

    def get_feature_importance_dict(self) -> Dict[str, float]:
        if self.feature_importances_ is None:
            return {}
        return {
            name: round(float(imp), 4)
            for name, imp in zip(self.feature_names, self.feature_importances_)
        }
