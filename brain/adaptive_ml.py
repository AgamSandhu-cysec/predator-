"""
brain/adaptive_ml.py

Online / incremental learning engine.

Design:
  - SGDClassifier(loss='log_loss') supports partial_fit() → true online learning.
  - StandardScaler.partial_fit() used for running mean/variance estimation.
  - Falls back to empty list when insufficient samples; caller uses rule-based order.
  - Model and scaler are persisted with joblib after every RETRAIN_EVERY updates.
  - On startup, detects SCHEMA_VERSION mismatch and discards stale models.
"""
import os
import json
import numpy as np
import joblib
from utils.logger import get_logger
logger = get_logger('AdaptiveML')
try:
    from sklearn.linear_model import SGDClassifier
    from sklearn.preprocessing import StandardScaler
    _SKLEARN = True
except ImportError:
    logger.warning('scikit-learn not installed — AdaptiveMLEngine will be disabled.')
    _SKLEARN = False
from brain.feature_schema import FEATURE_NAMES, LABEL_NAMES, ALL_CLASSES, FAILED_LABEL, SCHEMA_VERSION, N_FEATURES
_COUNTS_FILE = 'brain/models/update_count.json'

class AdaptiveMLEngine:
    """
    Incremental learning engine for exploit selection.

    Public API
    ----------
    update(feature_vec, exploit_name, success)   — call after every attempt
    predict(feature_vec) → list[dict]             — ranked recommendations
    retrain_from_history(feedback_logger)         — full retrain from DB
    get_update_count() → int
    """

    def __init__(self, config: dict):
        self.enabled = _SKLEARN and config.get('enabled', True)
        self.model_path = config.get('model_path', 'brain/models/adaptive_model.pkl')
        self.scaler_path = config.get('scaler_path', 'brain/models/scaler.pkl')
        self.min_samples = config.get('min_samples_for_ml', 5)
        self.retrain_every = config.get('retrain_every_n', 10)
        self.model = None
        self.scaler = None
        self._update_count = 0
        self._sample_buffer: list = []
        if self.enabled:
            self._load()

    def _load(self):
        """Load persisted model + scaler if schema version matches."""
        for path, attr in [(self.model_path, 'model'), (self.scaler_path, 'scaler')]:
            if os.path.exists(path):
                try:
                    obj = joblib.load(path)
                    setattr(self, attr, obj)
                except Exception as e:
                    logger.warning(f'Could not load {attr}: {e}. Starting fresh.')
        schema_file = self.model_path + '.schema'
        if self.model is not None and os.path.exists(schema_file):
            with open(schema_file) as f:
                saved_ver = json.load(f).get('version', 0)
            if saved_ver != SCHEMA_VERSION:
                logger.warning(f'Schema version mismatch (saved={saved_ver}, current={SCHEMA_VERSION}). Discarding stale model.')
                self.model = None
                self.scaler = None
        if os.path.exists(_COUNTS_FILE):
            with open(_COUNTS_FILE) as f:
                self._update_count = json.load(f).get('count', 0)
        if self.model:
            logger.info(f'Adaptive model loaded (updates={self._update_count}).')

    def _save(self):
        """Persist model + scaler."""
        if not self.enabled or self.model is None:
            return
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.scaler, self.scaler_path)
        with open(self.model_path + '.schema', 'w') as f:
            json.dump({'version': SCHEMA_VERSION}, f)
        with open(_COUNTS_FILE, 'w') as f:
            json.dump({'count': self._update_count}, f)
        logger.info(f'Model saved (updates={self._update_count}).')

    def update(self, feature_vec: list, exploit_name: str, success: bool) -> None:
        """
        Incremental update after one exploit attempt.

        Successful attempts teach the model to associate features with an exploit.
        Failed attempts add a negative example using the FAILED_LABEL pseudo-class.
        """
        if not self.enabled:
            return
        label = exploit_name if success else FAILED_LABEL
        self._sample_buffer.append((list(feature_vec), label))
        self._update_count += 1
        X = np.array([feature_vec], dtype=float)
        if self.scaler is None:
            self.scaler = StandardScaler()
            self.scaler.fit(X)
        else:
            self.scaler.partial_fit(X)
        X_scaled = self.scaler.transform(X)
        if self.model is None:
            self.model = SGDClassifier(loss='log_loss', max_iter=1, tol=None, random_state=42, n_jobs=-1, warm_start=True)
        if len(self._sample_buffer) >= self.min_samples:
            self.model.partial_fit(X_scaled, [label], classes=ALL_CLASSES)
        if self._update_count % self.retrain_every == 0:
            self._save()

    def predict(self, feature_vec: list) -> list:
        """
        Return ranked list of {"exploit": name, "confidence": float}.
        Returns [] if model is not ready (caller uses rule-based fallback).
        """
        if not self.enabled or self.model is None or self.scaler is None:
            return []
        if len(self._sample_buffer) < self.min_samples:
            return []
        X = np.array([feature_vec], dtype=float)
        try:
            X_scaled = self.scaler.transform(X)
            proba = self.model.predict_proba(X_scaled)[0]
            classes = list(self.model.classes_)
            ranked = sorted(zip(classes, proba), key=lambda x: -x[1])
            return [{'exploit': name, 'confidence': round(float(conf), 3), 'source': 'ml'} for name, conf in ranked if name != FAILED_LABEL and conf > 0.04]
        except Exception as e:
            logger.error(f'Prediction error: {e}')
            return []

    def retrain_from_history(self, feedback_logger) -> None:
        """
        Full mini-batch retrain from all historical data in the feedback DB.
        Called periodically (e.g. at startup or every N attempts).
        """
        if not self.enabled:
            return
        attempts = feedback_logger.get_recent_attempts(n=1000)
        if len(attempts) < self.min_samples:
            logger.info('Insufficient history for retrain.')
            return
        X_all, y_all = ([], [])
        for exploit_name, fv, success in attempts:
            if len(fv) != N_FEATURES:
                continue
            X_all.append(fv)
            y_all.append(exploit_name if success else FAILED_LABEL)
        if not X_all:
            return
        X_arr = np.array(X_all, dtype=float)
        if self.scaler is None:
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X_arr)
        else:
            self.scaler.partial_fit(X_arr)
            X_scaled = self.scaler.transform(X_arr)
        if self.model is None:
            self.model = SGDClassifier(loss='log_loss', max_iter=5, random_state=42, n_jobs=-1)
        self.model.partial_fit(X_scaled, y_all, classes=ALL_CLASSES)
        self._save()
        logger.info(f'Retrained on {len(X_all)} historical samples.')

    def get_update_count(self) -> int:
        return self._update_count

    def is_ready(self) -> bool:
        return self.enabled and self.model is not None and (len(self._sample_buffer) >= self.min_samples)
