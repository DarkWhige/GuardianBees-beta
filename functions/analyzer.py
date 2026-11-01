from datetime import datetime, timezone
import os
from pathlib import Path
import threading

import joblib
from sklearn.ensemble import IsolationForest

from functions.agregator import aggregate
from functions.alerts import anomaly_detected
from functions.features import FEATURES
from functions.logger import load_training_data, log_traffic
from functions.sniffer import run_sniffer


def validate_features(features):
    missing = set(FEATURES).difference(features.columns)
    if missing:
        raise ValueError(f"Missing analyzer features: {', '.join(sorted(missing))}")
    return features


class AnalyzerRuntime:
    """Own the trained model and score captured traffic windows."""

    def __init__(self):
        self._model = None
        self._training_records = 0
        self._model_path = None
        self._lock = threading.Lock()
        self._stop_event = None
        self._sniffer = None

    def train(self):
        baseline = load_training_data()
        if len(baseline) < 2:
            raise ValueError(
                "At least two traffic records are required for training"
            )

        validate_features(baseline)
        model = IsolationForest(
            n_estimators=200,
            contamination=0.01,
            random_state=0,
        )
        model.fit(baseline[FEATURES])
        model_directory = Path(os.getenv("MODEL_DIR", "models"))
        model_directory.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
        model_path = model_directory / f"analyzer-{timestamp}.joblib"
        joblib.dump(model, model_path)
        with self._lock:
            self._model = model
            self._training_records = len(baseline)
            self._model_path = str(model_path)
        return self._training_records

    def status(self):
        with self._lock:
            return (
                self._model is not None,
                self._training_records,
                self._model_path,
            )

    @property
    def model_path(self):
        with self._lock:
            return self._model_path

    def process_window(self, packets):
        features = aggregate(packets)
        if features.empty:
            return

        log_traffic(features)
        with self._lock:
            model = self._model
        if model is not None:
            validate_features(features)
            scored = features.copy()
            scored["score"] = -model.score_samples(scored[FEATURES])
            scored["anomaly"] = model.predict(scored[FEATURES]) == -1
            anomaly_detected(
                scored[scored["anomaly"]].sort_values(
                    "score", ascending=False
                )
            )

        print(features.to_json(orient="records", date_format="iso"), flush=True)

    def start_sniffing(self):
        self._stop_event = threading.Event()
        self._sniffer = threading.Thread(
            target=run_sniffer,
            kwargs={
                "on_window": self.process_window,
                "stop_event": self._stop_event,
            },
            name="guardianbees-sniffer",
            daemon=True,
        )
        self._sniffer.start()

    def stop_sniffing(self):
        if self._stop_event is not None:
            self._stop_event.set()
        if self._sniffer is not None:
            self._sniffer.join(timeout=5)
