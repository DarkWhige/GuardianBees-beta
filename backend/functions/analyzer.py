from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading

import joblib
from sklearn.ensemble import IsolationForest

from functions.DataProcess.agregator import aggregate
from functions.alerts import anomaly_detected
from functions.DataProcess.features import FEATURES
from functions.logger import load_training_data, log_traffic
from functions.DataProcess.sniffer import run_sniffer
from functions.AI.MetaAI import MetaAIClient
from functions.ipOwnership import lookup as lookup_ip_owner
from functions.activeAlerts import (
    get_alert,
    list_alerts,
    resolve_alert,
    save_alert,
)

ALERT_SCORE_THRESHOLD = 65


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
        self._ai = MetaAIClient()
        self._last_window = []
        self._last_window_at = None

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

    def latest_window(self):
        with self._lock:
            return {
                "window_start": self._last_window_at,
                "records": list(self._last_window),
            }

    def active_alerts(self):
        return list_alerts()

    def resolve_alert(self, source_ip):
        return resolve_alert(source_ip)

    @property
    def model_path(self):
        with self._lock:
            return self._model_path

    def process_window(self, packets):
        features = aggregate(packets)
        if features.empty:
            with self._lock:
                self._last_window = []
                self._last_window_at = datetime.now(timezone.utc).isoformat()
            return

        log_traffic(features)
        with self._lock:
            model = self._model
        scored = features.copy()
        scored["anomaly"] = False
        alerts_by_ip = {}
        if model is not None:
            validate_features(features)
            scored["score"] = (
                (-model.score_samples(scored[FEATURES])) * 100
            ).clip(0, 100)
            scored["anomaly"] = scored["score"] >= ALERT_SCORE_THRESHOLD
            new_anomalies = scored[
                scored["anomaly"]
                & ~scored["src_ip"].map(lambda ip: get_alert(ip)).astype(bool)
            ]
            new_anomalies = (
                new_anomalies.sort_values("score", ascending=False)
                .drop_duplicates("src_ip")
            )
            if not new_anomalies.empty:
                new_anomalies = new_anomalies.copy()
                contexts = new_anomalies.apply(self._security_context, axis=1)
                new_anomalies["traffic_direction"] = contexts.map(
                    lambda context: context["traffic_direction"]
                )
                new_anomalies["threat_indicators"] = contexts.map(
                    lambda context: context["threat_indicators"]
                )
                new_anomalies["ip_owner"] = new_anomalies["src_ip"].map(
                    lookup_ip_owner
                )
                alerts = anomaly_detected(
                    new_anomalies.sort_values(
                        "score", ascending=False
                    ),
                    ai_client=self._ai,
                )
                alerts_by_ip = {
                    alert["source_ip"]: alert
                    for alert in alerts
                }

        records = []
        for record in json.loads(
            scored.to_json(orient="records", date_format="iso")
        ):
            alert = alerts_by_ip.get(record["src_ip"])
            if alert:
                analysis = alert.get("ai_analysis")
                if (
                    not alert.get("ai_skipped")
                    and (
                        alert.get("meta_error")
                        or analysis is None
                        or analysis.get("is_alert")
                    )
                ):
                    alert_record = self._alert_record(record, alert)
                    save_alert(alert_record)
                continue
            if get_alert(record["src_ip"]):
                continue
            analysis = alert.get("ai_analysis") if alert else None
            if alert and alert.get("meta_error"):
                status = "meta-error"
            elif analysis and analysis.get("is_alert"):
                status = "ai-alert"
            elif alert:
                status = "anomaly"
            else:
                status = "normal"
            records.append({
                **record,
                "status": status,
                "is_alert": bool(analysis and analysis.get("is_alert")),
                "danger_score_pct": round(record.get("score", 0), 1),
                "description": (
                    alert.get("message")
                    if alert
                    else "Traffic profile matches the usual behavior"
                ),
                "ip_owner": alert.get("ip_owner") if alert else None,
                "severity": analysis.get("severity") if analysis else None,
                "summary": analysis.get("summary") if analysis else None,
                "action": analysis.get("action") if analysis else None,
            })
        with self._lock:
            self._last_window = records
            self._last_window_at = datetime.now(timezone.utc).isoformat()

        print(features.to_json(orient="records", date_format="iso"), flush=True)

    @staticmethod
    def _alert_record(record, alert):
        analysis = alert.get("ai_analysis")
        status = (
            "meta-error"
            if alert.get("meta_error")
            else "ai-alert"
            if analysis and analysis.get("is_alert")
            else "anomaly"
        )
        return {
            **record,
            "status": status,
            "is_alert": (
                True
                if alert.get("meta_error")
                else bool(analysis and analysis.get("is_alert"))
            ),
            "danger_score_pct": round(record.get("score", 0), 1),
            "description": alert.get("message"),
            "ip_owner": alert.get("ip_owner", "Unknown organization"),
            "traffic_direction": alert.get("traffic_direction"),
            "threat_indicators": alert.get("threat_indicators", []),
            "severity": analysis.get("severity") if analysis else None,
            "summary": analysis.get("summary") if analysis else None,
            "action": analysis.get("action") if analysis else None,
        }

    @staticmethod
    def _security_context(record):
        requests = max(int(record.get("requests", 0)), 1)
        incoming = int(record.get("local_requests", 0))
        outgoing = int(record.get("outgoing_requests", 0))
        ports = {
            port.strip()
            for port in str(record.get("dst_ports", "")).split(",")
            if port.strip()
        }
        indicators = []
        if incoming and not outgoing:
            direction = "inbound"
        elif outgoing and not incoming:
            direction = "outbound"
        else:
            direction = "mixed"
        if incoming / requests >= 0.5:
            indicators.append("inbound traffic toward an internal machine")
        if int(record.get("n_ports", 0)) >= 5:
            indicators.append("scan across multiple ports")
        if int(record.get("n_dst", 0)) >= 4:
            indicators.append("communications with multiple destinations")
        if int(record.get("syn_requests", 0)) >= max(3, requests * 0.5):
            indicators.append("high number of SYN attempts")
        if int(record.get("n_dns_queries", 0)) >= 5:
            indicators.append("unusual DNS activity")
        if "22" in ports and int(record.get("syn_requests", 0)) >= 5:
            indicators.append("repeated SSH connections to the internal network")
        if ports.intersection({"3389", "445", "5985", "5986"}):
            indicators.append("sensitive administration port targeted")
        return {
            "traffic_direction": direction,
            "threat_indicators": indicators,
        }

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
