import json


def anomaly_detected(anomalies):
    """Print the details of each anomalous traffic window."""
    if anomalies is None or anomalies.empty:
        return

    for record in json.loads(
        anomalies.to_json(orient="records", date_format="iso")
    ):
        source = record.get("src_ip", "unknown")
        window = record.get("window_start", "unknown")
        score = record.get("score")
        observed = {
            key: value
            for key, value in record.items()
            if key not in {"src_ip", "window_start", "score", "anomaly"}
        }
        alert = {
            "type": "network_anomaly",
            "message": "Traffic profile differs from the learned baseline",
            "source_ip": source,
            "window_start": window,
            "anomaly_score": score,
            "observed": observed,
        }
        print(f"ALERT {json.dumps(alert, separators=(',', ':'))}", flush=True)
