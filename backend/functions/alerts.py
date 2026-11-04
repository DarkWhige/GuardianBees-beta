import json

from functions.normalBehaviors import is_normal_behavior


def anomaly_detected(anomalies, ai_client=None):
    """Print and return the details of each anomalous traffic window."""
    alerts = []
    if anomalies is None or anomalies.empty:
        return alerts

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
        indicators = record.get("threat_indicators", [])
        direction = record.get("traffic_direction", "unknown")
        alert = {
            "type": "network_anomaly",
            "message": (
                "Suspicious network behavior detected: "
                f"{', '.join(indicators)}"
                if indicators
                else "Traffic profile differs from the learned baseline"
            ),
            "source_ip": source,
            "window_start": window,
            "anomaly_score": score,
            "traffic_direction": direction,
            "ip_owner": record.get("ip_owner", "Unknown organization"),
            "threat_indicators": indicators,
            "observed": observed,
        }
        if is_normal_behavior(alert):
            alert["normal_behavior"] = True
            alert["ai_skipped"] = True
        elif ai_client is not None:
            ai_analysis = ai_client.analyze(record)
            if ai_analysis is not None:
                alert["ai_analysis"] = ai_analysis
            else:
                alert["meta_error"] = True
        alerts.append(alert)
        print(f"ALERT {json.dumps(alert, separators=(',', ':'))}", flush=True)
    return alerts
