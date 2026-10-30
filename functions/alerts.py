def anomaly_detected(anomalies):
    """Print an alert when the analyzer returns one or more anomalies."""
    if anomalies is not None and not anomalies.empty:
        print("ALERT, ANOMALY DETECTED !", flush=True)