from functions.agregator import aggregate
from functions.alerts import anomaly_detected
from functions.analyzer import detect, train
from functions.logger import load_training_data, log_traffic
from functions.sniffer import run_sniffer


def process_window(packets):
    features = aggregate(packets)
    if features.empty:
        return

    baseline = load_training_data()
    if len(baseline) >= 2:
        model = train(baseline)
        anomaly_detected(detect(model, features))

    log_traffic(features)
    print(features.to_json(orient="records", date_format="iso"), flush=True)


if __name__ == "__main__":
    run_sniffer(on_window=process_window)