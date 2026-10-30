from sklearn.ensemble import IsolationForest

FEATURES = [
    "requests",
    "n_ports",
    "n_dst",
    "n_proto",
    "bytes",
    "syn_requests",
    "outgoing_requests",
    "local_requests",
    "n_dns_queries",
]
FEATS = FEATURES


def validate_features(features):
    missing = set(FEATURES).difference(features.columns)
    if missing:
        raise ValueError(f"Missing analyzer features: {', '.join(sorted(missing))}")
    return features


def train(baseline):
    """Train a model from rows returned by ``agregator.aggregate``."""
    validate_features(baseline)
    model = IsolationForest(
        n_estimators=200,
        contamination=0.01,
        random_state=0,
    )
    model.fit(baseline[FEATURES])
    return model


def detect(model, features):
    """Score one or more aggregated traffic windows."""
    validate_features(features)
    output = features.copy()
    output["score"] = -model.score_samples(output[FEATURES])
    output["anomaly"] = model.predict(output[FEATURES]) == -1
    return output[output["anomaly"]].sort_values("score", ascending=False)
