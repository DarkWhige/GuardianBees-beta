import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from functions.analyzer import FEATURES


DEFAULT_LOG_PATH = "data/traffic.jsonl"
RETENTION_DAYS = 30


def _log_path():
    return Path(os.getenv("TRAFFIC_LOG_PATH", DEFAULT_LOG_PATH))


def _parse_timestamp(value):
    timestamp = pd.to_datetime(value, utc=True, errors="coerce")
    if pd.isna(timestamp):
        raise ValueError(f"Invalid traffic timestamp: {value}")
    return timestamp.to_pydatetime()


def _prune(records, cutoff):
    return [
        record
        for record in records
        if _parse_timestamp(record["window_start"]) >= cutoff
    ]


def log_traffic(features, path=None, retention_days=RETENTION_DAYS):
    """Persist aggregated traffic and retain only the last ``retention_days``."""
    if features.empty:
        return

    missing = {"window_start", *FEATURES}.difference(features.columns)
    if missing:
        raise ValueError(f"Missing traffic fields: {', '.join(sorted(missing))}")

    log_file = Path(path) if path else _log_path()
    log_file.parent.mkdir(parents=True, exist_ok=True)

    records = []
    if log_file.exists():
        with log_file.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    records.append(json.loads(line))

    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    records = _prune(records, cutoff)
    records.extend(
        json.loads(features.to_json(orient="records", date_format="iso"))
    )

    with log_file.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")


def load_training_data(path=None, retention_days=RETENTION_DAYS):
    """Load retained aggregated traffic as an analyzer training DataFrame."""
    log_file = Path(path) if path else _log_path()
    if not log_file.exists():
        return pd.DataFrame(columns=["window_start", "src_ip", *FEATURES])

    records = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    with log_file.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                records.append(json.loads(line))

    records = _prune(records, cutoff)
    if not records:
        return pd.DataFrame(columns=["window_start", "src_ip", *FEATURES])

    training_data = pd.DataFrame.from_records(records)
    for feature in FEATURES:
        if feature not in training_data:
            training_data[feature] = 0
    return training_data