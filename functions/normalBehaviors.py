"""Persistent allow-list for behaviors confirmed as normal by the user."""

import json
import os
from pathlib import Path
import threading


_lock = threading.Lock()
_ignored_fields = {"window_start", "score", "anomaly"}


def _path():
    return Path(os.getenv("NORMAL_BEHAVIORS_PATH", "data/normal_behaviors.json"))


def _signature(alert):
    source_ip = alert.get("source_ip", alert.get("src_ip", "unknown"))
    observed = alert.get("observed")
    if observed is None:
        observed = {
            key: value
            for key, value in alert.items()
            if key not in _ignored_fields
            and key not in {"source_ip", "src_ip", "question"}
        }
    return {"source_ip": source_ip, "observed": observed}


def _read():
    try:
        value = json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return value if isinstance(value, list) else []


def is_normal_behavior(alert):
    """Return whether the user has already approved this behavior."""
    with _lock:
        return _signature(alert) in _read()


def add_normal_behavior(alert):
    """Persist a behavior so future matching alerts skip Meta analysis."""
    signature = _signature(alert)
    with _lock:
        behaviors = _read()
        if signature not in behaviors:
            behaviors.append(signature)
            path = _path()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(behaviors, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
    return signature


def list_normal_behaviors():
    """Return all user-approved behavior signatures."""
    with _lock:
        return _read()
