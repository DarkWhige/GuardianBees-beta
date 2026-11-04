"""Persistent storage for unresolved network alerts."""

import json
import os
from pathlib import Path
import threading


_lock = threading.Lock()


def _path():
    return Path(os.getenv("ACTIVE_ALERTS_PATH", "data/active_alerts.json"))


def _read():
    try:
        value = json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _write(alerts):
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(alerts, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def list_alerts():
    with _lock:
        alerts = _read()
        active = {
            source_ip: alert
            for source_ip, alert in alerts.items()
            if alert.get("is_alert", True) is not False
        }
        if active != alerts:
            _write(active)
        return list(active.values())


def get_alert(source_ip):
    with _lock:
        alert = _read().get(source_ip)
        return None if alert is not None and alert.get("is_alert") is False else alert


def save_alert(alert):
    source_ip = alert["src_ip"]
    with _lock:
        alerts = _read()
        alerts[source_ip] = alert
        _write(alerts)


def resolve_alert(source_ip):
    with _lock:
        alerts = _read()
        alert = alerts.pop(source_ip, None)
        if alert is None:
            return None
        _write(alerts)
        return alert
