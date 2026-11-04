"""Minimal Meta Model API client for validating network alerts."""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from dotenv import load_dotenv

load_dotenv()


class MetaAIClient:
    """Ask Meta whether one aggregated network alert is meaningful."""

    def __init__(self):
        self.api_key = os.getenv("MODEL_API_KEY") or os.getenv("META_API_KEY")
        self.endpoint = os.getenv(
            "META_API_URL",
            "https://api.meta.ai/v1/chat/completions",
        )
        self.model = os.getenv("META_AI_MODEL", "muse-spark-1.3")
        self.max_calls = int(os.getenv("META_AI_MAX_CALLS_PER_DAY", "100"))
        self.usage_path = Path(
            os.getenv("META_AI_USAGE_PATH", "data/meta_ai_usage.json")
        )

    def analyze(self, alert):
        """Return a structured analysis, or ``None`` if the call is unavailable."""
        source_ip = alert.get("src_ip", "unknown")
        if not self.api_key:
            print(f"Meta AI skipped for {source_ip}: API key is missing.", flush=True)
            return None
        if not self._can_call():
            print(f"Meta AI skipped for {source_ip}: daily limit reached.", flush=True)
            return None

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Return exactly ONE JSON object and NOTHING else. "
                        "Do not reason aloud. Do not use Markdown. Use "
                        "exactly these keys: is_alert, danger_score, "
                        "severity, summary, action. Types: boolean, "
                        "integer 0-10, null or one of low/medium/high/"
                        "critical, string, string. Example: "
                        "{\"is_alert\":false,\"danger_score\":1,"
                        "\"severity\":null,\"summary\":\"Normal traffic\","
                        "\"action\":\"No action\"}. Analyze all "
                        "provided fields together. Known cloud, GitHub, "
                        "Microsoft or CDN ownership is not suspicious "
                        "alone. Mark true only for credible scanning, "
                        "exploitation, compromise or lateral movement. "
                        "For false, severity must be null and action must "
                        "be No action. Output the JSON immediately."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(alert, ensure_ascii=False),
                },
            ],
            "reasoning_effort": "minimal",
            "max_completion_tokens": 4096,
        }
        print(
            f"Meta AI request started for {source_ip}: "
            f"model={self.model}, payload_bytes={len(json.dumps(payload))}.",
            flush=True,
        )
        request = Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=15) as response:
                raw_body = response.read().decode("utf-8")
                print(
                    f"Meta AI response received for {source_ip}: "
                    f"http={response.status}, bytes={len(raw_body)}.",
                    flush=True,
                )
                body = json.loads(raw_body)
            self._record_call()
            result = self._parse(body)
            print(
                f"Meta AI parsed for {source_ip}: "
                f"is_alert={result['is_alert']}, severity={result['severity']}.",
                flush=True,
            )
            return result
        except HTTPError as error:
            details = error.read().decode("utf-8", errors="replace")
            print(
                f"Meta AI request failed for {source_ip} with HTTP "
                f"{error.code}: {details}",
                flush=True,
            )
        except (URLError, TimeoutError, ValueError, KeyError, TypeError) as error:
            print(
                f"Meta AI request failed for {source_ip}: "
                f"{type(error).__name__}: {error}.",
                flush=True,
            )
        return None

    def _can_call(self):
        usage = self._read_usage()
        return usage["calls"] < self.max_calls

    def _record_call(self):
        usage = self._read_usage()
        usage["calls"] += 1
        self.usage_path.parent.mkdir(parents=True, exist_ok=True)
        self.usage_path.write_text(json.dumps(usage), encoding="utf-8")

    def _read_usage(self):
        today = datetime.now(timezone.utc).date().isoformat()
        try:
            usage = json.loads(self.usage_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            usage = {}
        if usage.get("date") != today:
            return {"date": today, "calls": 0}
        return {"date": today, "calls": int(usage.get("calls", 0))}

    @staticmethod
    def _parse(body):
        choice = body["choices"][0]
        print(
            "Meta AI completion metadata: "
            f"finish_reason={choice.get('finish_reason')}, "
            f"response_keys={sorted(choice.keys())}.",
            flush=True,
        )
        message = choice.get("message", {})
        content = message.get("content") or message.get("reasoning_content")
        if isinstance(content, list):
            content = "".join(
                part.get("text", "") if isinstance(part, dict) else str(part)
                for part in content
            )
        if not content:
            raise ValueError(
                "Meta AI returned no text "
                f"(finish_reason={choice.get('finish_reason')}, "
                f"message_keys={sorted(message.keys())})"
            )
        text = str(content).strip()
        result = None
        for match in re.finditer(r"\{", text):
            try:
                candidate, _ = json.JSONDecoder().raw_decode(text[match.start():])
                if isinstance(candidate, dict):
                    result = candidate
                    break
            except json.JSONDecodeError:
                continue

        if result is None:
            return {
                "is_alert": False,
                "danger_score": 5,
                "severity": None,
                "summary": text[:120],
                "action": "No action",
            }

        is_alert = result.get("is_alert", result.get("alert", True))
        if isinstance(is_alert, str):
            is_alert = is_alert.lower() in {"true", "yes", "oui", "alert"}
        is_alert = bool(is_alert)
        severity = result.get("severity")
        if not is_alert:
            severity = None
        else:
            severity = str(severity or "medium").lower()
            if severity not in {"low", "medium", "high", "critical"}:
                severity = "medium"
        try:
            danger_score = int(float(result.get("danger_score", 5)))
        except (TypeError, ValueError):
            danger_score = 5
        return {
            "is_alert": is_alert,
            "danger_score": max(0, min(10, danger_score)),
            "severity": severity,
            "summary": str(result.get("summary", "Meta analysis received."))[:180],
            "action": str(result.get("action", "Check this activity."))[:140],
        }
