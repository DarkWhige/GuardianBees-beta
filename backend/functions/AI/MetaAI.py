"""Minimal Meta Model API client for validating network alerts."""

import json
import os
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
        if not self.api_key or not self._can_call():
            return None

        request = Request(
            self.endpoint,
            data=json.dumps(
                {
                    "model": self.model,
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You are a network security expert. Determine "
                                "whether this alert is genuinely concerning. "
                                "Reply only with valid JSON containing exactly "
                                "these fields: is_alert (boolean), danger_score "
                                "(integer from 0 to 10), severity (low, medium, "
                                "high, or critical), summary (very short), and "
                                "action (one concrete action). Use only the "
                                "provided data."
                            ),
                        },
                        {
                            "role": "user",
                            "content": json.dumps(alert, ensure_ascii=False),
                        },
                    ],
                    "reasoning_effort": "minimal",
                    "max_completion_tokens": 512,
                }
            ).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=15) as response:
                body = json.loads(response.read().decode("utf-8"))
            self._record_call()
            return self._parse(body)
        except HTTPError as error:
            print(f"Meta AI request failed with HTTP {error.code}.", flush=True)
        except (URLError, TimeoutError, ValueError, KeyError, TypeError) as error:
            print(f"Meta AI request failed: {error}.", flush=True)
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
        content = choice["message"]["content"]
        if not content:
            raise ValueError(
                f"Meta AI returned no text (finish_reason={choice.get('finish_reason')})"
            )
        result = json.loads(content.strip().removeprefix("```json").removesuffix("```"))
        required = {"is_alert", "danger_score", "severity", "summary", "action"}
        if set(result) != required:
            raise ValueError("Meta AI returned an unexpected analysis format")
        if not isinstance(result["danger_score"], int) or not 0 <= result["danger_score"] <= 10:
            raise ValueError("danger_score must be an integer from 0 to 10")
        return result
