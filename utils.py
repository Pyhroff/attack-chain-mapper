"""Shared utility helpers."""

import json
import logging
import time
from collections.abc import Callable
from functools import wraps
from pathlib import Path

import config


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        return json.dumps(payload, ensure_ascii=True)


def setup_logging(verbose: bool = False, log_format: str = "text") -> None:
    level = logging.DEBUG if verbose else logging.INFO
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    handler = logging.StreamHandler()
    if log_format == "json":
        handler.setFormatter(JsonLogFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    root.addHandler(handler)


def apply_runtime_profile(profile: str) -> dict:
    selected = config.RUNTIME_PROFILES.get(profile, config.RUNTIME_PROFILES[config.DEFAULT_RUNTIME_PROFILE])
    config.REQUEST_TIMEOUT_SECONDS = selected["timeout_seconds"]
    config.RETRY_ATTEMPTS = selected["retry_attempts"]
    config.RETRY_BACKOFF_SECONDS = selected["retry_backoff_seconds"]
    return selected


def apply_config_file_overrides(config_file: str | None) -> dict:
    """Apply JSON config overrides to runtime config module."""
    if not config_file:
        return {}
    path = Path(config_file)
    payload = json.loads(path.read_text(encoding="utf-8"))
    applied = {}

    for key in ("SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "NVD_API_KEY"):
        if key in payload:
            setattr(config, key, payload[key])
            applied[key] = "set" if payload[key] else "empty"

    if "request_timeout_seconds" in payload:
        config.REQUEST_TIMEOUT_SECONDS = int(payload["request_timeout_seconds"])
        applied["REQUEST_TIMEOUT_SECONDS"] = config.REQUEST_TIMEOUT_SECONDS
    if "retry_attempts" in payload:
        config.RETRY_ATTEMPTS = int(payload["retry_attempts"])
        applied["RETRY_ATTEMPTS"] = config.RETRY_ATTEMPTS
    if "retry_backoff_seconds" in payload:
        config.RETRY_BACKOFF_SECONDS = float(payload["retry_backoff_seconds"])
        applied["RETRY_BACKOFF_SECONDS"] = config.RETRY_BACKOFF_SECONDS

    if "asset_criticality_rules" in payload and isinstance(payload["asset_criticality_rules"], dict):
        config.ASSET_CRITICALITY_RULES.update(payload["asset_criticality_rules"])
        applied["ASSET_CRITICALITY_RULES"] = "updated"
    if "maintenance_windows" in payload and isinstance(payload["maintenance_windows"], dict):
        config.MAINTENANCE_WINDOWS.update(payload["maintenance_windows"])
        applied["MAINTENANCE_WINDOWS"] = "updated"

    return applied


def apply_env_file_overrides(env_file: str | None, required: bool = False) -> dict:
    """Apply .env-style overrides. Returns applied keys."""
    if not env_file:
        return {}
    path = Path(env_file)
    if not path.exists():
        if required:
            raise FileNotFoundError(f"Environment file not found: {env_file}")
        return {}

    applied = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')

        if key in ("SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "NVD_API_KEY"):
            setattr(config, key, value)
            applied[key] = "set" if value else "empty"
        elif key == "REQUEST_TIMEOUT_SECONDS":
            config.REQUEST_TIMEOUT_SECONDS = int(value)
            applied[key] = config.REQUEST_TIMEOUT_SECONDS
        elif key == "RETRY_ATTEMPTS":
            config.RETRY_ATTEMPTS = int(value)
            applied[key] = config.RETRY_ATTEMPTS
        elif key == "RETRY_BACKOFF_SECONDS":
            config.RETRY_BACKOFF_SECONDS = float(value)
            applied[key] = config.RETRY_BACKOFF_SECONDS
    return applied


def retry(
    attempts: int = 3,
    backoff_seconds: float = 1.0,
    retry_on: tuple[type[Exception], ...] = (TimeoutError, ConnectionError),
) -> Callable:
    """Retry decorator for API calls with fixed backoff."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(1, attempts + 1):
                try:
                    return func(*args, **kwargs)
                except retry_on as exc:
                    last_error = exc
                    if attempt < attempts:
                        time.sleep(backoff_seconds)
            raise last_error

        return wrapper

    return decorator


def deduplicate(items: list) -> list:
    """Return a list preserving order while removing duplicates."""
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
