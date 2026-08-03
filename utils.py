"""Shared utility helpers."""

import json
import logging
import time
from collections.abc import Callable
from functools import wraps

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
