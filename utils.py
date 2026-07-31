"""Shared utility helpers."""

import logging
import time
from collections.abc import Callable
from functools import wraps


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


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
