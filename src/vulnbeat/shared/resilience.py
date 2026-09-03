import time
from functools import wraps
from typing import Callable, ParamSpec, TypeVar

import requests

RETRYABLE_STATUS_CODES = {500, 502, 503, 504}

P = ParamSpec("P")
R = TypeVar("R")


def retry(max_attempts: int = 3, backoff_seconds: float = 1.0) -> Callable[[Callable[P, R]], Callable[P, R]]:
    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except requests.exceptions.HTTPError as error:
                    status = error.response.status_code if error.response is not None else None
                    if status not in RETRYABLE_STATUS_CODES or attempt == max_attempts:
                        raise
                except requests.exceptions.RequestException:
                    if attempt == max_attempts:
                        raise
                time.sleep(backoff_seconds * attempt)
            raise RuntimeError(f"retry({func.__name__}): exhausted attempts without returning or raising")
        return wrapper
    return decorator