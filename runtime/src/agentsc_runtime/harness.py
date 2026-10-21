"""Model-call retries (design §12): which failures are worth another attempt, and how long to wait first.

The process-wide Anthropic client is built with `max_retries=0`; every retry happens here, so each
attempt is reported (and billed) on its own and none outlives the Execute deadline.
"""

from __future__ import annotations

import email.utils
import math
import time
from collections.abc import Iterator
from typing import Any

# Backoff before retry n (n = 0 for the first retry): RETRY_BASE * 2**n seconds, at most RETRY_CAP.
RETRY_BASE = 0.5
RETRY_CAP = 8.0
# Without an Execute deadline (never the case behind a sidecar) a retry-after is honoured up to this.
RETRY_AFTER_CAP_NO_DEADLINE = 60.0
# The error type the API sends in an SSE `error` event when it is overloaded mid-stream.
OVERLOADED = "overloaded_error"


def _chain(err: BaseException) -> Iterator[BaseException]:
    """`err`, the provider error a ModelError wraps, and their `__cause__`s, each once."""
    seen: set[int] = set()
    todo: list[BaseException | None] = [err]
    while todo:
        cur = todo.pop(0)
        if cur is None or id(cur) in seen:
            continue
        seen.add(id(cur))
        yield cur
        wrapped = getattr(cur, "cause", None)
        todo.append(wrapped if isinstance(wrapped, BaseException) else None)
        todo.append(cur.__cause__)


def _retryable_classes() -> tuple[type[BaseException], ...]:
    import anthropic

    names = (
        "RateLimitError",  # 429
        "InternalServerError",  # 5xx
        "OverloadedError",  # 529: its own class, not an InternalServerError, in this SDK
        "ServiceUnavailableError",  # 503, where the SDK raises it
        "DeadlineExceededError",  # 504, where the SDK raises it
        "APIConnectionError",  # includes APITimeoutError
    )
    return tuple(c for n in names if isinstance(c := getattr(anthropic, n, None), type))


def is_retryable(err: BaseException) -> bool:
    """A rate limit, a server error (incl. 529), a connection error or timeout, or an overload the API
    reported mid-stream. Any other API status error (every other 4xx) and anything that is not an SDK
    error is final."""
    try:
        import anthropic
    except ImportError:  # pragma: no cover — a dependency of this package
        return False
    retryable = _retryable_classes()
    for cur in _chain(err):
        if isinstance(cur, retryable):
            return True
        if isinstance(cur, anthropic.APIStatusError):
            # A stream that already started (HTTP 200) and then got an `error` event carries its type.
            return getattr(cur, "type", None) == OVERLOADED
    return False


def _headers(err: BaseException) -> Any:
    for cur in _chain(err):
        headers = getattr(getattr(cur, "response", None), "headers", None)
        if headers is not None:
            return headers
    return None


def _seconds(value: Any) -> float | None:
    try:
        s = float(value)
    except (TypeError, ValueError):
        return None
    return max(0.0, s) if math.isfinite(s) else None


def retry_after(err: BaseException) -> float | None:
    """Seconds the API asked to wait: `retry-after-ms`, else `retry-after` (seconds or an HTTP date)."""
    headers = _headers(err)
    if headers is None:
        return None
    try:
        ms, value = headers.get("retry-after-ms"), headers.get("retry-after")
    except AttributeError:
        return None
    if (s := _seconds(ms)) is not None:
        return s / 1000
    if (s := _seconds(value)) is not None:
        return s
    if not isinstance(value, str):
        return None
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if when.tzinfo is None:
        return None
    return max(0.0, when.timestamp() - time.time())


def backoff(n: int) -> float:
    """Wait before retry n (0-based): 0.5 s × 2ⁿ, capped at 8 s."""
    return min(RETRY_BASE * 2.0 ** min(n, 32), RETRY_CAP)


def retry_delay(n: int, err: BaseException) -> float:
    """Wait before retry n after `err`: the API's retry-after if it sent one, else the backoff."""
    asked = retry_after(err)
    return backoff(n) if asked is None else asked
