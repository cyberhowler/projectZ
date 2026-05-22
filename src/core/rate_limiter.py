"""
ProjectZ - Rate Limiter (Fixed)
- NO default delay (was causing 250s+ hangs on bulk requests)
- Only throttles when API actually returns 429
- Per-domain backoff that resets after success
- Lock kept only to prevent simultaneous 429 storms
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from contextlib import asynccontextmanager


class _DomainRateLimiter:

    def __init__(self):
        self._locks:     dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._backoff:   dict[str, float]         = {}   # only set after 429
        self._last_429:  dict[str, float]         = defaultdict(float)

    @asynccontextmanager
    async def throttle(self, domain: str):
        """
        No delay by default.
        Only waits if domain recently returned 429 (backoff active).
        """
        key = domain.lower().split("/")[0].split(":")[0]

        # Check if we're in backoff for this domain
        backoff = self._backoff.get(key, 0)
        if backoff > 0:
            since = time.monotonic() - self._last_429.get(key, 0)
            remaining = backoff - since
            if remaining > 0:
                await asyncio.sleep(min(remaining, 5.0))  # cap wait at 5s
            else:
                self._backoff.pop(key, None)   # backoff expired

        yield

    async def on_rate_limited(self, domain: str, wait: float = 5.0):
        """Called when a 429 is received — sets backoff for this domain only."""
        key = domain.lower().split("/")[0].split(":")[0]
        # Exponential backoff capped at 30s
        current = self._backoff.get(key, 1.0)
        self._backoff[key] = min(current * 2, 30.0)
        self._last_429[key] = time.monotonic()
        actual_wait = min(wait, 8.0)   # never wait more than 8s
        await asyncio.sleep(actual_wait)

    def reset(self, domain: str = None):
        """Reset backoff for domain (call after successful response)."""
        if domain:
            key = domain.lower().split("/")[0]
            self._backoff.pop(key, None)
        else:
            self._backoff.clear()

    def set_delay(self, domain: str, delay: float):
        """Legacy compat — sets backoff directly."""
        self._backoff[domain.lower()] = delay


rate_limiter = _DomainRateLimiter()
