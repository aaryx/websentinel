"""Rate limiter + elapsed timer."""
from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """Simple async rate limiter (requests per second, 0 = unlimited)."""

    def __init__(self, rate: float) -> None:
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def wait(self) -> None:
        if self.interval == 0:
            return
        async with self._lock:
            now = time.monotonic()
            if now < self._next:
                await asyncio.sleep(self._next - now)
            self._next = max(now, self._next) + self.interval


def elapsed_ms(start: float) -> float:
    return (time.monotonic() - start) * 1000.0
