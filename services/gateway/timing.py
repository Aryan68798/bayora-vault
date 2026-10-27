"""
Timing-padding helper.

Purpose
-------
The real LLM latency is correlated with prompt length. Padding erases
that correlation by sleeping until the next fixed-size time bucket.

Algorithm
---------
Given a bucket size B (seconds) and the wall-clock time at which processing
*started* (t_start), we compute the next bucket boundary and sleep until it:

    elapsed = now - t_start
    sleep_for = B - (elapsed % B)

If elapsed is already at a boundary (modulo arithmetic == 0) we sleep a
full bucket to avoid returning immediately.

Usage
-----
    pad = TimingPadder(bucket_seconds=1.0)
    t0 = pad.start()
    # ... do real work ...
    await pad.finish(t0)      # async — uses asyncio.sleep
    # or
    pad.finish_sync(t0)       # sync fallback
"""
from __future__ import annotations

import asyncio
import time


class TimingPadder:
    """Pad response time to fixed bucket boundaries."""

    def __init__(self, bucket_seconds: float = 1.0) -> None:
        if bucket_seconds <= 0:
            raise ValueError("bucket_seconds must be > 0")
        self.bucket_seconds = bucket_seconds

    def start(self) -> float:
        """Record and return the current monotonic timestamp."""
        return time.monotonic()

    def _sleep_duration(self, t_start: float) -> float:
        elapsed = time.monotonic() - t_start
        remainder = elapsed % self.bucket_seconds
        # If already on boundary, wait a full bucket
        sleep_for = self.bucket_seconds - remainder if remainder != 0.0 else self.bucket_seconds
        return sleep_for

    async def finish(self, t_start: float) -> float:
        """Async: sleep until next bucket boundary, return actual sleep time."""
        sleep_for = self._sleep_duration(t_start)
        await asyncio.sleep(sleep_for)
        return sleep_for

    def finish_sync(self, t_start: float) -> float:
        """Sync: sleep until next bucket boundary, return actual sleep time."""
        sleep_for = self._sleep_duration(t_start)
        time.sleep(sleep_for)
        return sleep_for
