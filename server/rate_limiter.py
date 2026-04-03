"""In-memory sliding-window rate limiter used by authentication and social endpoints."""

import threading
import time
from typing import Dict, List

from fastapi import HTTPException


class RateLimiter:
    def __init__(self):
        self._lock = threading.Lock()
        self._buckets: Dict[str, List[float]] = {}

    def check(self, scope: str, key: str, limit: int, window_seconds: int) -> None:
        now = time.time()
        bucket_key = f"{scope}:{key}"
        with self._lock:
            timestamps = self._buckets.get(bucket_key, [])
            cutoff = now - window_seconds
            timestamps = [ts for ts in timestamps if ts >= cutoff]
            if len(timestamps) >= limit:
                raise HTTPException(status_code=429, detail="Too many requests, try again later")
            timestamps.append(now)
            self._buckets[bucket_key] = timestamps
