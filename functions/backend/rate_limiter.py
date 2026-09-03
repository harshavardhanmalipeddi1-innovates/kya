"""
Distributed Rate Limiter Abstraction.

Provides a RateLimiter interface with two implementations:
- LocalRateLimiter: in-memory per-process (current default)
- RedisRateLimiter: placeholder for Redis-backed distributed limiting

Phase 1J: Architecture and abstraction.
"""

import os
import time
import threading
from typing import Dict, Optional, Tuple
from collections import defaultdict


class LocalRateLimiter:
    """In-memory sliding-window rate limiter (per-process)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._requests: Dict[str, list] = defaultdict(list)

    def allow_request(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.time()
        cutoff = now - window_seconds
        with self._lock:
            self._requests[key] = [t for t in self._requests[key] if t > cutoff]
            if len(self._requests[key]) >= limit:
                return False
            self._requests[key].append(now)
            return True

    def check_and_increment(self, key: str, limit: int, window_seconds: int = 60):
        allowed = self.allow_request(key, limit, window_seconds)
        retry_after = 0 if allowed else window_seconds
        count = self.get_count(key)
        return {"allowed": allowed, "retry_after": retry_after, "count": count}

    def get_usage(self, key: str, window_seconds: int) -> int:
        now = time.time()
        cutoff = now - window_seconds
        with self._lock:
            return len([t for t in self._requests[key] if t > cutoff])

    def get_count(self, key: str) -> int:
        return self.get_usage(key, 60)

    def reset(self, key: Optional[str] = None) -> None:
        with self._lock:
            if key:
                self._requests.pop(key, None)
            else:
                self._requests.clear()


class RedisRateLimiter:
    """Redis-backed distributed rate limiter (placeholder)."""

    def __init__(self, redis_url: str):
        self._redis_url = redis_url
        self._local = LocalRateLimiter()
        try:
            import redis
            self._client = redis.from_url(redis_url, socket_timeout=5)
            self._client.ping()
            self._available = True
        except Exception:
            self._available = False

    def allow_request(self, key: str, limit: int, window_seconds: int) -> bool:
        if not self._available:
            return self._local.allow_request(key, limit, window_seconds)
        try:
            pipe = self._client.pipeline()
            now = time.time()
            window_key = f"kya:ratelimit:{key}"
            pipe.zremrangebyscore(window_key, 0, now - window_seconds)
            pipe.zadd(window_key, {str(now): now})
            pipe.zcard(window_key)
            pipe.expire(window_key, window_seconds)
            results = pipe.execute()
            return results[2] <= limit
        except Exception:
            return self._local.allow_request(key, limit, window_seconds)

    def check_and_increment(self, key: str, limit: int, window_seconds: int = 60) -> Tuple[bool, int]:
        allowed = self.allow_request(key, limit, window_seconds)
        retry_after = 0 if allowed else window_seconds
        return allowed, retry_after

    def get_usage(self, key: str, window_seconds: int) -> int:
        if not self._available:
            return self._local.get_usage(key, window_seconds)
        try:
            now = time.time()
            return self._client.zcount(f"kya:ratelimit:{key}", now - window_seconds, now)
        except Exception:
            return self._local.get_usage(key, window_seconds)

    def get_count(self, key: str) -> int:
        return self.get_usage(key, 60)

    def reset(self, key: Optional[str] = None) -> None:
        if not self._available:
            return self._local.reset(key)
        try:
            if key:
                self._client.delete(f"kya:ratelimit:{key}")
            else:
                for k in self._client.scan_iter("kya:ratelimit:*"):
                    self._client.delete(k)
        except Exception:
            self._local.reset(key)


def get_rate_limiter():
    """Factory: returns the configured rate limiter."""
    redis_url = os.environ.get("KYA_REDIS_URL")
    if redis_url:
        return RedisRateLimiter(redis_url)
    return LocalRateLimiter()
