"""
Validates the LocalRateLimiter, RedisRateLimiter stub, and factory.
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from rate_limiter import LocalRateLimiter, RedisRateLimiter, get_rate_limiter


class TestLocalRateLimiter(unittest.TestCase):
    def setUp(self):
        self.limiter = LocalRateLimiter()

    def test_allows_under_limit(self):
        for _ in range(5):
            self.assertTrue(self.limiter.allow_request("key", 10, 60))

    def test_blocks_over_limit(self):
        for _ in range(5):
            self.limiter.allow_request("key", 5, 60)
        self.assertFalse(self.limiter.allow_request("key", 5, 60))

    def test_window_expiry(self):
        self.limiter.allow_request("key", 1, 0)
        time.sleep(0.01)
        self.assertTrue(self.limiter.allow_request("key", 1, 0))

    def test_get_usage(self):
        for _ in range(3):
            self.limiter.allow_request("key", 10, 60)
        self.assertEqual(self.limiter.get_usage("key", 60), 3)

    def test_reset_key(self):
        for _ in range(5):
            self.limiter.allow_request("key", 5, 60)
        self.limiter.reset("key")
        self.assertTrue(self.limiter.allow_request("key", 5, 60))

    def test_reset_all(self):
        for _ in range(5):
            self.limiter.allow_request("key", 5, 60)
        self.limiter.reset()
        self.assertTrue(self.limiter.allow_request("key", 5, 60))

    def test_independent_keys(self):
        for _ in range(5):
            self.limiter.allow_request("key1", 5, 60)
        self.assertFalse(self.limiter.allow_request("key1", 5, 60))
        self.assertTrue(self.limiter.allow_request("key2", 5, 60))


class TestRedisRateLimiterFallback(unittest.TestCase):
    def test_falls_back_to_local(self):
        limiter = RedisRateLimiter("redis://localhost:9999")
        self.assertFalse(limiter._available)
        self.assertTrue(limiter.allow_request("key", 10, 60))


class TestFactory(unittest.TestCase):
    def test_default_is_local(self):
        limiter = get_rate_limiter()
        self.assertIsInstance(limiter, LocalRateLimiter)


if __name__ == "__main__":
    unittest.main()
