import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

class TestPhase1J_RateLimiter(unittest.TestCase):
    def test_local_rate_limiter_allows_within_limit(self):
        from rate_limiter import LocalRateLimiter
        rl = LocalRateLimiter()
        for i in range(5):
            self.assertTrue(rl.allow_request("test_key", 10, 60))
    def test_local_rate_limiter_blocks_over_limit(self):
        from rate_limiter import LocalRateLimiter
        rl = LocalRateLimiter()
        for i in range(5):
            rl.allow_request("test_key", 5, 60)
        self.assertFalse(rl.allow_request("test_key", 5, 60))
    def test_local_rate_limiter_reset(self):
        from rate_limiter import LocalRateLimiter
        rl = LocalRateLimiter()
        for i in range(5):
            rl.allow_request("test_key", 5, 60)
        rl.reset("test_key")
        self.assertTrue(rl.allow_request("test_key", 5, 60))
    def test_factory_returns_local_by_default(self):
        from rate_limiter import get_rate_limiter, LocalRateLimiter
        rl = get_rate_limiter()
        self.assertIsInstance(rl, LocalRateLimiter)

class TestPhase1K_DatastoreEval(unittest.TestCase):
    def test_evaluate_datastore_default(self):
        from datastore_eval import evaluate_datastore
        result = evaluate_datastore()
        self.assertEqual(result["current"], "sqlite")
        self.assertTrue(result["migration_ready"])
    def test_schema_tables(self):
        from datastore_eval import get_schema_tables
        tables = get_schema_tables()
        self.assertIn("audit_entries", tables)
        self.assertIn("traces", tables)

class TestPhase6_Reliability(unittest.TestCase):
    def test_retry_succeeds(self):
        from reliability_ext import retry_with_backoff
        result = retry_with_backoff(lambda: 42, max_retries=0)
        self.assertTrue(result["success"])
        self.assertEqual(result["result"], 42)
    def test_retry_exhausts(self):
        from reliability_ext import retry_with_backoff
        result = retry_with_backoff(lambda: 1/0, max_retries=1, base_backoff=0.01)
        self.assertFalse(result["success"])
        self.assertEqual(result["attempts"], 2)
    def test_classify_timeout(self):
        from reliability_ext import classify_provider_error
        r = classify_provider_error(Exception("Connection timeout"))
        self.assertEqual(r["category"], "timeout")
    def test_classify_auth(self):
        from reliability_ext import classify_provider_error
        r = classify_provider_error(Exception("401 Unauthorized"))
        self.assertFalse(r["retryable"])

class TestPhase11_AgentGraph(unittest.TestCase):
    def test_register_and_check(self):
        from agent_graph import AgentGraph
        g = AgentGraph()
        g.register_agent("a1", {"allowed_actions": ["read"]})
        self.assertTrue(g.check_authority("a1", "read")["authorized"])
        self.assertFalse(g.check_authority("a1", "write")["authorized"])
    def test_delegation(self):
        from agent_graph import AgentGraph
        g = AgentGraph()
        g.register_agent("a1", {"allowed_actions": []})
        g.add_delegation("a1", "a2", ["read"])
        self.assertTrue(g.check_authority("a1", "read")["authorized"])
    def test_circular_detection(self):
        from agent_graph import AgentGraph
        g = AgentGraph()
        g.register_agent("a1", {})
        g.register_agent("a2", {})
        g.add_delegation("a1", "a2", ["x"])
        g.add_delegation("a2", "a1", ["y"])
        cycles = g.detect_circular_delegation()
        self.assertGreater(len(cycles), 0)

class TestPhase14_Benchmark(unittest.TestCase):
    def test_measure_latency(self):
        from benchmark import BenchmarkSuite
        bs = BenchmarkSuite()
        r = bs.measure_latency("test", lambda: sum(range(100)), iterations=10)
        self.assertIn("latency_ms", r)
        self.assertGreaterEqual(r["latency_ms"]["mean"], 0)
    def test_accuracy_metrics(self):
        from benchmark import BenchmarkSuite
        bs = BenchmarkSuite()
        r = bs.accuracy_metrics(["APPROVE", "BLOCK", "BLOCK"], ["APPROVE", "BLOCK", "APPROVE"])
        self.assertEqual(r["tp"], 1)
        self.assertEqual(r["fp"], 1)
        self.assertEqual(r["fn"], 0)

if __name__ == "__main__":
    unittest.main()
