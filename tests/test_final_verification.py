"""
KYA Final End-to-End Verification Suite.
"""
import os, sys, tempfile, shutil, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

class TestFullSystemVerification(unittest.TestCase):
    def setUp(self):
        import baseline, audit, registry
        self._tmpdir = tempfile.mkdtemp()
        self._orig_baseline = baseline.BASELINE_DB_PATH
        self._orig_consumed = registry.CONSUMED_DB_PATH
        self._orig_audit = audit.AUDIT_PATH
        baseline.BASELINE_DB_PATH = os.path.join(self._tmpdir, "baselines.db")
        registry.CONSUMED_DB_PATH = os.path.join(self._tmpdir, "consumed.db")
        audit.AUDIT_PATH = os.path.join(self._tmpdir, "audit.db")

    def tearDown(self):
        import baseline, audit, registry
        baseline.BASELINE_DB_PATH = self._orig_baseline
        registry.CONSUMED_DB_PATH = self._orig_consumed
        audit.AUDIT_PATH = self._orig_audit
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_01_pipeline_runs(self):
        from pipeline import run_pipeline
        result = run_pipeline(agent_id="agent_procure_bot_042", delegation_token="dummy",
            stated_intent="buy groceries", cart=[{"item":"Rice","amount":500.0,"category":"groceries"}],
            use_rolling_baseline=False)
        self.assertIn(result["decision"], ["APPROVE","BLOCK","STEP_UP"])
        self.assertIn("risk", result)

    def test_02_decision_engine(self):
        from decision_engine import decide
        self.assertEqual(decide(True,True,"",True,True,{"mismatch_severity":"none","reason":"ok"},{"total_score":10.0})["decision"], "APPROVE")
        self.assertEqual(decide(True,True,"",True,True,{"mismatch_severity":"none","reason":"ok"},{"total_score":30.0})["decision"], "STEP_UP")
        self.assertEqual(decide(True,True,"",True,True,{"mismatch_severity":"none","reason":"ok"},{"total_score":60.0})["decision"], "BLOCK")

    def test_03_risk_scorer(self):
        from risk_scorer import compute_risk
        r = compute_risk(100.0, {"baseline_mean_amount":1000,"baseline_std_amount":300}, True, True, {"mismatch_severity":"none"})
        self.assertGreaterEqual(r["total_score"], 0)
        self.assertLessEqual(r["total_score"], 100)

    def test_04_intent_matcher(self):
        from intent_match import check_intent_match
        r = check_intent_match("buy groceries", [{"item":"Rice","amount":500,"category":"groceries"}])
        self.assertTrue(r["match"])

    def test_05_audit_trail(self):
        from audit import record, get_all
        aid = record({"agent_id":"test","decision":"APPROVE","total_amount":100})
        self.assertIsNotNone(aid)
        self.assertGreater(len(get_all()), 0)

    def test_06_baseline_protection(self):
        from baseline import get_effective_baseline, record_transaction, MIN_SAMPLES
        for i in range(MIN_SAMPLES + 2):
            record_transaction("test_agent", 1000.0)
        mean, std, source = get_effective_baseline("test_agent", 1000.0, 200.0)
        self.assertIn(source, ["rolling", "clamped", "static_fallback"])

    def test_07_rate_limiter(self):
        from rate_limiter import LocalRateLimiter
        rl = LocalRateLimiter()
        for i in range(5): rl.allow_request("test", 5, 60)
        self.assertFalse(rl.allow_request("test", 5, 60))

    def test_08_trace_context(self):
        from trace import TraceContext, lookup_by_request_id
        import trace
        orig = trace.TRACE_DB_PATH
        trace.TRACE_DB_PATH = os.path.join(self._tmpdir, "traces.db")
        try:
            ctx = TraceContext(request_id="e2e_001")
            ctx.set_agent_id("a"); ctx.set_audit_id("audit_001"); ctx.set_execution_id("exec_001")
            ctx.finalize()
            self.assertIsNotNone(lookup_by_request_id("e2e_001"))
        finally:
            trace.TRACE_DB_PATH = orig

    def test_09_policy_engine(self):
        from policy_engine import PolicyEngine
        r = PolicyEngine().evaluate(agent_id="test", category="electronics", amount=100)
        self.assertIn("decision", r)

    def test_10_circuit_breaker(self):
        from reliability import CircuitBreaker
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=1)
        self.assertTrue(cb.allow_request())
        cb.record_failure(); cb.record_failure()
        self.assertFalse(cb.allow_request())

    def test_11_metrics(self):
        from metrics import MetricsCollector
        mc = MetricsCollector()
        mc.record_request("GET", "/test", 200, 0.01); mc.record_request("GET", "/test", 200, 0.02)
        self.assertTrue(hasattr(mc, "export_prometheus"))

    def test_12_payment_provider(self):
        from razorpay_mock import MockPaymentProvider
        r = MockPaymentProvider().create_order(100.0, "INR", "test")
        self.assertGreater(r.amount, 0)

    def test_13_webhook(self):
        from webhook import verify_signature
        self.assertFalse(verify_signature(b"test", "bad"))

    def test_14_reconciliation(self):
        from reconciliation import reconcile
        self.assertTrue(callable(reconcile))

    def test_15_agent_graph(self):
        from agent_graph import AgentGraph
        g = AgentGraph()
        g.register_agent("a", {"allowed_actions":[]}); g.register_agent("b", {"allowed_actions":[]})
        g.add_delegation("a", "b", ["x"]); g.add_delegation("b", "a", ["y"])
        self.assertGreater(len(g.detect_circular_delegation()), 0)

    def test_16_benchmark(self):
        from benchmark import BenchmarkSuite
        self.assertIn("latency_ms", BenchmarkSuite().measure_latency("t", lambda: None, 10))

    def test_17_datastore(self):
        from datastore_eval import evaluate_datastore
        self.assertEqual(evaluate_datastore()["current"], "sqlite")

    def test_18_reliability(self):
        from reliability_ext import retry_with_backoff, classify_provider_error
        self.assertTrue(retry_with_backoff(lambda: 42, max_retries=0)["success"])
        self.assertTrue(classify_provider_error(Exception("timeout"))["retryable"])

    def test_19_security(self):
        from registry import verify_delegation_token
        self.assertFalse(verify_delegation_token("invalid", now=1700000200)["valid"])

    def test_20_eval(self):
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "eval"))
        from harness import check_reproducibility
        self.assertTrue(check_reproducibility(runs=2))

if __name__ == "__main__": unittest.main()
