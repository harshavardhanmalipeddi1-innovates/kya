
"""
Phase 3A: Provider selection tests.
"""
import os, sys, unittest
BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, BACKEND_DIR)
os.environ.setdefault("KYA_SIGNING_SECRET", "test-signing-secret")
os.environ.setdefault("KYA_DEMO_ISSUER_KEY", "test-key")
try:
    from fastapi.testclient import TestClient
    HAVE_FASTAPI = True
except ImportError:
    HAVE_FASTAPI = False
import registry, audit as audit_store

AGENT_ID = "agent_procure_bot_042"
DEMO_KEY = os.environ.get("KYA_DEMO_ISSUER_KEY", "test-key")

def _make_token():
    return registry.issue_delegation_token(AGENT_ID, "user_priya_88", 50000, ["groceries"])

class TestProviderSelection(unittest.TestCase):
    def test_default_is_mock(self):
        from main import PAYMENT_PROVIDER_MODE
        self.assertEqual(PAYMENT_PROVIDER_MODE, "mock")

    def test_mock_creates_order(self):
        from razorpay_mock import MockPaymentProvider
        p = MockPaymentProvider()
        r = p.create_order(500.0, "INR", "test_receipt")
        self.assertTrue(r.success)
        self.assertIsNotNone(r.order_id)
        self.assertEqual(r.amount, 500.0)

    def test_mock_search(self):
        from razorpay_mock import MockPaymentProvider, seed_order
        from payment_provider import OrderSearchCriteria
        p = MockPaymentProvider()
        seed_order("order_1", 500.0, "exec_1", agent_id="agent_procure_bot_042")
        r = p.search_orders(OrderSearchCriteria(receipt="exec_1"))
        self.assertEqual(r.status.value, "exact_match")
        self.assertEqual(len(r.orders), 1)

@unittest.skipUnless(HAVE_FASTAPI, "fastapi not installed")
class TestProviderInRuntime(unittest.TestCase):
    def setUp(self):
        import tempfile, shutil
        self._tmpdir = tempfile.mkdtemp()
        self._orig_consumed = registry.CONSUMED_DB_PATH
        self._orig_audit = audit_store.AUDIT_PATH
        import baseline
        self._orig_baseline = baseline.BASELINE_DB_PATH
        registry.CONSUMED_DB_PATH = os.path.join(self._tmpdir, "e.db")
        audit_store.AUDIT_PATH = os.path.join(self._tmpdir, "a.db")
        baseline.BASELINE_DB_PATH = os.path.join(self._tmpdir, "b.db")
        from main import app
        self.client = TestClient(app)

    def tearDown(self):
        import shutil, baseline
        registry.CONSUMED_DB_PATH = self._orig_consumed
        audit_store.AUDIT_PATH = self._orig_audit
        baseline.BASELINE_DB_PATH = self._orig_baseline
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_verify_uses_mock_provider(self):
        token = _make_token()
        resp = self.client.post("/verify", json={
            "agent_id": AGENT_ID, "delegation_token": token,
            "stated_intent": "buy groceries",
            "cart": [{"item": "Milk", "category": "groceries", "amount": 500}],
        }, headers={"x-kya-demo-key": DEMO_KEY})
        data = resp.json()
        self.assertEqual(data["decision"], "APPROVE")
        self.assertIsNotNone(data["payment"])
        self.assertTrue(data["payment"]["razorpay_order_id"].startswith("order_TEST_"))

    def test_payment_has_execution_id(self):
        token = _make_token()
        resp = self.client.post("/verify", json={
            "agent_id": AGENT_ID, "delegation_token": token,
            "stated_intent": "buy groceries",
            "cart": [{"item": "Milk", "category": "groceries", "amount": 500}],
        }, headers={"x-kya-demo-key": DEMO_KEY})
        data = resp.json()
        self.assertIn("execution_id", data["payment"])
        self.assertTrue(data["payment"]["execution_id"].startswith("exec_"))

if __name__ == "__main__":
    unittest.main(verbosity=2)
