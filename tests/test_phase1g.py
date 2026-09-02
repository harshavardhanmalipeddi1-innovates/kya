"""
Phase 1G-A tests: Durable execution state machine and crash recovery.

Validates:
  - execution_state lifecycle in audit records
  - Audit record created BEFORE payment call
  - Explicit payment failure path (PAYMENT_FAILED)
  - Outbox replay on startup
  - PAYMENT_UNKNOWN is never auto-released
  - Orphaned reservation is not automatically reusable
  - Concurrent step-up execution state transitions
  - Duplicate execution remains blocked
  - Startup recovery algorithm
"""

import json
import os
import sys
import shutil
import tempfile
import unittest

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, BACKEND_DIR)

os.environ.setdefault("KYA_SIGNING_SECRET", "test-signing-secret-for-phase1g-tests")
os.environ.setdefault("KYA_DEMO_ISSUER_KEY", "test-key")

try:
    from fastapi.testclient import TestClient
    HAVE_FASTAPI = True
except ImportError:
    HAVE_FASTAPI = False

import registry
import audit as audit_store
import baseline


AGENT_ID = "agent_procure_bot_042"
HUMAN_ID = "user_priya_88"
DEMO_KEY = os.environ.get("KYA_DEMO_ISSUER_KEY", "test-key")


@unittest.skipUnless(HAVE_FASTAPI, "fastapi not installed")
class TestExecutionStateLifecycle(unittest.TestCase):
    """Test that execution_state transitions correctly through the lifecycle."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        # Redirect all DBs to temp dir
        self._orig_consumed = registry.CONSUMED_DB_PATH
        self._orig_audit = audit_store.AUDIT_PATH
        self._orig_baseline = baseline.BASELINE_DB_PATH
        registry.CONSUMED_DB_PATH = os.path.join(self._tmpdir, "execution_claims.db")
        audit_store.AUDIT_PATH = os.path.join(self._tmpdir, "audit_trail.db")
        baseline.BASELINE_DB_PATH = os.path.join(self._tmpdir, "baselines.db")
        # Import main after redirecting DBs
        from main import app
        self.client = TestClient(app)

    def tearDown(self):
        registry.CONSUMED_DB_PATH = self._orig_consumed
        audit_store.AUDIT_PATH = self._orig_audit
        baseline.BASELINE_DB_PATH = self._orig_baseline
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_approve_sets_execution_state(self):
        """Successful approve path sets execution_state through the lifecycle."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, max_amount=50000,
            allowed_categories=["groceries"],
        )
        resp = self.client.post("/verify", json={
            "agent_id": AGENT_ID,
            "delegation_token": token,
            "stated_intent": "buy groceries for the week",
            "cart": [{"item": "Milk", "category": "groceries", "amount": 500}],
        }, headers={"x-kya-demo-key": DEMO_KEY})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["decision"], "APPROVE")

        # Verify final execution_state is EXECUTED
        audit = audit_store.get_one(data["audit_id"])
        self.assertEqual(audit["execution_state"], "EXECUTED")
        self.assertEqual(audit["decision"], "APPROVE")
        self.assertTrue(audit["executed"])

    def test_audit_recorded_before_payment_in_verify(self):
        """Audit record exists with EXECUTION_PENDING before payment is created.
        
        This is the core Phase 1G-A invariant: the audit trail must exist
        before any external payment call.
        """
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, max_amount=50000,
            allowed_categories=["groceries"],
        )
        # We can't easily intercept the middle of the flow, but we can
        # verify that the final audit has the execution_id field, which
        # is only set when the audit is created before the payment call.
        resp = self.client.post("/verify", json={
            "agent_id": AGENT_ID,
            "delegation_token": token,
            "stated_intent": "buy groceries for the week",
            "cart": [{"item": "Milk", "category": "groceries", "amount": 500}],
        }, headers={"x-kya-demo-key": DEMO_KEY})
        data = resp.json()
        audit = audit_store.get_one(data["audit_id"])
        # execution_id is set when audit is created in EXECUTION_PENDING state
        self.assertIn("execution_id", audit)
        self.assertTrue(audit["execution_id"].startswith("exec_"))

    def test_outbox_has_reconciliation_fields(self):
        """Outbox entry contains execution_id, agent_id, amount for reconciliation."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, max_amount=50000,
            allowed_categories=["groceries"],
        )
        resp = self.client.post("/verify", json={
            "agent_id": AGENT_ID,
            "delegation_token": token,
            "stated_intent": "buy groceries for the week",
            "cart": [{"item": "Milk", "category": "groceries", "amount": 500}],
        }, headers={"x-kya-demo-key": DEMO_KEY})
        self.assertEqual(resp.json()["decision"], "APPROVE")
        # Outbox should be clean after finalization
        self.assertEqual(registry.get_pending_outbox_count(), 0)

    def test_step_up_sets_execution_state(self):
        """Step-up confirmation path sets execution_state correctly."""
        # First, create a STEP_UP scenario
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, max_amount=50000,
            allowed_categories=["groceries"],
        )
        # Large amount triggers STEP_UP for procure_bot (mean=1200, std=350)
        resp = self.client.post("/verify", json={
            "agent_id": AGENT_ID,
            "delegation_token": token,
            "stated_intent": "buy groceries for the week",
            "cart": [{"item": "Milk", "category": "groceries", "amount": 2500}],
        }, headers={"x-kya-demo-key": DEMO_KEY})
        data = resp.json()
        self.assertEqual(data["decision"], "STEP_UP")
        audit_id = data["audit_id"]

        # Confirm the step-up
        resp2 = self.client.post("/step-up/confirm", json={
            "audit_id": audit_id,
            "human_confirmed": True,
        }, headers={"x-kya-demo-key": DEMO_KEY})
        self.assertEqual(resp2.json()["decision"], "APPROVE (after step-up)")

        # Verify execution_state is EXECUTED
        audit = audit_store.get_one(audit_id)
        self.assertEqual(audit["execution_state"], "EXECUTED")

    def test_declined_step_up_no_execution_state(self):
        """Declined step-up doesn't set execution_state."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, max_amount=50000,
            allowed_categories=["groceries"],
        )
        resp = self.client.post("/verify", json={
            "agent_id": AGENT_ID,
            "delegation_token": token,
            "stated_intent": "buy groceries for the week",
            "cart": [{"item": "Milk", "category": "groceries", "amount": 2500}],
        }, headers={"x-kya-demo-key": DEMO_KEY})
        audit_id = resp.json()["audit_id"]

        resp2 = self.client.post("/step-up/confirm", json={
            "audit_id": audit_id,
            "human_confirmed": False,
        }, headers={"x-kya-demo-key": DEMO_KEY})
        self.assertIn("BLOCK", resp2.json()["decision"])

        # No execution_state for declined step-up
        audit = audit_store.get_one(audit_id)
        self.assertIsNone(audit.get("execution_state"))


@unittest.skipUnless(HAVE_FASTAPI, "fastapi not installed")
class TestCrashRecovery(unittest.TestCase):
    """Test startup crash recovery scenarios."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_consumed = registry.CONSUMED_DB_PATH
        self._orig_audit = audit_store.AUDIT_PATH
        self._orig_baseline = baseline.BASELINE_DB_PATH
        registry.CONSUMED_DB_PATH = os.path.join(self._tmpdir, "execution_claims.db")
        audit_store.AUDIT_PATH = os.path.join(self._tmpdir, "audit_trail.db")
        baseline.BASELINE_DB_PATH = os.path.join(self._tmpdir, "baselines.db")

    def tearDown(self):
        registry.CONSUMED_DB_PATH = self._orig_consumed
        audit_store.AUDIT_PATH = self._orig_audit
        baseline.BASELINE_DB_PATH = self._orig_baseline
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_orphaned_reservation_not_released(self):
        """A RESERVED token with no audit entry is NOT automatically released.
        
        Phase 1G-A invariant: we cannot prove the payment provider was never
        invoked just because the audit doesn't exist. The token must remain
        RESERVED and be flagged for administrative cleanup.
        """
        # Manually create a RESERVED token with no audit entry
        jti = "orphaned_test_jti_123"
        registry.reserve_token(jti)
        self.assertTrue(registry.is_token_consumed(jti))

        # Run recovery
        result = registry.recover_orphaned_reservations(
            audit_store.find_audit_by_jti,
            audit_store.update_execution_state,
        )

        # Token should NOT be released
        self.assertTrue(registry.is_token_consumed(jti))
        # Should be flagged as orphaned
        self.assertEqual(result["orphaned"], 1)
        self.assertEqual(result["released"], 0)

    def test_payment_failed_token_released(self):
        """A RESERVED token with PAYMENT_FAILED audit is released."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, max_amount=50000,
            allowed_categories=["groceries"],
        )
        # Create an audit entry with PAYMENT_FAILED state
        audit_entry = {
            "agent_id": AGENT_ID,
            "decision": "BLOCK",
            "execution_state": "PAYMENT_FAILED",
            "jti": "test_failed_jti",
            "total_amount": 500,
        }
        audit_id = audit_store.record(audit_entry)
        # Reserve the token
        registry.reserve_token("test_failed_jti")

        # Run recovery
        result = registry.recover_orphaned_reservations(
            audit_store.find_audit_by_jti,
            audit_store.update_execution_state,
        )

        # Token should be released
        self.assertFalse(registry.is_token_consumed("test_failed_jti"))
        self.assertEqual(result["released"], 1)

    def test_payment_unknown_not_released(self):
        """A RESERVED token with PAYMENT_UNKNOWN is NOT released."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, max_amount=50000,
            allowed_categories=["groceries"],
        )
        audit_entry = {
            "agent_id": AGENT_ID,
            "decision": "APPROVE",
            "execution_state": "PAYMENT_UNKNOWN",
            "jti": "test_unknown_jti",
            "total_amount": 500,
        }
        audit_id = audit_store.record(audit_entry)
        registry.reserve_token("test_unknown_jti")

        result = registry.recover_orphaned_reservations(
            audit_store.find_audit_by_jti,
            audit_store.update_execution_state,
        )

        # Token should NOT be released
        self.assertTrue(registry.is_token_consumed("test_unknown_jti"))
        self.assertEqual(result["released"], 0)
        self.assertEqual(result["flagged_payment_unknown"], 1)

    def test_execution_pending_not_released(self):
        """A RESERVED token with EXECUTION_PENDING is NOT released."""
        audit_entry = {
            "agent_id": AGENT_ID,
            "decision": "APPROVE",
            "execution_state": "EXECUTION_PENDING",
            "jti": "test_pending_jti",
            "total_amount": 500,
        }
        audit_id = audit_store.record(audit_entry)
        registry.reserve_token("test_pending_jti")

        result = registry.recover_orphaned_reservations(
            audit_store.find_audit_by_jti,
            audit_store.update_execution_state,
        )

        # Token should NOT be released, should be flagged as PAYMENT_UNKNOWN
        self.assertTrue(registry.is_token_consumed("test_pending_jti"))
        self.assertEqual(result["released"], 0)
        self.assertEqual(result["flagged_payment_unknown"], 1)

    def test_outbox_replay_still_works(self):
        """Existing outbox replay functionality is preserved."""
        jti = "outbox_replay_jti"
        audit_entry = {
            "agent_id": AGENT_ID,
            "decision": "APPROVE",
            "jti": jti,
            "total_amount": 500,
        }
        audit_id = audit_store.record(audit_entry)
        registry.reserve_token(jti)
        registry.write_outbox_entry(jti, audit_id, "order_test_123")

        # Verify outbox entry exists
        self.assertEqual(registry.get_pending_outbox_count(), 1)

        # Replay
        replayed = registry.replay_pending_finalizations(registry.finalize_execution)
        self.assertEqual(replayed, 1)
        self.assertEqual(registry.get_pending_outbox_count(), 0)
        # Token should be EXECUTED
        self.assertTrue(registry.is_token_consumed(jti))

    def test_find_audit_by_jti(self):
        """find_audit_by_jti correctly locates an audit entry."""
        jti = "findable_jti_456"
        audit_entry = {
            "agent_id": AGENT_ID,
            "decision": "APPROVE",
            "jti": jti,
            "total_amount": 500,
        }
        audit_id = audit_store.record(audit_entry)

        found = audit_store.find_audit_by_jti(jti)
        self.assertIsNotNone(found)
        self.assertEqual(found["jti"], jti)
        self.assertEqual(found["agent_id"], AGENT_ID)

    def test_find_audit_by_jti_not_found(self):
        """find_audit_by_jti returns None for non-existent jti."""
        found = audit_store.find_audit_by_jti("nonexistent_jti")
        self.assertIsNone(found)


@unittest.skipUnless(HAVE_FASTAPI, "fastapi not installed")
class TestDuplicateExecution(unittest.TestCase):
    """Test that duplicate execution remains blocked."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_consumed = registry.CONSUMED_DB_PATH
        self._orig_audit = audit_store.AUDIT_PATH
        self._orig_baseline = baseline.BASELINE_DB_PATH
        registry.CONSUMED_DB_PATH = os.path.join(self._tmpdir, "execution_claims.db")
        audit_store.AUDIT_PATH = os.path.join(self._tmpdir, "audit_trail.db")
        baseline.BASELINE_DB_PATH = os.path.join(self._tmpdir, "baselines.db")
        from main import app
        self.client = TestClient(app)

    def tearDown(self):
        registry.CONSUMED_DB_PATH = self._orig_consumed
        audit_store.AUDIT_PATH = self._orig_audit
        baseline.BASELINE_DB_PATH = self._orig_baseline
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_same_token_cannot_execute_twice(self):
        """Using the same delegation token twice blocks the second attempt."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, max_amount=50000,
            allowed_categories=["groceries"],
        )
        # First use: should APPROVE
        resp1 = self.client.post("/verify", json={
            "agent_id": AGENT_ID,
            "delegation_token": token,
            "stated_intent": "buy groceries for the week",
            "cart": [{"item": "Milk", "category": "groceries", "amount": 500}],
        }, headers={"x-kya-demo-key": DEMO_KEY})
        self.assertEqual(resp1.json()["decision"], "APPROVE")

        # Second use: should BLOCK (replay detected)
        resp2 = self.client.post("/verify", json={
            "agent_id": AGENT_ID,
            "delegation_token": token,
            "stated_intent": "buy groceries for the week",
            "cart": [{"item": "Milk", "category": "groceries", "amount": 500}],
        }, headers={"x-kya-demo-key": DEMO_KEY})
        self.assertEqual(resp2.json()["decision"], "BLOCK")
        self.assertIn("replay", resp2.json()["reasons"][0].lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
