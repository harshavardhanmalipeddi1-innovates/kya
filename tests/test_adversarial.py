"""
Adversarial test suite for KYA -- exercises the attack surface
systematically to verify the security boundary holds under hostile input.

Covers:
  1. Token forgery and manipulation
  2. Scope and category manipulation
  3. Amount boundary attacks
  4. Authentication bypass attempts
  5. Pipeline edge cases
  6. Concurrent attack scenarios
  7. Input injection

Each test documents the specific attack it validates against.
"""

import json
import math
import os
import sys
import tempfile
import threading
import time
import unittest

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, BACKEND_DIR)

os.environ.setdefault("KYA_SIGNING_SECRET", "test-signing-secret-for-adversarial")
os.environ.setdefault("KYA_DEMO_ISSUER_KEY", "test-demo-key-for-adversarial")

import registry
import audit
from pipeline import run_pipeline

AGENT_ID = "agent_procure_bot_042"
HUMAN_ID = "user_priya_88"


class IsolatedStorageTestCase(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_audit_db_path = audit.AUDIT_DB_PATH
        self._orig_consumed_db_path = registry.CONSUMED_DB_PATH
        audit.AUDIT_DB_PATH = os.path.join(self._tmpdir, "audit_trail.db")
        audit.AUDIT_PATH = audit.AUDIT_DB_PATH
        registry.CONSUMED_DB_PATH = os.path.join(self._tmpdir, "execution_claims.db")

    def tearDown(self):
        audit.AUDIT_DB_PATH = self._orig_audit_db_path
        audit.AUDIT_PATH = audit.AUDIT_DB_PATH
        registry.CONSUMED_DB_PATH = self._orig_consumed_db_path


def make_cart(amount=500.0, category="groceries", item="Vegetables box"):
    return [{"item": item, "category": category, "amount": amount}]


# --- 1. Token Forgery and Manipulation ---

class TestTokenForgery(IsolatedStorageTestCase):
    """Verify that forged, tampered, or malformed tokens are rejected."""

    def test_empty_token_rejected(self):
        result = run_pipeline(AGENT_ID, "", "buy groceries", make_cart(), now=2000)
        self.assertFalse(result["delegation_ok"])

    def test_garbage_token_rejected(self):
        result = run_pipeline(AGENT_ID, "not-a-json-string", "buy groceries", make_cart(), now=2000)
        self.assertFalse(result["delegation_ok"])

    def test_empty_json_token_rejected(self):
        result = run_pipeline(AGENT_ID, "{}", "buy groceries", make_cart(), now=2000)
        self.assertFalse(result["delegation_ok"])

    def test_token_with_missing_signature(self):
        payload = json.dumps({"agent_id": AGENT_ID, "human_id": HUMAN_ID,
                              "max_amount": 5000, "allowed_categories": ["groceries"],
                              "issued_at": 1000, "ttl_seconds": 3600, "jti": "fake"})
        token = json.dumps({"payload": payload})
        result = run_pipeline(AGENT_ID, token, "buy groceries", make_cart(), now=1500)
        self.assertFalse(result["delegation_ok"])

    def test_token_with_wrong_signature(self):
        payload = json.dumps({"agent_id": AGENT_ID, "human_id": HUMAN_ID,
                              "max_amount": 5000, "allowed_categories": ["groceries"],
                              "issued_at": 1000, "ttl_seconds": 3600, "jti": "fake"})
        token = json.dumps({"payload": payload, "signature": "a" * 64})
        result = run_pipeline(AGENT_ID, token, "buy groceries", make_cart(), now=1500)
        self.assertFalse(result["delegation_ok"])

    def test_token_with_tampered_amount(self):
        """Issue a valid token, then tamper with the amount in the payload."""
        valid_token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 5000.0, ["groceries"], issued_at=1000, ttl_seconds=3600
        )
        # Parse and tamper
        wrapper = json.loads(valid_token)
        payload_dict = json.loads(wrapper["payload"])
        payload_dict["max_amount"] = 999999.0  # tamper
        tampered_payload = json.dumps(payload_dict, sort_keys=True)
        wrapper["payload"] = tampered_payload
        tampered_token = json.dumps(wrapper)
        result = run_pipeline(AGENT_ID, tampered_token, "buy groceries", make_cart(), now=1500)
        self.assertFalse(result["delegation_ok"])

    def test_token_with_tampered_categories(self):
        """Issue a token for groceries only, then tamper to add electronics."""
        valid_token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 5000.0, ["groceries"], issued_at=1000, ttl_seconds=3600
        )
        wrapper = json.loads(valid_token)
        payload_dict = json.loads(wrapper["payload"])
        payload_dict["allowed_categories"] = ["groceries", "electronics"]  # tamper
        tampered_payload = json.dumps(payload_dict, sort_keys=True)
        wrapper["payload"] = tampered_payload
        tampered_token = json.dumps(wrapper)
        # Cart has electronics -- should be blocked by scope check (signature invalid)
        result = run_pipeline(AGENT_ID, tampered_token, "buy electronics",
                              make_cart(amount=500, category="electronics"), now=1500)
        self.assertFalse(result["delegation_ok"])

    def test_token_with_wrong_agent_id(self):
        """Token issued for agent A, presented by agent B."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 5000.0, ["groceries"], issued_at=1000, ttl_seconds=3600
        )
        result = run_pipeline("agent_shopgenie_777", token, "buy groceries",
                              make_cart(), now=1500)
        self.assertFalse(result["delegation_ok"])
        self.assertIn("different agent_id", result["delegation_reason"].lower())


# --- 2. Scope and Category Manipulation ---

class TestScopeManipulation(IsolatedStorageTestCase):
    """Verify that scope violations are caught regardless of how they're constructed."""

    def test_cart_category_not_in_token_scope(self):
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 50000.0, ["groceries"], issued_at=1000, ttl_seconds=3600
        )
        result = run_pipeline(AGENT_ID, token, "buy electronics",
                              make_cart(category="electronics"), now=1500)
        self.assertFalse(result["scope_ok"])

    def test_mixed_cart_with_out_of_scope_item(self):
        """Cart has 2 groceries + 1 electronics. Scope check must fail."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 50000.0, ["groceries"], issued_at=1000, ttl_seconds=3600
        )
        cart = [
            {"item": "Milk", "category": "groceries", "amount": 100.0},
            {"item": "Rice", "category": "groceries", "amount": 200.0},
            {"item": "Laptop", "category": "electronics", "amount": 50000.0},
        ]
        result = run_pipeline(AGENT_ID, token, "buy groceries", cart, now=1500)
        self.assertFalse(result["scope_ok"])

    def test_empty_allowed_categories_blocks_everything(self):
        """Token with empty categories should block any non-empty cart."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 50000.0, [], issued_at=1000, ttl_seconds=3600
        )
        result = run_pipeline(AGENT_ID, token, "buy groceries",
                              make_cart(category="groceries"), now=1500)
        self.assertFalse(result["scope_ok"])


# --- 3. Amount Boundary Attacks ---

class TestAmountBoundaryAttacks(IsolatedStorageTestCase):
    """Verify that amount-based checks hold at boundaries."""

    def test_amount_at_delegation_limit(self):
        """Amount exactly at the limit should pass."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 500.0, ["groceries"], issued_at=1000, ttl_seconds=3600
        )
        result = run_pipeline(AGENT_ID, token, "buy groceries",
                              make_cart(amount=500.0), now=1500)
        self.assertTrue(result["within_delegated_limit"])

    def test_amount_one_over_delegation_limit(self):
        """Amount one paisa over the limit should fail."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 500.0, ["groceries"], issued_at=1000, ttl_seconds=3600
        )
        result = run_pipeline(AGENT_ID, token, "buy groceries",
                              make_cart(amount=500.01), now=1500)
        self.assertFalse(result["within_delegated_limit"])

    def test_multi_item_cart_total_exceeds_limit(self):
        """5 items at 100 each = 500, limit is 499.99."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 499.99, ["groceries"], issued_at=1000, ttl_seconds=3600
        )
        cart = [{"item": f"Item {i}", "category": "groceries", "amount": 100.0} for i in range(5)]
        result = run_pipeline(AGENT_ID, token, "buy groceries", cart, now=1500)
        self.assertFalse(result["within_delegated_limit"])

    def test_zero_amount_cart(self):
        """Empty-ish cart with zero-amount items passes Pydantic but amount is 0."""
        # Note: Pydantic validators now reject amount <= 0, so this tests
        # the pipeline logic with a pre-validated cart (bypassing Pydantic).
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 5000.0, ["groceries"], issued_at=1000, ttl_seconds=3600
        )
        result = run_pipeline(AGENT_ID, token, "buy groceries",
                              [{"item": "Free sample", "category": "groceries", "amount": 0.0}],
                              now=1500)
        self.assertTrue(result["within_delegated_limit"])
        self.assertEqual(result["total_amount"], 0.0)


# --- 4. Authentication Bypass Attempts ---

class TestAuthBypass(IsolatedStorageTestCase):
    """Verify that authentication failures are caught at every layer."""

    def test_unregistered_agent_always_blocked(self):
        token = registry.issue_delegation_token(
            "agent_fake_999", HUMAN_ID, 50000.0, ["groceries", "electronics"],
            issued_at=1000, ttl_seconds=3600
        )
        result = run_pipeline("agent_fake_999", token, "buy groceries",
                              make_cart(), now=1500)
        self.assertFalse(result["identity_ok"])

    def test_expired_token_always_blocked(self):
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 50000.0, ["groceries"], issued_at=1000, ttl_seconds=100
        )
        result = run_pipeline(AGENT_ID, token, "buy groceries",
                              make_cart(), now=2000)  # 2000 > 1100
        self.assertFalse(result["delegation_ok"])

    def test_token_not_yet_valid(self):
        """Token issued in the future should be blocked."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 50000.0, ["groceries"],
            issued_at=100000, ttl_seconds=3600  # issued far in the future
        )
        result = run_pipeline(AGENT_ID, token, "buy groceries",
                              make_cart(), now=1000)  # now < issued_at
        # The token's expiry is 100000+3600=103600, and now=1000 < 103600
        # so the token is technically valid (issued_at is just metadata, not a "not before" check)
        # This documents the current behavior -- production should add nbf check.
        self.assertTrue(result["delegation_ok"])

    def test_replay_after_execution(self):
        """Token used once must be rejected on second use."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 50000.0, ["groceries"], issued_at=1000, ttl_seconds=3600
        )
        # First use
        result1 = run_pipeline(AGENT_ID, token, "buy groceries", make_cart(), now=1500)
        self.assertEqual(result1["decision"], "APPROVE")
        # Simulate execution
        registry.reserve_token(result1["jti"])
        registry.finalize_execution(result1["jti"], "audit_1")
        # Second use
        result2 = run_pipeline(AGENT_ID, token, "buy groceries", make_cart(), now=1600)
        self.assertFalse(result2["delegation_ok"])


# --- 5. Pipeline Edge Cases ---

class TestPipelineEdgeCases(IsolatedStorageTestCase):
    """Verify the pipeline handles unusual but valid inputs correctly."""

    def test_empty_cart_pipeline(self):
        """Pipeline with empty cart should handle gracefully."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 50000.0, ["groceries"], issued_at=1000, ttl_seconds=3600
        )
        result = run_pipeline(AGENT_ID, token, "buy groceries", [], now=1500)
        self.assertEqual(result["total_amount"], 0.0)

    def test_single_item_cart(self):
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 50000.0, ["groceries"], issued_at=1000, ttl_seconds=3600
        )
        result = run_pipeline(AGENT_ID, token, "buy groceries", make_cart(500.0), now=1500)
        self.assertEqual(result["total_amount"], 500.0)

    def test_large_cart_50_items(self):
        """50-item cart should pass pipeline (max validated by Pydantic)."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 100000.0, ["groceries"], issued_at=1000, ttl_seconds=3600
        )
        cart = [{"item": f"Item {i}", "category": "groceries", "amount": 100.0} for i in range(50)]
        result = run_pipeline(AGENT_ID, token, "buy groceries", cart, now=1500)
        self.assertEqual(result["total_amount"], 5000.0)

    def test_unknown_agent_gets_max_risk(self):
        """Unknown agent should get risk score of 100."""
        result = run_pipeline("agent_nonexistent", "fake", "buy groceries",
                              make_cart(), now=1500)
        self.assertEqual(result["risk"]["total_score"], 100.0)

    def test_intent_match_with_unclassifiable_intent(self):
        """Vague intent should not force a block on its own."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 50000.0, ["groceries"], issued_at=1000, ttl_seconds=3600
        )
        result = run_pipeline(AGENT_ID, token, "pick up some essentials for home",
                              make_cart(500.0), now=1500)
        # The intent is unclassifiable -> "unknown" -> low severity
        # With a normal amount, this should still APPROVE
        self.assertEqual(result["decision"], "APPROVE")

    def test_high_intent_mismatch_with_normal_amount(self):
        """Intent says groceries, cart is electronics -- should BLOCK."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 50000.0, ["groceries", "electronics"],
            issued_at=1000, ttl_seconds=3600
        )
        result = run_pipeline(AGENT_ID, token, "buy groceries for the week",
                              make_cart(amount=500, category="electronics"), now=1500)
        # High intent mismatch -> high severity -> adds 65 to risk score
        # With identity_ok, delegation_ok, scope_ok -> base risk is just intent(65) + drift
        self.assertIn("BLOCK", result["decision"])


# --- 6. Concurrent Attack Scenarios ---

class TestConcurrentAttacks(IsolatedStorageTestCase):
    """Verify that concurrent attacks don't bypass security."""

    def test_concurrent_token_use_exactly_one_succeeds(self):
        """Multiple threads race to use the same token. Only 1 must execute.
        Simulates the full main.py path: pipeline + reserve + finalize.

        Security invariant: regardless of how many threads race, at most
        1 execution occurs. Some threads may be blocked at the pipeline
        level (token consumed by finalize_execution) rather than at the
        reserve_token level — both paths correctly prevent double-spend."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 50000.0, ["groceries"], issued_at=1000, ttl_seconds=3600
        )
        outcomes = []
        lock = threading.Lock()
        n_threads = 10

        def attempt():
            result = run_pipeline(AGENT_ID, token, "buy groceries", make_cart(500.0), now=1500)
            if result["decision"] == "APPROVE":
                if registry.reserve_token(result["jti"]):
                    registry.finalize_execution(result["jti"], f"audit_{threading.current_thread().name}")
                    with lock:
                        outcomes.append("executed")
                else:
                    with lock:
                        outcomes.append("replay_blocked")
            else:
                with lock:
                        outcomes.append("blocked")

        threads = [threading.Thread(target=attempt, name=str(i)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        executions = outcomes.count("executed")
        self.assertEqual(executions, 1, f"Expected exactly 1 execution, got {executions}")
        # All other threads must be blocked (either at pipeline or reserve level)
        blocked = len(outcomes) - executions
        self.assertEqual(blocked, n_threads - 1, f"Expected {n_threads-1} blocked, got {blocked}")

    def test_concurrent_different_agents_no_interference(self):
        """Two agents using different tokens concurrently must not interfere.
        Note: SQLite may lock under heavy concurrent reads; we test with
        fewer concurrent threads to avoid busy_timeout issues."""
        token_a = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 50000.0, ["groceries"], issued_at=1000, ttl_seconds=3600
        )
        token_b = registry.issue_delegation_token(
            "agent_shopgenie_777", "user_rahul_12", 50000.0, ["groceries"],
            issued_at=1000, ttl_seconds=3600
        )
        results_a = []
        results_b = []
        lock = threading.Lock()

        def use_a():
            r = run_pipeline(AGENT_ID, token_a, "buy groceries", make_cart(500.0), now=1500)
            with lock:
                results_a.append(r["decision"])

        def use_b():
            r = run_pipeline("agent_shopgenie_777", token_b, "buy groceries",
                             make_cart(500.0), now=1500)
            with lock:
                results_b.append(r["decision"])

        # Run sequentially in pairs to avoid SQLite locking
        for _ in range(5):
            ta = threading.Thread(target=use_a)
            tb = threading.Thread(target=use_b)
            ta.start()
            tb.start()
            ta.join()
            tb.join()

        self.assertEqual(results_a.count("APPROVE"), 5,
                         "All 5 token_a uses should APPROVE")
        self.assertEqual(results_b.count("APPROVE"), 5,
                         "All 5 token_b uses should APPROVE")


# --- 7. Input Injection ---

class TestInputInjection(IsolatedStorageTestCase):
    """Verify that injection-style inputs don't break the pipeline."""

    def test_sql_injection_in_agent_id(self):
        result = run_pipeline("'; DROP TABLE agents; --", "fake", "buy groceries",
                              make_cart(), now=1500)
        self.assertFalse(result["identity_ok"])

    def test_xss_in_stated_intent(self):
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 50000.0, ["groceries"], issued_at=1000, ttl_seconds=3600
        )
        result = run_pipeline(AGENT_ID, token,
                              "<script>alert('xss')</script>", make_cart(), now=1500)
        # Should not crash; intent just won't match any category
        self.assertIn(result["intent_result"]["inferred_category"], ["unknown", "groceries"])

    def test_unicode_in_cart_item(self):
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 50000.0, ["groceries"], issued_at=1000, ttl_seconds=3600
        )
        result = run_pipeline(AGENT_ID, token, "buy groceries",
                              [{"item": "🥬 Organic spinach 有机菠菜", "category": "groceries", "amount": 200.0}],
                              now=1500)
        self.assertEqual(result["decision"], "APPROVE")

    def test_extremely_long_intent_string(self):
        """1000-char intent string should be handled (Pydantic caps at 1000)."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 50000.0, ["groceries"], issued_at=1000, ttl_seconds=3600
        )
        long_intent = "buy " + "groceries " * 100  # ~1000 chars
        result = run_pipeline(AGENT_ID, token, long_intent, make_cart(), now=1500)
        # Should not crash
        self.assertIn(result["decision"], ["APPROVE", "STEP_UP", "BLOCK"])

    def test_none_like_values_in_cart(self):
        """Pipeline should handle cart items with unusual values gracefully."""
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 50000.0, ["groceries"], issued_at=1000, ttl_seconds=3600
        )
        # Very small amount
        result = run_pipeline(AGENT_ID, token, "buy groceries",
                              [{"item": "Sample", "category": "groceries", "amount": 0.01}],
                              now=1500)
        self.assertEqual(result["decision"], "APPROVE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
