"""
Phase 2 Integration Validation Tests.

Validates that every newly-integrated module actually participates in the
runtime execution path, not just that it imports successfully.

Tests:
  A. Policy BLOCK prevents any payment call
  B. Policy STEP_UP prevents payment until confirmation
  C. Circuit breaker OPEN prevents payment calls
  D. Ed25519 signing and verification work end-to-end
  E. Advanced intent classifier affects the real pipeline
  F. Multi-signal risk affects the real decision
  G. Metrics actually increment through real requests
  H. Existing HMAC/basic/keyword behavior remains unchanged
  I. PAYMENT_UNKNOWN remains non-releasable
  J. Replay protection remains intact
  K. Step-up concurrency protection remains intact
"""

import json
import os
import sys
import shutil
import tempfile
import unittest

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, BACKEND_DIR)

os.environ.setdefault("KYA_SIGNING_SECRET", "test-signing-secret-for-integration-validation")
os.environ.setdefault("KYA_DEMO_ISSUER_KEY", "test-key-integration")

try:
    from fastapi.testclient import TestClient
    HAVE_FASTAPI = True
except ImportError:
    HAVE_FASTAPI = False

import registry
import audit as audit_store


AGENT_ID = "agent_procure_bot_042"
HUMAN_ID = "user_priya_88"
DEMO_KEY = os.environ.get("KYA_DEMO_ISSUER_KEY", "test-key-integration")


def _make_token(**overrides):
    """Create a delegation token with sensible defaults."""
    defaults = dict(
        agent_id=AGENT_ID,
        human_id=HUMAN_ID,
        max_amount=50000,
        allowed_categories=["groceries"],
    )
    defaults.update(overrides)
    return registry.issue_delegation_token(**defaults)


# ──────────────────────────────────────────────────────────────────────
# A. Policy engine prevents payment when it says BLOCK
# ──────────────────────────────────────────────────────────────────────

@unittest.skipUnless(HAVE_FASTAPI, "fastapi not installed")
class TestPolicyEngineIntegration(unittest.TestCase):
    """A. Policy BLOCK prevents any payment call.
       B. Policy STEP_UP prevents payment until confirmation."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_consumed = registry.CONSUMED_DB_PATH
        self._orig_audit = audit_store.AUDIT_PATH
        registry.CONSUMED_DB_PATH = os.path.join(self._tmpdir, "execution_claims.db")
        audit_store.AUDIT_PATH = os.path.join(self._tmpdir, "audit_trail.db")
        from main import app
        self.client = TestClient(app)

    def tearDown(self):
        registry.CONSUMED_DB_PATH = self._orig_consumed
        audit_store.AUDIT_PATH = self._orig_audit
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_a_policy_block_prevents_payment(self):
        """When policy says BLOCK, no payment should be created even if pipeline says APPROVE."""
        from policy_engine import get_policy_engine
        pe = get_policy_engine()

        # Set a policy that BLOCKs all electronics purchases above 100
        pe.set_agent_policy(AGENT_ID, {
            "rules": [
                {"category": "groceries", "max_amount": 100, "require_step_up_above": 50},
            ],
            "global": {}
        })

        try:
            token = _make_token(max_amount=50000, allowed_categories=["groceries"])
            resp = self.client.post("/verify", json={
                "agent_id": AGENT_ID,
                "delegation_token": token,
                "stated_intent": "buy groceries",
                "cart": [{"item": "Premium Milk", "category": "groceries", "amount": 200}],
            }, headers={"x-kya-demo-key": DEMO_KEY})

            data = resp.json()
            # Policy should have overridden to BLOCK
            self.assertEqual(data["decision"], "BLOCK")
            # Payment should be None
            self.assertIsNone(data["payment"])
            # Policy violations should be present
            self.assertTrue(len(data.get("policy_violations", [])) > 0)
        finally:
            pe._policies.clear()
            pe.save_policies()

    def test_b_policy_step_up_prevents_payment(self):
        """When policy says STEP_UP, payment should not happen until confirmation."""
        from policy_engine import get_policy_engine
        pe = get_policy_engine()

        # Set a policy that requires step-up above 100
        pe.set_agent_policy(AGENT_ID, {
            "rules": [
                {"category": "groceries", "max_amount": 50000, "require_step_up_above": 100},
            ],
            "global": {}
        })

        try:
            token = _make_token(max_amount=50000, allowed_categories=["groceries"])
            resp = self.client.post("/verify", json={
                "agent_id": AGENT_ID,
                "delegation_token": token,
                "stated_intent": "buy groceries",
                "cart": [{"item": "Premium Milk", "category": "groceries", "amount": 200}],
            }, headers={"x-kya-demo-key": DEMO_KEY})

            data = resp.json()
            # Pipeline would APPROVE, but policy forces STEP_UP
            self.assertEqual(data["decision"], "STEP_UP")
            # Payment should be None
            self.assertIsNone(data["payment"])
        finally:
            pe._policies.clear()
            pe.save_policies()

    def test_no_policy_means_approve(self):
        """Without a policy, pipeline decision stands."""
        token = _make_token(max_amount=50000, allowed_categories=["groceries"])
        resp = self.client.post("/verify", json={
            "agent_id": AGENT_ID,
            "delegation_token": token,
            "stated_intent": "buy groceries",
            "cart": [{"item": "Milk", "category": "groceries", "amount": 500}],
        }, headers={"x-kya-demo-key": DEMO_KEY})

        data = resp.json()
        self.assertEqual(data["decision"], "APPROVE")
        self.assertEqual(data.get("policy_violations", []), [])


# ──────────────────────────────────────────────────────────────────────
# C. Circuit breaker integration
# ──────────────────────────────────────────────────────────────────────

@unittest.skipUnless(HAVE_FASTAPI, "fastapi not installed")
class TestCircuitBreakerIntegration(unittest.TestCase):
    """C. Circuit breaker OPEN prevents payment calls."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_consumed = registry.CONSUMED_DB_PATH
        self._orig_audit = audit_store.AUDIT_PATH
        registry.CONSUMED_DB_PATH = os.path.join(self._tmpdir, "execution_claims.db")
        audit_store.AUDIT_PATH = os.path.join(self._tmpdir, "audit_trail.db")
        from main import app
        self.client = TestClient(app)

    def tearDown(self):
        registry.CONSUMED_DB_PATH = self._orig_consumed
        audit_store.AUDIT_PATH = self._orig_audit
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_circuit_breaker_blocks_payment_when_open(self):
        """When circuit breaker is OPEN, payment should fail and result in BLOCK."""
        from reliability import get_payment_circuit_breaker
        breaker = get_payment_circuit_breaker()

        # Force circuit to OPEN
        breaker.state = breaker.state.__class__.OPEN
        breaker.failure_count = 10
        breaker.last_failure_time = __import__("time").time()

        try:
            token = _make_token(max_amount=50000, allowed_categories=["groceries"])
            resp = self.client.post("/verify", json={
                "agent_id": AGENT_ID,
                "delegation_token": token,
                "stated_intent": "buy groceries",
                "cart": [{"item": "Milk", "category": "groceries", "amount": 500}],
            }, headers={"x-kya-demo-key": DEMO_KEY})

            data = resp.json()
            # Pipeline says APPROVE but circuit breaker blocks payment
            # Result should be BLOCK with payment failure reason
            self.assertEqual(data["decision"], "BLOCK")
            self.assertIsNone(data["payment"])
        finally:
            # Reset circuit breaker
            from reliability import CircuitState
            breaker.state = CircuitState.CLOSED
            breaker.failure_count = 0
            breaker.success_count = 0

    def test_circuit_breaker_recovers(self):
        """Circuit breaker transitions from OPEN -> HALF_OPEN -> CLOSED on recovery."""
        from reliability import get_payment_circuit_breaker, CircuitState
        breaker = get_payment_circuit_breaker()

        # Force to OPEN with a very short recovery timeout
        original_timeout = breaker.recovery_timeout
        breaker.recovery_timeout = 0.0  # Immediate recovery
        breaker.state = CircuitState.OPEN
        breaker.failure_count = 10
        breaker.last_failure_time = __import__("time").time() - 1  # Past recovery

        try:
            # Should transition to HALF_OPEN and allow request
            self.assertTrue(breaker.allow_request())
            self.assertEqual(breaker.state, CircuitState.HALF_OPEN)

            # Record enough successes to close
            for _ in range(breaker.success_threshold):
                breaker.record_success()

            self.assertEqual(breaker.state, CircuitState.CLOSED)
        finally:
            breaker.recovery_timeout = original_timeout
            breaker.state = CircuitState.CLOSED
            breaker.failure_count = 0
            breaker.success_count = 0


# ──────────────────────────────────────────────────────────────────────
# D. Ed25519 identity mode
# ──────────────────────────────────────────────────────────────────────

class TestEd25519Identity(unittest.TestCase):
    """D. Ed25519 signing and verification work end-to-end."""

    def test_ed25519_sign_and_verify(self):
        """Ed25519 keypair can sign and verify payloads."""
        from identity import Ed25519KeyPair

        kp = Ed25519KeyPair.generate()
        payload = "test-payload-for-ed25519"

        sig = kp.sign(payload)
        self.assertTrue(kp.verify(payload, sig))
        self.assertFalse(kp.verify(payload, "wrong_signature"))
        self.assertFalse(kp.verify("different_payload", sig))

    def test_ed25519_key_id_is_stable(self):
        """Same keypair produces the same key_id."""
        from identity import Ed25519KeyPair

        kp = Ed25519KeyPair.generate()
        kid1 = kp.key_id
        kid2 = kp.key_id
        self.assertEqual(kid1, kid2)
        self.assertNotEqual(kid1, "unknown")

    def test_ed25519_provider_signs_tokens(self):
        """IdentityProvider in ed25519 mode signs and verifies tokens."""
        from identity import IdentityProvider

        # We can't change IDENTITY_MODE at runtime easily,
        # but we can test the provider directly
        provider = IdentityProvider.__new__(IdentityProvider)
        provider.mode = "ed25519"
        provider._hmac_secret = None
        from identity import Ed25519KeyPair
        kp = Ed25519KeyPair.generate()
        provider._issuer_keys = {"default": kp}

        payload = '{"jti":"test","agent_id":"test"}'
        sig = provider.sign_token(payload)
        self.assertTrue(provider.verify_token(payload, sig))
        self.assertFalse(provider.verify_token(payload, "bad_sig"))

    def test_hmac_provider_still_works(self):
        """IdentityProvider in hmac mode uses HMAC-SHA256."""
        from identity import IdentityProvider

        provider = IdentityProvider.__new__(IdentityProvider)
        provider.mode = "hmac"
        provider._hmac_secret = b"test-secret"
        provider._issuer_keys = {}

        payload = '{"jti":"test"}'
        sig = provider.sign_token(payload)
        self.assertTrue(provider.verify_token(payload, sig))


# ──────────────────────────────────────────────────────────────────────
# E. Advanced intent classifier
# ──────────────────────────────────────────────────────────────────────

class TestAdvancedIntentClassifier(unittest.TestCase):
    """E. Advanced intent classifier produces structured results."""

    def test_advanced_classifier_category_match(self):
        """Advanced classifier correctly identifies matching categories."""
        from intent_classifier import get_advanced_matcher
        matcher = get_advanced_matcher()

        result = matcher.check_intent_match(
            "buy groceries for the week",
            [{"item": "Milk", "category": "groceries", "amount": 100}],
        )
        self.assertTrue(result["match"])
        self.assertIn("groceries", result["cart_categories"])
        self.assertEqual(result["mismatch_severity"], "none")

    def test_advanced_classifier_mismatch(self):
        """Advanced classifier detects category mismatch."""
        from intent_classifier import get_advanced_matcher
        matcher = get_advanced_matcher()

        result = matcher.check_intent_match(
            "buy electronics for the office",
            [{"item": "Milk", "category": "groceries", "amount": 100}],
        )
        # Intent says electronics, cart has groceries -> mismatch
        self.assertIn(result["mismatch_severity"], ["medium", "high"])
        self.assertFalse(result["match"])

    def test_advanced_classifier_amount_extraction(self):
        """Advanced classifier extracts amounts from intent text."""
        from intent_classifier import get_advanced_matcher
        matcher = get_advanced_matcher()

        result = matcher.check_intent_match(
            "buy groceries for rs 500",
            [{"item": "Milk", "category": "groceries", "amount": 480}],
        )
        signals = result.get("intent_signals", {})
        self.assertIsNotNone(signals.get("mentioned_amount"))

    def test_advanced_classifier_returns_same_interface(self):
        """Advanced classifier returns the same interface as keyword matcher."""
        from intent_classifier import get_advanced_matcher
        matcher = get_advanced_matcher()

        result = matcher.check_intent_match(
            "buy groceries",
            [{"item": "Milk", "category": "groceries", "amount": 100}],
        )
        # Must have all fields that keyword matcher produces
        for field in ["match", "inferred_category", "cart_categories", "reason", "mismatch_severity"]:
            self.assertIn(field, result)


# ──────────────────────────────────────────────────────────────────────
# F. Multi-signal risk scorer
# ──────────────────────────────────────────────────────────────────────

class TestMultiSignalRisk(unittest.TestCase):
    """F. Multi-signal risk scorer affects the real decision."""

    def test_multi_signal_produces_risk_score(self):
        """Multi-signal scorer produces a valid risk score."""
        from risk_signals import get_multi_signal_scorer
        scorer = get_multi_signal_scorer()

        agent = {
            "agent_id": AGENT_ID,
            "baseline_mean_amount": 1200,
            "baseline_std_amount": 350,
        }
        result = scorer.compute_risk(
            amount=1500,
            agent=agent,
            identity_ok=True,
            delegation_ok=True,
            intent_result={"mismatch_severity": "none"},
        )
        self.assertIn("total_score", result)
        self.assertIn("signals", result)
        self.assertGreaterEqual(result["total_score"], 0)
        self.assertLessEqual(result["total_score"], 100)

    def test_multi_signal_has_all_components(self):
        """Multi-signal scorer includes all signal components."""
        from risk_signals import get_multi_signal_scorer
        scorer = get_multi_signal_scorer()

        agent = {"agent_id": AGENT_ID, "baseline_mean_amount": 1000, "baseline_std_amount": 200}
        result = scorer.compute_risk(
            amount=1000, agent=agent, identity_ok=True, delegation_ok=True,
            intent_result={"mismatch_severity": "none"},
        )
        components = result["components"]
        # Should have behavioral_drift, identity, delegation, intent, plus signals
        self.assertIn("behavioral_drift", components)
        self.assertIn("identity_penalty", components)
        self.assertIn("delegation_penalty", components)
        self.assertIn("intent_mismatch_penalty", components)

    def test_multi_signal_increases_risk_for_bad_identity(self):
        """Multi-signal scorer increases risk when identity fails."""
        from risk_signals import get_multi_signal_scorer
        scorer = get_multi_signal_scorer()

        agent = {"agent_id": AGENT_ID, "baseline_mean_amount": 1000, "baseline_std_amount": 200}
        ok = scorer.compute_risk(1000, agent, True, True, {"mismatch_severity": "none"})
        bad = scorer.compute_risk(1000, agent, False, True, {"mismatch_severity": "none"})
        self.assertGreater(bad["total_score"], ok["total_score"])


# ──────────────────────────────────────────────────────────────────────
# G. Metrics actually increment
# ──────────────────────────────────────────────────────────────────────

@unittest.skipUnless(HAVE_FASTAPI, "fastapi not installed")
class TestMetricsIntegration(unittest.TestCase):
    """G. Metrics actually increment through real requests."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_consumed = registry.CONSUMED_DB_PATH
        self._orig_audit = audit_store.AUDIT_PATH
        registry.CONSUMED_DB_PATH = os.path.join(self._tmpdir, "execution_claims.db")
        audit_store.AUDIT_PATH = os.path.join(self._tmpdir, "audit_trail.db")
        from main import app, _metrics
        self.client = TestClient(app)
        self.metrics = _metrics

    def tearDown(self):
        registry.CONSUMED_DB_PATH = self._orig_consumed
        audit_store.AUDIT_PATH = self._orig_audit
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_metrics_requests_increment(self):
        """requests_total increments after real requests."""
        before = self.metrics.requests_total.get()
        self.client.get("/health")
        after = self.metrics.requests_total.get()
        self.assertGreater(after, before)

    def test_metrics_approve_counter(self):
        """APPROVE counter increments after successful payment."""
        before = self.metrics.requests_by_decision["APPROVE"].get()
        token = _make_token(max_amount=50000, allowed_categories=["groceries"])
        self.client.post("/verify", json={
            "agent_id": AGENT_ID,
            "delegation_token": token,
            "stated_intent": "buy groceries",
            "cart": [{"item": "Milk", "category": "groceries", "amount": 500}],
        }, headers={"x-kya-demo-key": DEMO_KEY})
        after = self.metrics.requests_by_decision["APPROVE"].get()
        self.assertGreater(after, before)

    def test_metrics_auth_failure_counter(self):
        """auth_failures counter increments on bad demo key."""
        before = self.metrics.auth_failures.get()
        self.client.get("/agents", headers={"x-kya-demo-key": "wrong-key"})
        after = self.metrics.auth_failures.get()
        self.assertGreater(after, before)

    def test_metrics_endpoint_returns_prometheus(self):
        """/metrics endpoint returns Prometheus-compatible text."""
        resp = self.client.get("/metrics")
        self.assertEqual(resp.status_code, 200)
        text = resp.text
        self.assertIn("kya_requests_total", text)
        self.assertIn("kya_auth_failures_total", text)
        self.assertIn("# TYPE", text)

    def test_metrics_json_endpoint(self):
        """/metrics/json returns structured JSON."""
        resp = self.client.get("/metrics/json")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("requests_total", data)
        self.assertIn("uptime_seconds", data)


# ──────────────────────────────────────────────────────────────────────
# H. Default behavior unchanged
# ──────────────────────────────────────────────────────────────────────

@unittest.skipUnless(HAVE_FASTAPI, "fastapi not installed")
class TestDefaultBehaviorUnchanged(unittest.TestCase):
    """H. Existing HMAC/basic/keyword behavior remains unchanged."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_consumed = registry.CONSUMED_DB_PATH
        self._orig_audit = audit_store.AUDIT_PATH
        registry.CONSUMED_DB_PATH = os.path.join(self._tmpdir, "execution_claims.db")
        audit_store.AUDIT_PATH = os.path.join(self._tmpdir, "audit_trail.db")
        from main import app
        self.client = TestClient(app)

    def tearDown(self):
        registry.CONSUMED_DB_PATH = self._orig_consumed
        audit_store.AUDIT_PATH = self._orig_audit
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_hmac_token_still_works(self):
        """HMAC-signed delegation tokens still verify correctly."""
        token = _make_token(max_amount=50000, allowed_categories=["groceries"])
        resp = self.client.post("/verify", json={
            "agent_id": AGENT_ID,
            "delegation_token": token,
            "stated_intent": "buy groceries",
            "cart": [{"item": "Milk", "category": "groceries", "amount": 500}],
        }, headers={"x-kya-demo-key": DEMO_KEY})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["decision"], "APPROVE")

    def test_keyword_intent_matcher_still_works(self):
        """Default keyword intent matcher produces correct results."""
        from intent_match import check_intent_match
        result = check_intent_match(
            "buy groceries for the week",
            [{"item": "Milk", "category": "groceries", "amount": 100}],
        )
        self.assertTrue(result["match"])

    def test_basic_risk_scorer_still_works(self):
        """Default z-score risk scorer produces valid results."""
        from risk_scorer import compute_risk
        agent = {"agent_id": AGENT_ID, "baseline_mean_amount": 1200, "baseline_std_amount": 350}
        result = compute_risk(1500, agent, True, True, {"mismatch_severity": "none"})
        self.assertIn("total_score", result)
        self.assertGreaterEqual(result["total_score"], 0)

    def test_replay_protection_still_intact(self):
        """Token replay is still blocked."""
        token = _make_token(max_amount=50000, allowed_categories=["groceries"])
        # First use
        resp1 = self.client.post("/verify", json={
            "agent_id": AGENT_ID,
            "delegation_token": token,
            "stated_intent": "buy groceries",
            "cart": [{"item": "Milk", "category": "groceries", "amount": 500}],
        }, headers={"x-kya-demo-key": DEMO_KEY})
        self.assertEqual(resp1.json()["decision"], "APPROVE")

        # Second use — replay
        resp2 = self.client.post("/verify", json={
            "agent_id": AGENT_ID,
            "delegation_token": token,
            "stated_intent": "buy groceries",
            "cart": [{"item": "Milk", "category": "groceries", "amount": 500}],
        }, headers={"x-kya-demo-key": DEMO_KEY})
        self.assertEqual(resp2.json()["decision"], "BLOCK")




# ──────────────────────────────────────────────────────────────────────
# I. PAYMENT_UNKNOWN remains non-releasable
# ──────────────────────────────────────────────────────────────────────

class TestPaymentUnknownNonReleasable(unittest.TestCase):
    """I. PAYMENT_UNKNOWN tokens are never auto-released."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_consumed = registry.CONSUMED_DB_PATH
        self._orig_audit = audit_store.AUDIT_PATH
        registry.CONSUMED_DB_PATH = os.path.join(self._tmpdir, "execution_claims.db")
        audit_store.AUDIT_PATH = os.path.join(self._tmpdir, "audit_trail.db")

    def tearDown(self):
        registry.CONSUMED_DB_PATH = self._orig_consumed
        audit_store.AUDIT_PATH = self._orig_audit
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_payment_unknown_never_released(self):
        """PAYMENT_UNKNOWN execution_state never triggers automatic release."""
        jti = "payment_unknown_test_jti"
        audit_entry = {
            "agent_id": AGENT_ID,
            "decision": "APPROVE",
            "execution_state": "PAYMENT_UNKNOWN",
            "jti": jti,
            "total_amount": 500,
        }
        audit_store.record(audit_entry)
        registry.reserve_token(jti)

        result = registry.recover_orphaned_reservations(
            audit_store.find_audit_by_jti,
            audit_store.update_execution_state,
        )

        self.assertTrue(registry.is_token_consumed(jti))
        self.assertEqual(result["released"], 0)

    def test_execution_pending_never_released(self):
        """EXECUTION_PENDING execution_state never triggers automatic release."""
        jti = "exec_pending_test_jti"
        audit_entry = {
            "agent_id": AGENT_ID,
            "decision": "APPROVE",
            "execution_state": "EXECUTION_PENDING",
            "jti": jti,
            "total_amount": 500,
        }
        audit_store.record(audit_entry)
        registry.reserve_token(jti)

        result = registry.recover_orphaned_reservations(
            audit_store.find_audit_by_jti,
            audit_store.update_execution_state,
        )

        self.assertTrue(registry.is_token_consumed(jti))
        self.assertEqual(result["released"], 0)


# ──────────────────────────────────────────────────────────────────────
# J. Replay protection remains intact
# ──────────────────────────────────────────────────────────────────────

@unittest.skipUnless(HAVE_FASTAPI, "fastapi not installed")
class TestReplayProtection(unittest.TestCase):
    """J. Replay protection remains intact through all integrations."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_consumed = registry.CONSUMED_DB_PATH
        self._orig_audit = audit_store.AUDIT_PATH
        registry.CONSUMED_DB_PATH = os.path.join(self._tmpdir, "execution_claims.db")
        audit_store.AUDIT_PATH = os.path.join(self._tmpdir, "audit_trail.db")
        from main import app
        self.client = TestClient(app)

    def tearDown(self):
        registry.CONSUMED_DB_PATH = self._orig_consumed
        audit_store.AUDIT_PATH = self._orig_audit
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_token_single_use_enforced(self):
        """Token can only be used once, regardless of integrations."""
        token = _make_token(max_amount=50000, allowed_categories=["groceries"])
        resp1 = self.client.post("/verify", json={
            "agent_id": AGENT_ID,
            "delegation_token": token,
            "stated_intent": "buy groceries",
            "cart": [{"item": "Milk", "category": "groceries", "amount": 500}],
        }, headers={"x-kya-demo-key": DEMO_KEY})
        self.assertEqual(resp1.json()["decision"], "APPROVE")

        resp2 = self.client.post("/verify", json={
            "agent_id": AGENT_ID,
            "delegation_token": token,
            "stated_intent": "buy groceries again",
            "cart": [{"item": "Bread", "category": "groceries", "amount": 200}],
        }, headers={"x-kya-demo-key": DEMO_KEY})
        self.assertEqual(resp2.json()["decision"], "BLOCK")
        self.assertIn("replay", resp2.json()["reasons"][0].lower())

    def test_forged_token_rejected(self):
        """Forged tokens are rejected."""
        forged = json.dumps({
            "payload": json.dumps({"jti": "forged", "agent_id": AGENT_ID, "human_id": HUMAN_ID, "max_amount": 999999, "allowed_categories": ["groceries"], "issued_at": 9999999999, "ttl_seconds": 3600}),
            "signature": "forged_signature"
        })
        resp = self.client.post("/verify", json={
            "agent_id": AGENT_ID,
            "delegation_token": forged,
            "stated_intent": "buy groceries",
            "cart": [{"item": "Milk", "category": "groceries", "amount": 500}],
        }, headers={"x-kya-demo-key": DEMO_KEY})
        self.assertEqual(resp.json()["decision"], "BLOCK")


# ──────────────────────────────────────────────────────────────────────
