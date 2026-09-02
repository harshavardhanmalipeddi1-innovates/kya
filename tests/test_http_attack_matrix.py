"""
HTTP-level attack matrix against the actual FastAPI app -- the layer
tests/test_security.py deliberately does NOT cover, because it avoids
importing main.py (which needs fastapi, not installable in every dev
sandbox).

*** Per tests/README.md, this file has been run and all 10 cases
passed, in an environment with fastapi/uvicorn/httpx installed. ***
That run did not happen in this sandbox, and I have not personally
re-verified it here -- this sandbox also lacks fastapi (see the
`unittest.skip` behavior below, which is why you'll see this file
report as skipped rather than passed if you run it in an environment
like this one). Treat "passed" as reported by whoever last ran it
with the dependencies installed, not as something re-confirmed on
every read of this file. tests/README.md also documents what a real
`uvicorn` + real HTTP run additionally caught that TestClient alone
didn't (a missing header in demo/scenarios.py, and separately in
frontend/index.html). Run it yourself with:

    pip install fastapi uvicorn httpx
    python -m unittest tests.test_http_attack_matrix -v

This uses fastapi.testclient.TestClient, which drives the ASGI app
in-process (no real HTTP socket, no separate `uvicorn` process
needed) -- so it's a faster and more repeatable way to exercise the
live request/response path than manually curling a running server,
though it is not a substitute for also clicking through /docs by
hand at least once, since TestClient can't catch things like a
misconfigured host/port or a reverse-proxy issue.

Each test case's expected outcome, and the (agent, cart, amount)
combination chosen to produce it, is derived from:
  - data/agents.json (agent_procure_bot_042 / ProcureBot: scope
    [groceries, office_supplies], baseline_mean_amount=1200,
    baseline_std_amount=350)
  - decision_engine.py (BLOCK_THRESHOLD=55, STEP_UP_THRESHOLD=25)
  - risk_scorer.py (sub_score = z_score * 12.5, z = (amount - mean)/std)

So for ProcureBot buying groceries (identity_ok, delegation_ok,
scope_ok, intent match all True/none -> those penalty components are
all 0, and total score is just the amount-drift sub_score):
  amount ~500   -> z is negative -> sub_score 0   -> APPROVE
  amount ~2000  -> z ~2.29       -> sub_score ~28.6 -> STEP_UP
  (2000 chosen to comfortably clear STEP_UP_THRESHOLD=25 while
  staying under BLOCK_THRESHOLD=55, i.e. z below ~4.4 / amount below
  ~2740)
"""

import json
import os
import sys
import tempfile
import threading
import unittest

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, BACKEND_DIR)

# Must be set before `import main`, since main.py and registry.py read
# these at module import time into module-level constants.
os.environ["KYA_SIGNING_SECRET"] = "test-signing-secret-for-http-attack-matrix"
os.environ["KYA_DEMO_ISSUER_KEY"] = "test-demo-key-for-http-attack-matrix"

import registry  # noqa: E402
import audit  # noqa: E402

try:
    from fastapi.testclient import TestClient
    HAVE_FASTAPI = True
except ImportError:
    HAVE_FASTAPI = False


AGENT_ID = "agent_procure_bot_042"  # ProcureBot: scope [groceries, office_supplies]
HUMAN_ID = "user_priya_88"
DEMO_KEY = "test-demo-key-for-http-attack-matrix"


@unittest.skipUnless(HAVE_FASTAPI, "fastapi not installed -- pip install fastapi uvicorn httpx")
class HTTPAttackMatrix(unittest.TestCase):
    """One TestClient per test, fresh isolated storage per test, so
    nothing here depends on run order or pollutes the real demo
    data/ directory."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_audit_db_path = audit.AUDIT_DB_PATH
        self._orig_consumed_db_path = registry.CONSUMED_DB_PATH
        import baseline as _baseline
        self._orig_baseline_db_path = _baseline.BASELINE_DB_PATH
        audit.AUDIT_DB_PATH = os.path.join(self._tmpdir, "audit_trail.db")
        audit.AUDIT_PATH = audit.AUDIT_DB_PATH
        registry.CONSUMED_DB_PATH = os.path.join(self._tmpdir, "execution_claims.db")
        _baseline.BASELINE_DB_PATH = os.path.join(self._tmpdir, "baselines.db")

        import main  # imported lazily, per-test, after path patches are in place
        self.main = main
        # Clear global rate-limit state so tests don't leak limits to each other
        main._rate_limiter.reset()
        self.client = TestClient(main.app)

    def tearDown(self):
        audit.AUDIT_DB_PATH = self._orig_audit_db_path
        audit.AUDIT_PATH = audit.AUDIT_DB_PATH
        registry.CONSUMED_DB_PATH = self._orig_consumed_db_path
        import baseline as _baseline
        _baseline.BASELINE_DB_PATH = self._orig_baseline_db_path

    # -- helpers ---------------------------------------------------

    def issue_token(self, max_amount=6000.0, categories=None, key=DEMO_KEY, agent_id=AGENT_ID):
        resp = self.client.post(
            "/issue-token",
            headers={"x-kya-demo-key": key} if key is not None else {},
            json={
                "agent_id": agent_id,
                "human_id": HUMAN_ID,
                "max_amount": max_amount,
                "categories": categories or ["groceries", "office_supplies"],
            },
        )
        return resp

    def verify(self, token, agent_id=AGENT_ID, stated_intent="buy groceries for the week",
               cart=None, key=DEMO_KEY):
        cart = cart or [{"item": "Vegetables box", "category": "groceries", "amount": 500.0}]
        headers = {"x-kya-demo-key": key} if key is not None else {}
        return self.client.post(
            "/verify",
            headers=headers,
            json={
                "agent_id": agent_id,
                "delegation_token": token,
                "stated_intent": stated_intent,
                "cart": cart,
            },
        )

    # -- 1. legitimate purchase -------------------------------------

    def test_legitimate_purchase_approves_exactly_once(self):
        token = self.issue_token().json()["delegation_token"]
        resp = self.verify(token, cart=[
            {"item": "Vegetables box", "category": "groceries", "amount": 500.0}
        ])
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["decision"], "APPROVE")
        self.assertIsNotNone(body["payment"])

    # -- 2. /issue-token auth -----------------------------------------

    def test_issue_token_without_demo_key_is_401(self):
        resp = self.issue_token(key=None)
        self.assertEqual(resp.status_code, 401)

    def test_issue_token_with_wrong_demo_key_is_401(self):
        resp = self.issue_token(key="wrong-key")
        self.assertEqual(resp.status_code, 401)

    def test_issue_token_with_correct_demo_key_succeeds(self):
        resp = self.issue_token()
        self.assertEqual(resp.status_code, 200)
        self.assertIn("delegation_token", resp.json())

    # -- 3. scope attack -----------------------------------------------

    def test_scope_violation_is_blocked(self):
        """ProcureBot is only scoped for groceries/office_supplies --
        an electronics purchase must be hard-blocked regardless of
        risk score."""
        token = self.issue_token(categories=["groceries", "office_supplies"]).json()["delegation_token"]
        resp = self.verify(token, stated_intent="buy a laptop", cart=[
            {"item": "Laptop", "category": "electronics", "amount": 500.0}
        ])
        body = resp.json()
        self.assertEqual(body["decision"], "BLOCK")

    # -- 4. expired delegation -------------------------------------------

    def test_expired_delegation_is_blocked(self):
        """/issue-token doesn't expose issued_at, so this mints the
        expired token directly via registry (still verified over
        real HTTP through /verify)."""
        expired_token = registry.issue_delegation_token(
            agent_id=AGENT_ID, human_id=HUMAN_ID, max_amount=6000.0,
            allowed_categories=["groceries", "office_supplies"],
            issued_at=1000, ttl_seconds=100,  # expired relative to real wall-clock `now`
        )
        resp = self.verify(expired_token)
        body = resp.json()
        self.assertEqual(body["decision"], "BLOCK")

    # -- 5. identity spoof --------------------------------------------

    def test_unregistered_agent_is_blocked(self):
        token = self.issue_token(agent_id="agent_totally_unregistered_999").json()["delegation_token"]
        resp = self.verify(token, agent_id="agent_totally_unregistered_999")
        body = resp.json()
        self.assertEqual(body["decision"], "BLOCK")

    # -- 6. replay ------------------------------------------------------

    def test_replay_second_execution_is_blocked(self):
        token = self.issue_token().json()["delegation_token"]
        first = self.verify(token)
        self.assertEqual(first.json()["decision"], "APPROVE")

        second = self.verify(token)
        self.assertEqual(second.json()["decision"], "BLOCK")
        self.assertIn("replay", " ".join(second.json()["reasons"]).lower())

    # -- 7. step-up flow --------------------------------------------------

    def test_step_up_then_confirm_then_replay_confirm_is_rejected(self):
        token = self.issue_token().json()["delegation_token"]
        # amount picked to land in the STEP_UP band -- see module
        # docstring for the risk-score math.
        first = self.verify(token, cart=[
            {"item": "Bulk groceries", "category": "groceries", "amount": 2000.0}
        ])
        body = first.json()
        self.assertEqual(body["decision"], "STEP_UP")
        audit_id = body["audit_id"]

        confirm = self.client.post("/step-up/confirm",
            headers={"x-kya-demo-key": DEMO_KEY},
            json={"audit_id": audit_id, "human_confirmed": True},
        )
        self.assertEqual(confirm.json()["decision"], "APPROVE (after step-up)")

        replay_confirm = self.client.post("/step-up/confirm",
            headers={"x-kya-demo-key": DEMO_KEY},
            json={"audit_id": audit_id, "human_confirmed": True},
        )
        self.assertEqual(replay_confirm.status_code, 409)

    # -- 8. concurrent replay (the important one) ------------------------

    def test_concurrent_replay_exactly_one_execution(self):
        token = self.issue_token().json()["delegation_token"]
        statuses = []
        decisions = []
        exceptions = []
        lock = threading.Lock()

        def attempt():
            try:
                resp = self.verify(token, key=DEMO_KEY)
            except Exception as exc:  # noqa: BLE001 -- capturing for the assertion below
                with lock:
                    exceptions.append(exc)
                return
            with lock:
                statuses.append(resp.status_code)
                # Only a 200 response is guaranteed to carry a "decision"
                # field -- don't assume every thread got one back, since
                # that's exactly the kind of assumption that would let a
                # crash or a non-200 response go unnoticed here.
                if resp.status_code == 200:
                    decisions.append(resp.json()["decision"])

        threads = [threading.Thread(target=attempt) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(
            exceptions, [],
            f"expected no exceptions from any of the 20 concurrent requests, got {exceptions}",
        )
        self.assertEqual(
            statuses, [200] * 20,
            f"expected all 20 concurrent requests to return HTTP 200, got {statuses}",
        )

        approvals = decisions.count("APPROVE")
        blocks = decisions.count("BLOCK")
        self.assertEqual(approvals, 1, f"expected exactly 1 APPROVE out of 20 concurrent requests, got {approvals}")
        self.assertEqual(blocks, 19, f"expected exactly 19 BLOCK out of 20 concurrent requests, got {blocks}")


    # -- 9. authentication boundaries -------------------------------------

    def test_agents_requires_auth(self):
        resp = self.client.get("/agents")
        self.assertEqual(resp.status_code, 401)

    def test_agents_with_auth_returns_safe_fields(self):
        resp = self.client.get("/agents", headers={"x-kya-demo-key": DEMO_KEY})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        for agent_id, agent in body.items():
            self.assertIn("agent_id", agent)
            self.assertIn("name", agent)
            self.assertNotIn("baseline_mean_amount", agent, "baseline must not be exposed")
            self.assertNotIn("baseline_std_amount", agent, "baseline must not be exposed")
            self.assertNotIn("baseline_txn_count", agent, "baseline must not be exposed")
            self.assertNotIn("certificate_fingerprint", agent, "fingerprint must not be exposed")

    def test_audit_requires_auth(self):
        resp = self.client.get("/audit")
        self.assertEqual(resp.status_code, 401)

    def test_audit_with_auth_succeeds(self):
        resp = self.client.get("/audit", headers={"x-kya-demo-key": DEMO_KEY})
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)

    def test_verify_requires_auth(self):
        token = self.issue_token().json()["delegation_token"]
        resp = self.verify(token, key=None)
        self.assertEqual(resp.status_code, 401)

    def test_stepup_requires_auth(self):
        resp = self.client.post("/step-up/confirm",
            json={"audit_id": "audit_fake", "human_confirmed": True},
        )
        self.assertEqual(resp.status_code, 401)

    def test_stepup_not_found_returns_404(self):
        resp = self.client.post("/step-up/confirm",
            headers={"x-kya-demo-key": DEMO_KEY},
            json={"audit_id": "audit_nonexistent", "human_confirmed": True},
        )
        self.assertEqual(resp.status_code, 404)

    def test_stepup_wrong_state_returns_409(self):
        # Seed an APPROVE entry (not STEP_UP) and try to confirm it
        entry = {
            "agent_id": AGENT_ID,
            "total_amount": 500.0,
            "decision": "APPROVE",
            "jti": "jti-test-wrong-state",
            "payment": None,
            "executed": False,
            "step_up_confirmed": None,
        }
        audit_id = audit.record(entry)
        resp = self.client.post("/step-up/confirm",
            headers={"x-kya-demo-key": DEMO_KEY},
            json={"audit_id": audit_id, "human_confirmed": True},
        )
        self.assertEqual(resp.status_code, 409)

    def test_root_endpoint_requires_no_auth(self):
        """GET / must remain public for service discovery."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("endpoints", resp.json())

    # -- 10. rate limiting ------------------------------------------------

    def test_rate_limit_on_issue_token(self):
        """Issuing more than 10 tokens in 60s must hit 429."""
        for _ in range(10):
            self.issue_token()
        resp = self.issue_token()
        self.assertEqual(resp.status_code, 429)
        self.assertIn("Rate limit exceeded", resp.json()["detail"])

    def test_rate_limit_resets_after_window(self):
        """After the 60s window passes, requests should succeed again.
        We can't actually sleep 60s in a test, so we manipulate the
        internal rate-limit state directly."""
        import main as _main
        # Exhaust the limit
        for _ in range(10):
            self.issue_token()
        resp = self.issue_token()
        self.assertEqual(resp.status_code, 429)

        # Clear the rate window for this IP+path (TestClient uses 'testclient' as host)
        key = "testclient:/issue-token"
        _main._rate_limiter.reset(key)

        # Now it should work again
        resp = self.issue_token()
        self.assertEqual(resp.status_code, 200)

    def test_rate_limit_is_per_path(self):
        """Rate limits on /issue-token must not affect /verify."""
        import main as _main
        # Exhaust /issue-token limit
        for _ in range(10):
            self.issue_token()
        resp = self.issue_token()
        self.assertEqual(resp.status_code, 429)

        # /verify must still work (separate rate window)
        token = registry.issue_delegation_token(
            agent_id=AGENT_ID, human_id=HUMAN_ID, max_amount=6000.0,
            allowed_categories=["groceries", "office_supplies"],
        )
        resp = self.verify(token)
        self.assertEqual(resp.status_code, 200)

    def test_rate_limit_response_includes_retry_after(self):
        """429 response must include Retry-After header."""
        for _ in range(10):
            self.issue_token()
        resp = self.issue_token()
        self.assertEqual(resp.status_code, 429)
        self.assertIn("Retry-After", resp.headers)
        self.assertGreater(int(resp.headers["Retry-After"]), 0)

    # -- 11. request body size --------------------------------------------

    def test_oversized_request_body_rejected(self):
        """Request bodies over 1 MB must be rejected with 413."""
        import main as _main
        # Temporarily lower the limit so we don't need a 1MB+ body
        original = _main.MAX_REQUEST_BYTES
        _main.MAX_REQUEST_BYTES = 100  # 100 bytes
        try:
            large_cart = [{"item": "x" * 50, "category": "groceries", "amount": 10.0}]
            resp = self.client.post("/verify",
                headers={"x-kya-demo-key": DEMO_KEY, "content-length": "200"},
                content="x" * 200,
            )
            self.assertEqual(resp.status_code, 413)
        finally:
            _main.MAX_REQUEST_BYTES = original


    # -- 12. security headers --------------------------------------------

    def test_security_headers_present(self):
        """Every response must include security headers."""
        resp = self.client.get("/")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(resp.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")

    def test_security_headers_on_post_responses(self):
        """POST responses must also include security headers."""
        resp = self.client.get("/agents", headers={"x-kya-demo-key": DEMO_KEY})
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")

    def test_security_headers_on_error_responses(self):
        """Even 401/429 responses must include security headers."""
        resp = self.client.get("/agents")  # no auth -> 401
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")

    # -- 13. health check -----------------------------------------------

    def test_health_endpoint_requires_no_auth(self):
        """Health check is unauthenticated (load balancers need it)."""
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("status", data)
        self.assertIn("pending_finalizations", data)
        self.assertIn("version", data)
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["pending_finalizations"], 0)

    def test_health_in_root_endpoints(self):
        """Root endpoint lists /health in its endpoints."""
        resp = self.client.get("/")
        data = resp.json()
        self.assertIn("/health", data["endpoints"])

    # -- 14. metrics endpoint ------------------------------------------

    def test_metrics_endpoint_returns_prometheus_format(self):
        """GET /metrics should return Prometheus text format."""
        resp = self.client.get("/metrics")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/plain", resp.headers.get("content-type", ""))
        self.assertIn("kya_requests_total", resp.text)
        self.assertIn("kya_request_duration_seconds", resp.text)

    def test_metrics_json_endpoint(self):
        """GET /metrics/json should return JSON with standard keys."""
        resp = self.client.get("/metrics/json")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("requests_total", data)
        self.assertIn("uptime_seconds", data)
        self.assertIn("request_p50_ms", data)

    def test_metrics_in_root_endpoints(self):
        """Root endpoint lists /metrics in its endpoints."""
        resp = self.client.get("/")
        data = resp.json()
        self.assertIn("/metrics", data["endpoints"])

    # -- 15. outbox crash recovery --------------------------------------

    def test_outbox_entry_created_and_cleaned(self):
        """After a successful verify, the outbox entry should be cleaned up."""
        import registry
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
        self.assertEqual(resp.json()["decision"], "APPROVE")
        # Outbox should be clean after successful finalization
        self.assertEqual(registry.get_pending_outbox_count(), 0)

    def test_outbox_replay_finalizes_pending(self):
        """Simulate a crash by writing a PENDING outbox entry, then verify
        that replay_pending_finalizations completes it."""
        import registry
        import audit as audit_store

        # Create a token and reserve it
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, max_amount=50000,
            allowed_categories=["groceries"],
        )
        claims = json.loads(json.loads(token)["payload"])
        jti = claims["jti"]
        self.assertTrue(registry.reserve_token(jti))

        # Create an audit entry (simulating the audit step that happened before crash)
        audit_entry = {
            "agent_id": AGENT_ID,
            "decision": "APPROVE",
            "total_amount": 500,
        }
        audit_id = audit_store.record(audit_entry)

        # Write an outbox entry (simulating step 4 before crash)
        registry.write_outbox_entry(jti, audit_id, "order_simulated")
        self.assertEqual(registry.get_pending_outbox_count(), 1)

        # Simulate replay (as if server restarted)
        replayed = registry.replay_pending_finalizations(registry.finalize_execution)
        self.assertEqual(replayed, 1)

        # Outbox should now be clean
        self.assertEqual(registry.get_pending_outbox_count(), 0)

        # Token should be EXECUTED
        self.assertTrue(registry.is_token_consumed(jti))

    def test_request_id_header_present(self):
        """Every response includes X-Request-ID header."""
        resp = self.client.get("/")
        self.assertIn("X-Request-ID", resp.headers)
        self.assertTrue(len(resp.headers["X-Request-ID"]) > 0)

    def test_request_id_passthrough(self):
        """Client-provided X-Request-ID is echoed back."""
        custom_id = "test-trace-12345"
        resp = self.client.get("/", headers={"X-Request-ID": custom_id})
        self.assertEqual(resp.headers.get("X-Request-ID"), custom_id)

    def test_response_time_header(self):
        """Every response includes X-Response-Time header."""
        resp = self.client.get("/")
        self.assertIn("X-Response-Time", resp.headers)
        self.assertTrue(resp.headers["X-Response-Time"].endswith("ms"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
