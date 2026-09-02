"""
Regression tests for the P0 issues found during review:

  1. Step-up confirmation could be replayed against the same audit_id
     to create a second order (audit.py never mutated the original
     record; it only appended a new one).
  2. A stolen-but-valid delegation token could be used to execute more
     than one transaction (no real replay protection -- "replay" only
     checked that the presenting agent_id matched the issuing one).
  3. Evaluation results depended on wall-clock time because token
     expiry was an absolute timestamp baked in at dataset-generation
     time (see eval/harness.py's reproducibility check for the
     evaluation-side version of this).
  4. Two concurrent /step-up/confirm calls for the *same* audit_id
     could both pass the STEP_UP check; the loser of the token
     reservation race would then overwrite the audit record to BLOCK
     while the winner was still mid-payment-call, so the winner's own
     final audit update lost that race and failed -- leaving a real
     payment created, an audit trail reading BLOCK, and the token
     reservation stuck at RESERVED forever. Fixed by having the
     handler claim an atomic STEP_UP -> CONFIRMING transition before
     touching reserve_token() or the payment call at all, so only one
     concurrent caller per audit_id can ever decide its outcome.

Deliberately imports only backend.pipeline / registry / audit /
decision_engine / risk_scorer -- NOT main.py. main.py imports
FastAPI, which isn't installable in every environment (this sandbox
included: no network access to pip install fastapi/uvicorn). These
tests exercise the exact same functions main.py calls
(pipeline.run_pipeline, registry.reserve_token, audit.update),
so they cover the real logic -- but they are not a substitute for
actually running `uvicorn main:app` and hitting /verify and
/step-up/confirm over HTTP the way a judge's browser would. That live
check is still outstanding; see tests/README.md.

TestConcurrentStepUpConfirmation below reimplements confirm_step_up()'s
body inline rather than importing it, for that same fastapi reason --
if main.py's /step-up/confirm logic changes, this copy needs to be
kept in sync by hand (same maintenance caveat TestStepUpCannotBeReplayed
above already has).
"""

import json
import os
import sys
import tempfile
import threading
import time
import unittest

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, BACKEND_DIR)

# Tests must explicitly provide a signing secret. registry.py now requires
# KYA_SIGNING_SECRET to be set -- without it, import registry would raise
# a RuntimeError and the entire test module would fail to load.
os.environ.setdefault("KYA_SIGNING_SECRET", "test-signing-secret-for-unit-tests")

import registry  # noqa: E402
import audit  # noqa: E402
from pipeline import run_pipeline  # noqa: E402
from razorpay_mock import create_test_order  # noqa: E402


class IsolatedStorageTestCase(unittest.TestCase):
    """Points audit.py and registry.py's replay store at fresh temp
    files per test, so tests don't read/pollute the real demo data
    directory and don't depend on run order."""

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


AGENT_ID = "agent_procure_bot_042"
HUMAN_ID = "user_priya_88"


def make_token(**kwargs):
    defaults = dict(
        agent_id=AGENT_ID,
        human_id=HUMAN_ID,
        max_amount=6000.0,
        allowed_categories=["groceries", "office_supplies"],
    )
    defaults.update(kwargs)
    return registry.issue_delegation_token(**defaults)


def make_cart(amount=500.0, category="groceries"):
    return [{"item": "Vegetables box", "category": category, "amount": amount}]


class TestDelegationExpiry(IsolatedStorageTestCase):
    def test_expired_token_is_rejected(self):
        token = make_token(issued_at=1000, ttl_seconds=100)
        result = registry.verify_delegation_token(token, now=1000 + 101)
        self.assertFalse(result["valid"])
        self.assertIn("expired", result["reason"].lower())

    def test_valid_token_at_boundary_still_valid(self):
        token = make_token(issued_at=1000, ttl_seconds=100)
        result = registry.verify_delegation_token(token, now=1000 + 100)
        self.assertTrue(result["valid"])

    def test_same_token_same_clock_gives_identical_result_every_time(self):
        """The determinism fix, at unit-test granularity: same token,
        same `now`, run repeatedly -- must never depend on when the
        test itself happens to execute."""
        token = make_token(issued_at=1000, ttl_seconds=3600)
        results = [registry.verify_delegation_token(token, now=2000)["valid"] for _ in range(20)]
        self.assertTrue(all(results))


class TestReplayProtection(IsolatedStorageTestCase):
    def test_valid_token_can_be_verified_more_than_once(self):
        """Verifying (e.g. a client previewing risk before committing)
        must NOT consume the token -- only execution does."""
        token = make_token(issued_at=1000, ttl_seconds=3600)
        r1 = registry.verify_delegation_token(token, now=1500)
        r2 = registry.verify_delegation_token(token, now=1500)
        self.assertTrue(r1["valid"])
        self.assertTrue(r2["valid"])

    def test_token_cannot_execute_two_transactions(self):
        """The actual replay-protection bug: previously a stolen-but-
        valid token could pay for a second cart after the first
        purchase went through, because nothing was ever marked used."""
        token = make_token(issued_at=1000, ttl_seconds=3600)

        first = run_pipeline(AGENT_ID, token, "buy groceries for the week", make_cart(500.0), now=1500)
        self.assertEqual(first["decision"], "APPROVE")
        self.assertFalse(registry.is_token_consumed(first["jti"]))  # not yet -- run_pipeline only verifies, it doesn't execute
        # simulate what main.py does on APPROVE: reserve *before*
        # creating the order, create the order, then finalize with
        # the audit_id (which doesn't exist until after the order).
        self.assertTrue(registry.reserve_token(first["jti"]))
        create_test_order(first["total_amount"], AGENT_ID)
        registry.finalize_execution(first["jti"], audit_id="audit_test_1")
        self.assertTrue(registry.is_token_consumed(first["jti"]))

        second = run_pipeline(AGENT_ID, token, "buy groceries for the week", make_cart(400.0), now=1600)
        # pipeline itself only flags this via delegation_ok=False / reason;
        # main.py additionally hard-blocks at the execution step. Check both
        # layers: the token-level signal, and that a second order is refused.
        self.assertFalse(registry.verify_delegation_token(token, now=1600)["valid"])
        self.assertFalse(registry.reserve_token(second["jti"]), "same jti -- must not be reservable twice")

    def test_reserve_token_is_atomic_under_concurrency(self):
        """The TOCTOU regression this fix specifically targets: a
        separate is_token_consumed() check followed by a later
        mark_token_consumed() write left a window where two
        concurrent callers could both pass the check. reserve_token()
        must let exactly one caller through no matter how many race
        for the same jti."""
        import threading

        token = make_token(issued_at=1000, ttl_seconds=3600)
        result = run_pipeline(AGENT_ID, token, "buy groceries for the week", make_cart(500.0), now=1500)
        jti = result["jti"]

        outcomes = []

        def attempt():
            outcomes.append(registry.reserve_token(jti))

        threads = [threading.Thread(target=attempt) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(sum(outcomes), 1, "exactly one of many concurrent reservations must win")

    def test_release_token_allows_retry_after_failed_execution(self):
        """If create_test_order() fails after a successful reservation,
        main.py calls release_token() so the delegation token isn't
        permanently burned by an infra failure that never actually
        spent anything."""
        token = make_token(issued_at=1000, ttl_seconds=3600)
        result = run_pipeline(AGENT_ID, token, "buy groceries for the week", make_cart(500.0), now=1500)
        jti = result["jti"]

        self.assertTrue(registry.reserve_token(jti))
        registry.release_token(jti)
        self.assertFalse(registry.is_token_consumed(jti), "a released reservation must not count as consumed")
        self.assertTrue(registry.reserve_token(jti), "token must be reservable again after release")

    def test_release_token_never_releases_an_executed_claim(self):
        """A completed transaction must never become reservable again,
        even if release_token() is called against it by mistake."""
        token = make_token(issued_at=1000, ttl_seconds=3600)
        result = run_pipeline(AGENT_ID, token, "buy groceries for the week", make_cart(500.0), now=1500)
        jti = result["jti"]

        self.assertTrue(registry.reserve_token(jti))
        registry.finalize_execution(jti, audit_id="audit_test_2")
        registry.release_token(jti)  # must be a no-op against an EXECUTED claim
        self.assertTrue(registry.is_token_consumed(jti))
        self.assertFalse(registry.reserve_token(jti))


class TestStepUpCannotBeReplayed(IsolatedStorageTestCase):
    """Simulates exactly what main.py's /step-up/confirm does, without
    importing main.py (avoids the fastapi dependency)."""

    def _seed_step_up_entry(self):
        entry = {
            "agent_id": AGENT_ID,
            "total_amount": 5000.0,
            "decision": "STEP_UP",
            "jti": "jti-test-1",
            "payment": None,
            "executed": False,
            "step_up_confirmed": None,
        }
        return audit.record(entry)

    def test_first_confirmation_succeeds(self):
        audit_id = self._seed_step_up_entry()
        ok = audit.update(audit_id, "STEP_UP", {
            "decision": "APPROVE (after step-up)",
            "step_up_confirmed": True,
            "executed": True,
        })
        self.assertTrue(ok)
        entry = audit.get_one(audit_id)
        self.assertEqual(entry["decision"], "APPROVE (after step-up)")

    def test_second_confirmation_of_same_audit_id_is_rejected(self):
        """This is the exact bug: the original implementation left the
        record's `decision` at "STEP_UP" forever (it only appended a
        new record), so this second call used to succeed and create
        a second order. It must now fail."""
        audit_id = self._seed_step_up_entry()

        first_ok = audit.update(audit_id, "STEP_UP", {
            "decision": "APPROVE (after step-up)",
            "step_up_confirmed": True,
            "executed": True,
        })
        self.assertTrue(first_ok)

        # Replay: same audit_id, confirm again.
        second_ok = audit.update(audit_id, "STEP_UP", {
            "decision": "APPROVE (after step-up)",
            "step_up_confirmed": True,
            "executed": True,
        })
        self.assertFalse(second_ok, "Second confirmation of the same audit_id must be rejected")

        entries = audit._load()
        matching = [e for e in entries if e["audit_id"] == audit_id]
        self.assertEqual(len(matching), 1, "Confirmation must mutate the one record in place, not append a duplicate")


class TestConcurrentStepUpConfirmation(IsolatedStorageTestCase):
    """Regression test for the concurrent-/step-up/confirm race found
    during review: two callers confirming the *same* audit_id at once
    could both pass the STEP_UP check and race reserve_token() (only
    one wins, correctly) -- but the loser would then immediately write
    BLOCK to the audit record, so when the winner's create_test_order()
    call finished, its own final audit.update() lost to that BLOCK
    write and failed. Net effect: a real payment order got created,
    the audit trail read BLOCK, and the token reservation was left
    stuck at RESERVED forever (finalize_execution() never ran).

    The fix (mirrored here, not imported from main.py -- same fastapi
    constraint as the rest of this file) claims the record with an
    atomic STEP_UP -> CONFIRMING transition *before* reserve_token()
    or the payment call run at all, so only one concurrent caller for
    a given audit_id can ever decide its outcome; every other
    concurrent caller is rejected immediately and never gets to write
    anything to that record."""

    def _seed_step_up_entry(self, jti="jti-test-concurrent"):
        entry = {
            "agent_id": AGENT_ID,
            "total_amount": 5000.0,
            "decision": "STEP_UP",
            "jti": jti,
            "payment": None,
            "executed": False,
            "step_up_confirmed": None,
        }
        return audit.record(entry)

    def _confirm_step_up(self, audit_id, slow_payment_seconds=0.0):
        """Mirrors main.py's confirm_step_up(human_confirmed=True)
        body exactly, including the CONFIRMING ownership claim."""
        claimed = audit.update(audit_id, "STEP_UP", {"decision": "CONFIRMING"})
        if not claimed:
            return {"error": "Step-up already resolved or in progress for this audit_id"}

        entry = audit.get_one(audit_id)
        jti = entry.get("jti")

        if jti and not registry.reserve_token(jti):
            audit.update(audit_id, "CONFIRMING", {
                "decision": "BLOCK (step-up declined -- token already used)",
                "step_up_confirmed": False,
            })
            return {"decision": "BLOCK (step-up declined -- token already used)", "payment": None}

        if slow_payment_seconds:
            time.sleep(slow_payment_seconds)
        payment = create_test_order(entry["total_amount"], entry["agent_id"])

        audit.update(audit_id, "CONFIRMING", {
            "decision": "APPROVE (after step-up)",
            "step_up_confirmed": True,
            "payment": payment,
            "executed": True,
        })
        if jti:
            registry.finalize_execution(jti, audit_id, payment.get("razorpay_order_id"))
        return {"decision": "APPROVE (after step-up)", "payment": payment}

    def test_concurrent_confirm_forced_race_stays_consistent(self):
        """Forces the exact interleaving the review reproduced: give
        the first caller a deliberately slow payment call so the
        second caller's reservation loss (and its BLOCK write) lands
        while the first is still "mid-payment"."""
        audit_id = self._seed_step_up_entry()
        results = []
        lock = threading.Lock()

        def slow_confirm():
            r = self._confirm_step_up(audit_id, slow_payment_seconds=0.3)
            with lock:
                results.append(r)

        def fast_confirm():
            r = self._confirm_step_up(audit_id, slow_payment_seconds=0.0)
            with lock:
                results.append(r)

        t_slow = threading.Thread(target=slow_confirm)
        t_fast = threading.Thread(target=fast_confirm)
        t_slow.start()
        time.sleep(0.05)  # let the slow caller win the CONFIRMING claim first
        t_fast.start()
        t_slow.join()
        t_fast.join()

        approvals = [r for r in results if r.get("decision") == "APPROVE (after step-up)"]
        self.assertEqual(len(approvals), 1, f"expected exactly 1 approval, got {results}")
        self.assertIsNotNone(approvals[0]["payment"])

        final_entry = audit.get_one(audit_id)
        self.assertEqual(
            final_entry["decision"], "APPROVE (after step-up)",
            "the audit trail must reflect the payment that was actually created, "
            "not be overwritten by the losing concurrent caller",
        )
        self.assertTrue(final_entry["executed"])
        self.assertIsNotNone(final_entry["payment"])

        import contextlib
        with contextlib.closing(registry._connect()) as conn:
            row = conn.execute(
                "SELECT status, audit_id FROM execution_claims WHERE jti = ?",
                ("jti-test-concurrent",),
            ).fetchone()
        self.assertIsNotNone(row, "the token reservation must not vanish")
        self.assertEqual(
            row[0], "EXECUTED",
            "the reservation must be finalized to EXECUTED, not left stuck at RESERVED",
        )
        self.assertEqual(row[1], audit_id)

    def test_concurrent_confirm_twenty_way_exactly_one_winner(self):
        """Same shape as the /verify 20-thread concurrency test:
        20 concurrent confirms against the same audit_id, exactly one
        should win, and the audit trail must end up consistent with
        whichever one actually created the payment."""
        audit_id = self._seed_step_up_entry(jti="jti-test-concurrent-20")
        results = []
        lock = threading.Lock()

        def attempt():
            r = self._confirm_step_up(audit_id)
            with lock:
                results.append(r)

        threads = [threading.Thread(target=attempt) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        approvals = [r for r in results if r.get("decision") == "APPROVE (after step-up)"]
        self.assertEqual(len(approvals), 1, f"expected exactly 1 approval out of 20, got {len(approvals)}")

        final_entry = audit.get_one(audit_id)
        self.assertEqual(final_entry["decision"], "APPROVE (after step-up)")
        self.assertEqual(final_entry["payment"]["razorpay_order_id"], approvals[0]["payment"]["razorpay_order_id"])


class TestFailClosedSecrets(unittest.TestCase):
    """Proves that the application refuses to start when required
    environment variables are missing, rather than silently falling
    back to insecure defaults. Uses subprocess to get a clean import
    environment without module-cache contamination."""

    def _run_import(self, code, env_overrides=None):
        """Run a Python import in a subprocess with a clean env.
        env_overrides: dict of env vars to SET (replacing current values).
        Keys set to None are explicitly removed."""
        import subprocess
        env = os.environ.copy()
        # Remove any existing KYA_ vars so overrides are the sole source
        for key in list(env.keys()):
            if key.startswith("KYA_"):
                del env[key]
        if env_overrides:
            for k, v in env_overrides.items():
                if v is None:
                    env.pop(k, None)
                else:
                    env[k] = v
        return subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
            env=env,
        )

    def test_registry_import_fails_without_signing_secret(self):
        """registry.py must raise RuntimeError when KYA_SIGNING_SECRET is not set."""
        result = self._run_import(
            "import sys; sys.path.insert(0, 'backend'); import registry",
        )
        self.assertNotEqual(result.returncode, 0, "import registry should fail without KYA_SIGNING_SECRET")
        self.assertIn("KYA_SIGNING_SECRET", result.stderr)

    def test_registry_works_with_signing_secret_set(self):
        """registry.py must import successfully when KYA_SIGNING_SECRET is set."""
        result = self._run_import(
            "import sys; sys.path.insert(0, 'backend'); import registry; print('OK')",
            env_overrides={"KYA_SIGNING_SECRET": "test-value"},
        )
        self.assertEqual(result.returncode, 0, f"import registry should succeed: {result.stderr}")
        self.assertIn("OK", result.stdout)

    def test_main_import_fails_without_demo_issuer_key(self):
        """main.py must raise RuntimeError when KYA_DEMO_ISSUER_KEY is not set."""
        result = self._run_import(
            "import sys; sys.path.insert(0, 'backend'); import main",
            env_overrides={"KYA_SIGNING_SECRET": "test-value"},
            # no KYA_DEMO_ISSUER_KEY
        )
        self.assertNotEqual(result.returncode, 0, "import main should fail without KYA_DEMO_ISSUER_KEY")
        self.assertIn("KYA_DEMO_ISSUER_KEY", result.stderr)

    def test_main_import_works_with_both_keys_set(self):
        """main.py must import successfully when both env vars are set."""
        result = self._run_import(
            "import sys; sys.path.insert(0, 'backend'); import main; print('OK')",
            env_overrides={
                "KYA_SIGNING_SECRET": "test-value",
                "KYA_DEMO_ISSUER_KEY": "test-value",
            },
        )
        self.assertEqual(result.returncode, 0, f"import main should succeed: {result.stderr}")
        self.assertIn("OK", result.stdout)

    def test_wildcard_cors_rejected(self):
        """main.py must refuse to start when KYA_ALLOWED_ORIGINS contains '*'."""
        result = self._run_import(
            "import sys; sys.path.insert(0, 'backend'); import main; print('OK')",
            env_overrides={
                "KYA_SIGNING_SECRET": "test-value",
                "KYA_DEMO_ISSUER_KEY": "test-value",
                "KYA_ALLOWED_ORIGINS": "*",
            },
        )
        self.assertNotEqual(result.returncode, 0, "import main should fail with wildcard CORS")
        self.assertIn("wildcard", result.stderr.lower())


# ---------------------------------------------------------------------
# Input Validation Boundary Tests (Phase 1B)
#
# These test the Pydantic model validators added to main.py and the
# TTL bounds added to registry.py. We import the models selectively
# to avoid pulling in FastAPI (the same reason the rest of this file
# avoids importing main.py).
# ---------------------------------------------------------------------

import math
from pydantic import ValidationError

# Import models directly -- Pydantic models don't depend on FastAPI,
# but importing main.py triggers module-level checks (env vars).
# Set KYA_DEMO_ISSUER_KEY so main.py can load, then import the models.
os.environ.setdefault("KYA_DEMO_ISSUER_KEY", "test-demo-issuer-key-for-unit-tests")
from main import CartItem, PurchaseRequest, IssueTokenRequest


class TestCartItemValidation(unittest.TestCase):
    """CartItem.amount must reject negative, zero, NaN, and Infinity.
    CartItem.category must be in KNOWN_CATEGORIES.
    CartItem.item must be non-empty and bounded."""

    def test_negative_amount_rejected(self):
        with self.assertRaises(ValidationError):
            CartItem(item="Milk", category="groceries", amount=-100.0)

    def test_zero_amount_rejected(self):
        with self.assertRaises(ValidationError):
            CartItem(item="Milk", category="groceries", amount=0.0)

    def test_nan_amount_rejected(self):
        with self.assertRaises(ValidationError):
            CartItem(item="Milk", category="groceries", amount=float("nan"))

    def test_infinite_amount_rejected(self):
        with self.assertRaises(ValidationError):
            CartItem(item="Milk", category="groceries", amount=float("inf"))

    def test_negative_infinite_amount_rejected(self):
        with self.assertRaises(ValidationError):
            CartItem(item="Milk", category="groceries", amount=float("-inf"))

    def test_excessive_amount_rejected(self):
        with self.assertRaises(ValidationError):
            CartItem(item="Milk", category="groceries", amount=2_000_000.0)

    def test_unknown_category_rejected(self):
        with self.assertRaises(ValidationError):
            CartItem(item="Weapons pack", category="weapons", amount=500.0)

    def test_empty_category_rejected(self):
        with self.assertRaises(ValidationError):
            CartItem(item="Milk", category="", amount=500.0)

    def test_empty_item_rejected(self):
        with self.assertRaises(ValidationError):
            CartItem(item="", category="groceries", amount=500.0)

    def test_long_item_rejected(self):
        with self.assertRaises(ValidationError):
            CartItem(item="x" * 257, category="groceries", amount=500.0)

    def test_valid_cart_item_accepted(self):
        item = CartItem(item="Milk", category="groceries", amount=150.0)
        self.assertEqual(item.item, "Milk")
        self.assertEqual(item.amount, 150.0)


class TestPurchaseRequestValidation(unittest.TestCase):
    """PurchaseRequest must enforce non-empty fields and cart bounds."""

    def test_empty_cart_rejected(self):
        with self.assertRaises(ValidationError):
            PurchaseRequest(
                agent_id="agent_procure_bot_042",
                delegation_token="some-token",
                stated_intent="buy groceries",
                cart=[],
            )

    def test_oversized_cart_rejected(self):
        items = [CartItem(item="Milk", category="groceries", amount=10.0) for _ in range(51)]
        with self.assertRaises(ValidationError):
            PurchaseRequest(
                agent_id="agent_procure_bot_042",
                delegation_token="some-token",
                stated_intent="buy groceries",
                cart=items,
            )

    def test_empty_agent_id_rejected(self):
        with self.assertRaises(ValidationError):
            PurchaseRequest(
                agent_id="",
                delegation_token="some-token",
                stated_intent="buy groceries",
                cart=[CartItem(item="Milk", category="groceries", amount=100.0)],
            )

    def test_empty_stated_intent_rejected(self):
        with self.assertRaises(ValidationError):
            PurchaseRequest(
                agent_id="agent_procure_bot_042",
                delegation_token="some-token",
                stated_intent="",
                cart=[CartItem(item="Milk", category="groceries", amount=100.0)],
            )

    def test_empty_delegation_token_rejected(self):
        with self.assertRaises(ValidationError):
            PurchaseRequest(
                agent_id="agent_procure_bot_042",
                delegation_token="",
                stated_intent="buy groceries",
                cart=[CartItem(item="Milk", category="groceries", amount=100.0)],
            )


class TestIssueTokenRequestValidation(unittest.TestCase):
    """IssueTokenRequest must enforce max_amount bounds and category validity."""

    def test_negative_max_amount_rejected(self):
        with self.assertRaises(ValidationError):
            IssueTokenRequest(
                agent_id="agent_procure_bot_042",
                human_id="user_priya_88",
                max_amount=-1.0,
                categories=["groceries"],
            )

    def test_zero_max_amount_rejected(self):
        with self.assertRaises(ValidationError):
            IssueTokenRequest(
                agent_id="agent_procure_bot_042",
                human_id="user_priya_88",
                max_amount=0.0,
                categories=["groceries"],
            )

    def test_infinite_max_amount_rejected(self):
        with self.assertRaises(ValidationError):
            IssueTokenRequest(
                agent_id="agent_procure_bot_042",
                human_id="user_priya_88",
                max_amount=float("inf"),
                categories=["groceries"],
            )

    def test_excessive_max_amount_rejected(self):
        with self.assertRaises(ValidationError):
            IssueTokenRequest(
                agent_id="agent_procure_bot_042",
                human_id="user_priya_88",
                max_amount=5_000_000.0,
                categories=["groceries"],
            )

    def test_unknown_category_rejected(self):
        with self.assertRaises(ValidationError):
            IssueTokenRequest(
                agent_id="agent_procure_bot_042",
                human_id="user_priya_88",
                max_amount=10000.0,
                categories=["groceries", "weapons"],
            )

    def test_empty_categories_rejected(self):
        with self.assertRaises(ValidationError):
            IssueTokenRequest(
                agent_id="agent_procure_bot_042",
                human_id="user_priya_88",
                max_amount=10000.0,
                categories=[],
            )

    def test_empty_agent_id_rejected(self):
        with self.assertRaises(ValidationError):
            IssueTokenRequest(
                agent_id="",
                human_id="user_priya_88",
                max_amount=10000.0,
                categories=["groceries"],
            )

    def test_empty_human_id_rejected(self):
        with self.assertRaises(ValidationError):
            IssueTokenRequest(
                agent_id="agent_procure_bot_042",
                human_id="",
                max_amount=10000.0,
                categories=["groceries"],
            )


class TestDelegationTokenTTLBounds(IsolatedStorageTestCase):
    """issue_delegation_token() must reject TTL <= 0 and TTL > 86400."""

    def test_excessive_ttl_rejected(self):
        with self.assertRaises(ValueError):
            registry.issue_delegation_token(
                AGENT_ID, HUMAN_ID, 6000.0, ["groceries"], ttl_seconds=999999,
            )

    def test_zero_ttl_rejected(self):
        with self.assertRaises(ValueError):
            registry.issue_delegation_token(
                AGENT_ID, HUMAN_ID, 6000.0, ["groceries"], ttl_seconds=0,
            )

    def test_negative_ttl_rejected(self):
        with self.assertRaises(ValueError):
            registry.issue_delegation_token(
                AGENT_ID, HUMAN_ID, 6000.0, ["groceries"], ttl_seconds=-1,
            )

    def test_max_ttl_accepted(self):
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 6000.0, ["groceries"], ttl_seconds=86400,
        )
        self.assertIsNotNone(token)

    def test_normal_ttl_accepted(self):
        token = registry.issue_delegation_token(
            AGENT_ID, HUMAN_ID, 6000.0, ["groceries"], ttl_seconds=3600,
        )
        self.assertIsNotNone(token)


if __name__ == "__main__":
    unittest.main(verbosity=2)
