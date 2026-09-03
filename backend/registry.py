"""
Agent Registry + Delegation Token handling.

In production this would map onto emerging agentic-commerce identity
standards (Google's AP2 verifiable credentials, the Agentic Commerce
Protocol, x402, NPCI's UAP). For the MVP we simulate the same shape:
a signed, scoped, expiring credential that proves a human authorized
a specific agent to spend up to a specific amount, in specific
categories.

Two things changed from the original version, both driven by issues
found during review:

1. Expiry is now stored as (issued_at, ttl_seconds) rather than a
   baked-in absolute Unix timestamp, and verify_delegation_token()
   takes an explicit `now` so callers (the eval harness, tests) can
   pin the clock instead of racing against real time. Production
   callers (main.py) simply don't pass `now` and get real wall time,
   so behavior there is unchanged.
2. Tokens carry a `jti` (JWT-style unique ID). This is what makes
   genuine replay protection possible -- see reserve_token(),
   release_token(), and finalize_execution() below. Previously
   "replay" only meant "token presented by a different agent_id than
   it was issued for," which is agent-binding validation, not replay
   protection: a stolen token reused by the *same* agent for a second
   transaction sailed straight through.
"""

import json
import hmac
import hashlib
import sqlite3
import contextlib
import time
import os
import uuid
from typing import Optional, Dict, Any

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
AGENTS_PATH = os.path.join(DATA_DIR, "agents.json")

# Execution-claims ledger: whether a delegation token has ever been
# used to actually execute a transaction. Backed by SQLite rather
# than a JSON file + threading.Lock -- see the block below the
# delegation-verification functions for why.
CONSUMED_DB_PATH = os.path.join(DATA_DIR, "execution_claims.db")

# Secret used to sign delegation tokens. In production this would be
# per-issuer public-key cryptography (verifiable credentials), not a
# shared HMAC secret -- simplified here for demo purposes.
#
# CRITICAL: This secret is the root of trust for delegation tokens.
# If it leaks, an attacker can forge tokens for any agent.
# A secure random value can be generated with:
#   python -c "import secrets; print(secrets.token_hex(32))"
_signing_secret_raw = os.environ.get("KYA_SIGNING_SECRET")
if not _signing_secret_raw:
    raise RuntimeError(
        "KYA_SIGNING_SECRET environment variable is not set. "
        "This is the HMAC key used to sign delegation tokens. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\" "
        "and set it before starting the server."
    )
SIGNING_SECRET = _signing_secret_raw.encode()

# Identity mode: "hmac" (default) or "ed25519"
# Set KYA_IDENTITY_MODE=ed25519 to enable asymmetric crypto.
# When ed25519 is enabled, delegation tokens are signed with Ed25519
# instead of HMAC, enabling per-issuer key pairs and key rotation.
IDENTITY_MODE = os.environ.get("KYA_IDENTITY_MODE", "hmac").lower()
_identity_provider = None
if IDENTITY_MODE == "ed25519":
    try:
        from identity import get_identity_provider
        _identity_provider = get_identity_provider()
    except Exception as e:
        raise RuntimeError(
            f"KYA_IDENTITY_MODE=ed25519 but identity module failed to load: {e}"
        )

# Maximum allowed TTL for delegation tokens (24 hours).
MAX_TTL_SECONDS = 86400

# Set WAL mode once at module load, not on every connection.
# WAL allows concurrent readers without blocking each other.
try:
    _init_conn = sqlite3.connect(CONSUMED_DB_PATH, timeout=30)
    _init_conn.execute("PRAGMA journal_mode=WAL")
    _init_conn.close()
except Exception:
    pass  # Will be set on first connection if this fails


def load_registry() -> Dict[str, Any]:
    with open(AGENTS_PATH, "r") as f:
        return json.load(f)


def get_agent(agent_id: str) -> Optional[Dict[str, Any]]:
    registry = load_registry()
    return registry.get(agent_id)


def update_agent_limit(agent_id: str, owner_max_amount: float) -> Optional[Dict[str, Any]]:
    registry = load_registry()
    if agent_id not in registry:
        return None
    registry[agent_id]["owner_max_amount"] = owner_max_amount
    with open(AGENTS_PATH, "w") as f:
        json.dump(registry, f, indent=2)
    return registry[agent_id]


def _sign(payload: str) -> str:
    """Sign a payload using the configured identity mode."""
    if _identity_provider and IDENTITY_MODE == "ed25519":
        return _identity_provider.sign_token(payload)
    return hmac.new(SIGNING_SECRET, payload.encode(), hashlib.sha256).hexdigest()


def issue_delegation_token(
    agent_id: str,
    human_id: str,
    max_amount: float,
    allowed_categories: list,
    ttl_seconds: int = 3600,
    issued_at: Optional[int] = None,
) -> str:
    """Simulates a human granting a scoped, time-boxed spending mandate
    to an agent -- the credential the agent presents at checkout.

    Stores (issued_at, ttl_seconds) instead of a baked-in absolute
    expiry so verification can be evaluated against any explicit
    clock (see verify_delegation_token). issued_at defaults to "now"
    for live issuance; callers building deterministic fixtures (the
    eval dataset generator) can pass a fixed issued_at explicitly.
    """
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    if ttl_seconds > MAX_TTL_SECONDS:
        raise ValueError(f"ttl_seconds must not exceed {MAX_TTL_SECONDS} (24 hours)")
    if issued_at is None:
        issued_at = int(time.time())
    payload = json.dumps(
        {
            "jti": uuid.uuid4().hex,
            "agent_id": agent_id,
            "human_id": human_id,
            "max_amount": max_amount,
            "allowed_categories": allowed_categories,
            "issued_at": issued_at,
            "ttl_seconds": ttl_seconds,
        },
        sort_keys=True,
    )
    signature = _sign(payload)
    token = json.dumps({"payload": payload, "signature": signature})
    return token


def verify_delegation_token(token: str, now: Optional[int] = None) -> Dict[str, Any]:
    """Returns a verification result dict:
    {valid: bool, reason: str, claims: dict|None}

    `now`: the clock to evaluate expiry against. Defaults to the real
    wall clock (production behavior, unchanged). The eval harness and
    tests pass this explicitly so results don't depend on when they
    happen to be run -- see eval/harness.py and eval/eval_manifest.json.
    """
    if now is None:
        now = int(time.time())

    try:
        wrapper = json.loads(token)
        payload = wrapper["payload"]
        signature = wrapper["signature"]
    except Exception:
        return {"valid": False, "reason": "Malformed delegation token", "claims": None}

    # Verify signature using configured identity mode
    if _identity_provider and IDENTITY_MODE == "ed25519":
        if not _identity_provider.verify_token(payload, signature):
            return {"valid": False, "reason": "Signature mismatch -- token forged or tampered", "claims": None}
    else:
        expected_sig = _sign(payload)
        if not hmac.compare_digest(expected_sig, signature):
            return {"valid": False, "reason": "Signature mismatch -- token forged or tampered", "claims": None}

    claims = json.loads(payload)

    # Back-compat: tolerate tokens minted by the old absolute-`expiry`
    # format so nothing already issued breaks.
    if "expiry" in claims:
        expiry = claims["expiry"]
    else:
        expiry = claims.get("issued_at", 0) + claims.get("ttl_seconds", 0)

    if now > expiry:
        return {"valid": False, "reason": "Delegation token expired", "claims": claims}

    if is_token_consumed(claims.get("jti")):
        return {
            "valid": False,
            "reason": "Delegation token already used for a prior transaction -- replay detected",
            "claims": claims,
        }

    return {"valid": True, "reason": "Signature and expiry valid", "claims": claims}


# ---------------------------------------------------------------------
# Replay protection: a valid, unexpired, correctly-scoped token can
# still be a *stolen* token being replayed for a second purchase.
# Real replay protection means a token is single-use once it has
# actually been used to execute a transaction (not merely verified --
# a client may legitimately call /verify more than once, e.g. to
# preview risk, before committing).
#
# This used to be a JSON file guarded by a threading.Lock. That closed
# the race between concurrent requests *inside one Python process*,
# but it does not hold across `uvicorn --workers N`: each worker is a
# separate process with its own Lock object, so two workers could each
# win their own in-process lock and both write the same jti to the
# file, racing each other on the actual write.
#
# SQLite's UNIQUE constraint + its own cross-process file locking is
# what actually gives an atomic claim here: an INSERT either succeeds
# once, ever, per jti, or raises IntegrityError -- enforced by SQLite
# itself, not by anything in this process's memory, so it holds
# whether the second attempt comes from another thread, another
# worker process, or a second `uvicorn` instance pointed at the same
# data/ directory.
# ---------------------------------------------------------------------

def _connect():
    """Returns a SQLite connection with WAL mode and the schema ready.

    Deliberately NOT used as `with _connect() as conn: ...` — a
    sqlite3.Connection used as a context manager only wraps the
    transaction (commit on success, rollback on exception); it does
    NOT close the connection afterward. Read-only call sites use
    `with contextlib.closing(_connect()) as conn:`; writes use
    `with _transaction() as conn:` (below), which handles both the
    commit/rollback AND the close. Confirmed the leak was real before
    left ~120 open file descriptors behind (DB + WAL + SHM files per
    unclosed connection) -- exactly the kind of thing that exhausts a
    process's fd limit under sustained traffic, not just a cosmetic
    warning.
    """
    conn = sqlite3.connect(CONSUMED_DB_PATH, timeout=30)
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS execution_claims (
            jti TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            audit_id TEXT,
            payment_id TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )
        """
    )
    # Outbox table: tracks payment orders that need finalization.
    # Closes the crash gap between create_test_order() and
    # finalize_execution(): if the process crashes after the order
    # is created but before finalize_execution() runs, the outbox
    # entry survives and can be replayed on next startup.
    #
    # execution_id: KYA-internal deterministic identifier for this
    #   execution attempt. NOT a Razorpay idempotency key -- provider-
    #   specific idempotency will be mapped in Phase 2.
    # agent_id / amount: stored for reconciliation with payment provider.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS finalization_outbox (
            jti TEXT PRIMARY KEY,
            audit_id TEXT NOT NULL,
            payment_id TEXT,
            execution_id TEXT,
            agent_id TEXT,
            amount REAL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )
        """
    )
    # Reconciliation log: audit trail of every reconciliation attempt.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS reconciliation_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id TEXT NOT NULL,
            execution_id TEXT NOT NULL,
            attempt_number INTEGER NOT NULL,
            search_criteria TEXT NOT NULL,
            query_result TEXT NOT NULL,
            confidence_level INTEGER NOT NULL,
            action_taken TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        """
    )
    return conn


@contextlib.contextmanager
def _transaction():
    """Yields a connection, commits on clean exit, rolls back and
    re-raises on exception, and always closes the connection.

    `with conn:` (sqlite3.Connection's own context manager) gives the
    commit/rollback half of this but never closes the connection --
    that's the leak this whole function exists to close. Every write
    call site below uses `with _transaction() as conn:` instead of a
    bare `with _connect() as conn:`.
    """
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def is_token_consumed(jti: Optional[str]) -> bool:
    if not jti:
        return False
    with contextlib.closing(_connect()) as conn:
        row = conn.execute(
            "SELECT 1 FROM execution_claims WHERE jti = ?", (jti,)
        ).fetchone()
        return row is not None


def reserve_token(jti: Optional[str]) -> bool:
    """Atomically reserve a token for one-time execution.

    The INSERT's PRIMARY KEY constraint is the atomic check-and-set:
    two concurrent callers for the same jti both attempt the INSERT,
    SQLite's own locking serializes them, and only one succeeds -- the
    other gets IntegrityError and False. There is no separate
    check-then-write window for a second caller to slip through.

    Returns True if this call reserved the token (caller may proceed
    to execute), False if it was already reserved/consumed (caller
    must not execute -- treat as replay).

    A token with no jti (shouldn't happen once a token has passed
    delegation verification, but guarded here defensively) is treated
    as unreservable-but-not-blocking: returns True so callers don't
    have to special-case it.
    """
    if not jti:
        return True
    now = int(time.time())
    try:
        with _transaction() as conn:
            conn.execute(
                "INSERT INTO execution_claims "
                "(jti, status, audit_id, payment_id, created_at, updated_at) "
                "VALUES (?, 'RESERVED', NULL, NULL, ?, ?)",
                (jti, now, now),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def release_token(jti: Optional[str]) -> None:
    """Releases a reservation that was never actually executed.

    Call this when reserve_token() succeeded but the execution it was
    reserving for then failed (e.g. the Razorpay call raised) -- so
    the token doesn't come out permanently unusable for a failure
    that never actually spent anything. Only deletes a claim that is
    still RESERVED: an EXECUTED claim represents a real completed
    transaction and must never be released, regardless of what a
    caller passes in.
    """
    if not jti:
        return
    with _transaction() as conn:
        conn.execute(
            "DELETE FROM execution_claims WHERE jti = ? AND status = 'RESERVED'",
            (jti,),
        )


def finalize_execution(jti: Optional[str], audit_id: str, payment_id: Optional[str] = None) -> None:
    """Marks a reserved token as actually executed, and attaches the
    audit_id/payment_id that didn't exist yet at reservation time.

    reserve_token() has to run *before* the audit record exists (it's
    the gate that decides whether execution is allowed at all), so
    the claim starts as RESERVED with no audit_id and is finalized
    here once the order has actually been created and audit.record()
    has produced an id.

    Also removes any outbox entry for this jti, since the
    finalization is now complete.
    """
    if not jti:
        return
    now = int(time.time())
    with _transaction() as conn:
        conn.execute(
            "UPDATE execution_claims "
            "SET status = 'EXECUTED', audit_id = ?, payment_id = ?, updated_at = ? "
            "WHERE jti = ?",
            (audit_id, payment_id, now, jti),
        )
        # Clean up outbox entry -- finalization is complete
        conn.execute(
            "DELETE FROM finalization_outbox WHERE jti = ?",
            (jti,),
        )


# ---------------------------------------------------------------------
# Outbox pattern: crash recovery for payment-audit finalization.
#
# Problem: between create_test_order() (payment is created) and
# finalize_execution() (token marked EXECUTED), a crash leaves the
# token at RESERVED with a real order behind it but no audit link.
#
# Solution: write an outbox entry BEFORE the finalization step.
# If the process crashes after order creation but before
# finalize_execution(), the outbox entry survives. On next startup
# (or first request), replay_pending_finalizations() scans for
# PENDING outbox entries and completes the finalization.
#
# Flow:
#   1. reserve_token(jti)          -> token RESERVED
#   2. create_test_order()          -> real payment exists
#   3. audit_store.record()         -> audit trail exists
#   4. write_outbox_entry(jti, audit_id, payment_id)  -> PENDING
#   5. finalize_execution(jti, audit_id, payment_id)   -> EXECUTED + outbox removed
#
# If crash happens between 4 and 5: outbox entry is PENDING.
# On restart, replay_pending_finalizations() will finalize it.
# ---------------------------------------------------------------------

def write_outbox_entry(
    jti: Optional[str],
    audit_id: str,
    payment_id: Optional[str] = None,
    execution_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    amount: Optional[float] = None,
) -> None:
    """Write an outbox entry for a pending finalization.

    Called after the payment order is created and audit record exists,
    but BEFORE finalize_execution(). This ensures that if the process
    crashes before finalization, the entry can be replayed on restart.

    execution_id: KYA-internal deterministic identifier for this
      execution attempt. NOT a Razorpay idempotency key -- provider-
      specific idempotency will be mapped in Phase 2.
    agent_id / amount: stored for reconciliation with payment provider.
    """
    if not jti:
        return
    now = int(time.time())
    try:
        with _transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO finalization_outbox "
                "(jti, audit_id, payment_id, execution_id, agent_id, amount, "
                "status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)",
                (jti, audit_id, payment_id, execution_id, agent_id, amount, now, now),
            )
    except sqlite3.IntegrityError:
        pass  # Entry already exists -- idempotent


def replay_pending_finalizations(finalizer_fn) -> int:
    """Scan for PENDING outbox entries and attempt to finalize them.

    `finalizer_fn`: callable(jti, audit_id, payment_id) that performs
    the actual finalization. In production this would be
    finalize_execution(); callers can pass a lambda that also logs,
    sends alerts, etc.

    Returns the number of entries successfully replayed.

    This should be called once at startup (or on the first request)
    to recover from any crash that left outbox entries in PENDING
    state.
    """
    replayed = 0
    with contextlib.closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT jti, audit_id, payment_id FROM finalization_outbox WHERE status = 'PENDING'"
        ).fetchall()

    for jti, audit_id, payment_id in rows:
        try:
            finalizer_fn(jti, audit_id, payment_id)
            replayed += 1
        except Exception:
            # Don't crash startup over a single failed replay --
            # log and continue. The entry stays PENDING for the next
            # attempt.
            pass

    return replayed


def get_pending_outbox_count() -> int:
    """Return the number of PENDING outbox entries.
    Useful for health checks and monitoring."""
    with contextlib.closing(_connect()) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM finalization_outbox WHERE status = 'PENDING'"
        ).fetchone()
    return row[0] if row else 0


# ---------------------------------------------------------------------
# Startup recovery: Phase 1G-A
#
# Safety invariant: NEVER release a token when the external payment
# outcome is unknown. UNKNOWN != FAILED. UNKNOWN != SAFE TO RETRY.
# UNKNOWN = RECONCILE.
# ---------------------------------------------------------------------

def recover_orphaned_reservations(find_audit_fn, update_exec_state_fn) -> dict:
    """Scan for RESERVED tokens and reconcile with audit state.

    Returns a dict with counts of each recovery action taken:
    {"released": N, "flagged_payment_unknown": N, "orphaned": N}

    Recovery rules:
    - RESERVED + no audit entry → ORPHANED (do NOT release)
    - RESERVED + audit.execution_state == PAYMENT_FAILED → release
    - RESERVED + audit.execution_state in (EXECUTION_PENDING, PAYMENT_UNKNOWN) → flag
    - RESERVED + audit.execution_state in (PAYMENT_CREATED, None, no outbox) → flag
    """
    result = {"released": 0, "flagged_payment_unknown": 0, "orphaned": 0}

    with contextlib.closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT jti FROM execution_claims WHERE status = 'RESERVED'"
        ).fetchall()

    for (jti,) in rows:
        audit = find_audit_fn(jti)

        if audit is None:
            # C2: reservation with no audit entry.
            # CRITICAL: We cannot prove the payment provider was never
            # invoked. The reservation itself is a SQLite INSERT with
            # no external side effects, BUT if we crash after calling
            # create_test_order() but before audit_store.record(), the
            # audit doesn't exist yet. The payment may have been created.
            # Therefore: DO NOT release. Flag as orphaned.
            result["orphaned"] += 1
            # Log for administrative handling
            import logging
            logging.getLogger("kya").warning(
                f"Orphaned reservation: jti={jti} has no matching audit entry. "
                f"Token NOT released -- requires administrative cleanup."
            )
            continue

        exec_state = audit.get("execution_state")

        if exec_state == "PAYMENT_FAILED":
            # Payment explicitly failed. Safe to release.
            release_token(jti)
            result["released"] += 1
            import logging
            logging.getLogger("kya").info(
                f"Released reservation: jti={jti} (PAYMENT_FAILED)"
            )

        elif exec_state in ("EXECUTION_PENDING", "PAYMENT_UNKNOWN"):
            # Ambiguous: payment may or may not have been created.
            # DO NOT release. Flag for reconciliation.
            if exec_state != "PAYMENT_UNKNOWN":
                update_exec_state_fn(audit["audit_id"], "PAYMENT_UNKNOWN")
            result["flagged_payment_unknown"] += 1
            import logging
            logging.getLogger("kya").warning(
                f"PAYMENT_UNKNOWN: jti={jti}, audit_id={audit.get('audit_id')}. "
                f"Token NOT released -- requires reconciliation."
            )

        elif exec_state in ("PAYMENT_CREATED",):
            # Outbox should exist. If it doesn't, the crash happened
            # between payment creation and outbox write. Flag as unknown.
            update_exec_state_fn(audit["audit_id"], "PAYMENT_UNKNOWN")
            result["flagged_payment_unknown"] += 1
            import logging
            logging.getLogger("kya").warning(
                f"PAYMENT_UNKNOWN (outbox missing): jti={jti}, "
                f"audit_id={audit.get('audit_id')}. Token NOT released."
            )

        elif exec_state in ("EXECUTED",):
            # Token is EXECUTED in claims but audit not yet updated.
            # This is a benign inconsistency -- update audit.
            update_exec_state_fn(audit["audit_id"], "EXECUTED")

        # else: exec_state is None (BLOCK/STEP_UP path, no execution attempted)
        # Token shouldn't be RESERVED in this case, but if it is, flag it.

    return result


# ---------------------------------------------------------------------
# Reconciliation logging (Phase 1G-B)
# ---------------------------------------------------------------------

def record_reconciliation_attempt(
    audit_id: str,
    execution_id: str,
    attempt_number: int,
    search_criteria: dict,
    query_result: dict,
    confidence_level: int,
    action_taken: str,
) -> None:
    """Record a reconciliation attempt in the log.

    Provides an audit trail of every reconciliation attempt, including
    what was searched, what was found, and what action was taken.
    """
    now = int(time.time())
    with _transaction() as conn:
        conn.execute(
            "INSERT INTO reconciliation_log "
            "(audit_id, execution_id, attempt_number, search_criteria, "
            "query_result, confidence_level, action_taken, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                audit_id,
                execution_id,
                attempt_number,
                json.dumps(search_criteria),
                json.dumps(query_result),
                confidence_level,
                action_taken,
                now,
            ),
        )


def get_reconciliation_log(audit_id: str) -> list:
    """Return all reconciliation attempts for an audit entry."""
    with contextlib.closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT search_criteria, query_result, confidence_level, "
            "action_taken, created_at FROM reconciliation_log "
            "WHERE audit_id = ? ORDER BY attempt_number ASC",
            (audit_id,),
        ).fetchall()
    return [
        {
            "search_criteria": json.loads(r[0]),
            "query_result": json.loads(r[1]),
            "confidence_level": r[2],
            "action_taken": r[3],
            "created_at": r[4],
        }
        for r in rows
    ]


def get_reconciliation_attempts_count(audit_id: str) -> int:
    """Return the number of reconciliation attempts for an audit entry."""
    with contextlib.closing(_connect()) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM reconciliation_log WHERE audit_id = ?",
            (audit_id,),
        ).fetchone()
    return row[0] if row else 0
