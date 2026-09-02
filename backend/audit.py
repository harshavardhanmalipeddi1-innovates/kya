"""
Audit trail storage -- SQLite-backed.

Previously used a JSON file guarded by a threading.Lock. That closed
torn-write races within one process but did not hold across
`uvicorn --workers N`: each worker is a separate process with its own
Lock object, so two workers could each win their own in-process lock
and race on the actual file write.

SQLite's own file locking and WAL mode give the same cross-process
safety that registry.py already uses for replay protection. The
schema stores each audit entry as a JSON blob in a TEXT column --
the API contract (record/get_all/get_one/update) is unchanged.
"""

import json
import os
import sqlite3
import contextlib
import time
import uuid
from typing import Dict, Any, List, Optional

import threading

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
AUDIT_DB_PATH = os.path.join(DATA_DIR, "audit_trail.db")

# Write lock: serializes record()/update() calls within a single
# process. SQLite's own file locking handles cross-process safety,
# but this prevents the WAL-mode TOCTOU where two in-process
# threads both read the same state and both decide to transition.
_WRITE_LOCK = threading.Lock()

# Back-compat: test files may reassign this to a temp path
# (same pattern as registry.CONSUMED_DB_PATH).
_AUDIT_DB_PATH_OVERRIDE: Optional[str] = None


def _db_path() -> str:
    return _AUDIT_DB_PATH_OVERRIDE or AUDIT_DB_PATH


# Allow tests to redirect storage (mirrors how registry.py lets
# tests point CONSUMED_DB_PATH at a temp file).
class _PathProxy:
    """Module-level AUDIT_DB_PATH that tests can reassign."""
    def __init__(self):
        self._value = AUDIT_DB_PATH

    @property
    def value(self):
        return _AUDIT_DB_PATH_OVERRIDE or self._value

    @value.setter
    def value(self, v):
        global _AUDIT_DB_PATH_OVERRIDE
        _AUDIT_DB_PATH_OVERRIDE = v


# Expose as module-level attribute for test compatibility.
# Tests do: audit.AUDIT_PATH = os.path.join(tmpdir, "audit_log.json")
# We keep AUDIT_PATH as a mutable string so that assignment works.
# When tests assign a path, _connect() uses it as the SQLite DB path
# (or derives one from the directory if it's a directory).
AUDIT_PATH = AUDIT_DB_PATH


def _connect() -> sqlite3.Connection:
    """Open a SQLite connection with WAL mode and schema ready."""
    db = AUDIT_PATH if isinstance(AUDIT_PATH, str) else str(AUDIT_PATH)
    # If AUDIT_PATH was reassigned to a directory-style path,
    # derive the DB file from it.
    if os.path.isdir(db):
        db = os.path.join(db, "audit_trail.db")
    conn = sqlite3.connect(db, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    # Allow up to 5 seconds of busy-wait when the DB is locked by
    # another thread/process, instead of immediately raising.
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_entries (
            audit_id TEXT PRIMARY KEY,
            entry_json TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        """
    )
    return conn


@contextlib.contextmanager
def _transaction():
    """Yields a connection, commits on clean exit, rolls back and
    re-raises on exception, and always closes the connection.

    SQLite's WAL mode + busy_timeout handles concurrent access:
    writers are serialized by SQLite's internal lock, and
    busy_timeout causes automatic retry instead of immediate failure.
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


def record(entry: Dict[str, Any]) -> str:
    """Append a new audit entry. Returns the generated audit_id."""
    entry_id = f"audit_{uuid.uuid4().hex[:10]}"
    entry["audit_id"] = entry_id
    entry["timestamp"] = int(time.time())
    now = int(time.time())
    with _WRITE_LOCK:
        with _transaction() as conn:
            conn.execute(
                "INSERT INTO audit_entries (audit_id, entry_json, created_at) VALUES (?, ?, ?)",
                (entry_id, json.dumps(entry, default=str), now),
            )
    return entry_id


def _load() -> List[Dict[str, Any]]:
    """Backward-compat: return all entries as a list (oldest first).
    Used by tests that inspect raw audit state."""
    with contextlib.closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT entry_json FROM audit_entries ORDER BY created_at ASC, audit_id ASC"
        ).fetchall()
    return [json.loads(row[0]) for row in rows]


def get_all() -> List[Dict[str, Any]]:
    """Return all entries, most recent first."""
    with contextlib.closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT entry_json FROM audit_entries ORDER BY created_at DESC, audit_id DESC"
        ).fetchall()
    return [json.loads(row[0]) for row in rows]


def get_one(audit_id: str) -> Optional[Dict[str, Any]]:
    """Return one entry by audit_id, or None."""
    with contextlib.closing(_connect()) as conn:
        row = conn.execute(
            "SELECT entry_json FROM audit_entries WHERE audit_id = ?", (audit_id,)
        ).fetchone()
    return json.loads(row[0]) if row else None


def update(audit_id: str, expected_status: str, updates: Dict[str, Any]) -> bool:
    """Atomically transitions one audit entry's decision field.

    Reads the current entry, checks that its "decision" equals
    `expected_status`, applies the updates, and writes it back -- all
    within a single SQLite transaction, serialized by _WRITE_LOCK.

    The write lock prevents the WAL-mode TOCTOU where two in-process
    threads both read STEP_UP and both decide to transition. SQLite's
    own file locking handles cross-process safety.

    Returns True if the transition was applied, False if the entry
    wasn't found or wasn't in `expected_status`.
    """
    with _WRITE_LOCK:
        with _transaction() as conn:
            row = conn.execute(
                "SELECT entry_json FROM audit_entries WHERE audit_id = ?", (audit_id,)
            ).fetchone()
            if row is None:
                return False
            entry = json.loads(row[0])
            if entry.get("decision") != expected_status:
                return False
            entry.update(updates)
            conn.execute(
                "UPDATE audit_entries SET entry_json = ? WHERE audit_id = ?",
                (json.dumps(entry, default=str), audit_id),
            )
            return True


def find_audit_by_jti(jti: str) -> Optional[Dict[str, Any]]:
    """Find an audit entry by its delegation token jti.

    Scans all audit entries for one whose JSON contains a matching
    "jti" field. Used by startup recovery to correlate RESERVED
    tokens with their audit records.

    Returns the entry dict (with audit_id) or None.
    """
    if not jti:
        return None
    with contextlib.closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT audit_id, entry_json FROM audit_entries"
        ).fetchall()
    for audit_id, entry_json in rows:
        entry = json.loads(entry_json)
        if entry.get("jti") == jti:
            entry["audit_id"] = audit_id
            return entry
    return None


def update_execution_state(audit_id: str, execution_state: str) -> bool:
    """Update only the execution_state field of an audit entry.

    Unlike update(), this does NOT require an expected_status check --
    it unconditionally sets the execution_state field. Used by startup
    recovery to flag PAYMENT_UNKNOWN states.

    Returns True if the entry was found and updated.
    """
    with _WRITE_LOCK:
        with _transaction() as conn:
            row = conn.execute(
                "SELECT entry_json FROM audit_entries WHERE audit_id = ?",
                (audit_id,),
            ).fetchone()
            if row is None:
                return False
            entry = json.loads(row[0])
            entry["execution_state"] = execution_state
            conn.execute(
                "UPDATE audit_entries SET entry_json = ? WHERE audit_id = ?",
                (json.dumps(entry, default=str), audit_id),
            )
            return True


def get_pending_reconciliation_count() -> int:
    """Count audit entries requiring reconciliation.

    Used by the health endpoint to report pending reconciliations.
    Counts: PAYMENT_UNKNOWN, RECONCILE_PENDING, RECONCILE_RETRYING,
    MANUAL_REQUIRED, EXECUTION_PENDING.
    """
    RECONCILE_STATES = {
        "PAYMENT_UNKNOWN", "RECONCILE_PENDING", "RECONCILE_RETRYING",
        "MANUAL_REQUIRED", "EXECUTION_PENDING",
    }
    with contextlib.closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT entry_json FROM audit_entries"
        ).fetchall()
    count = 0
    for (entry_json,) in rows:
        entry = json.loads(entry_json)
        if entry.get("execution_state") in RECONCILE_STATES:
            count += 1
    return count
