"""
End-to-End Request Tracing.

Provides a TraceContext that flows through the entire KYA request lifecycle,
linking: request_id -> audit_id -> execution_id -> payment_id -> reconciliation_id.

Every security-critical event (auth, decision, payment, webhook, reconciliation)
is stamped with the same trace context, making full forensic reconstruction
possible from any single ID.

Usage:
    from trace import TraceContext
    ctx = TraceContext.create(request_id="abc123")
    # ... pass through pipeline ...
    ctx.set_audit_id("audit_xyz")
    ctx.set_execution_id("exec_abc")
    ctx.set_payment_id("pay_123")
    trace_log = ctx.finalize()
"""

import time
import json
import logging
import sqlite3
import os
import contextlib
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
TRACE_DB_PATH = os.path.join(DATA_DIR, "traces.db")


@dataclass
class TraceContext:
    """Correlation context for a single KYA request lifecycle."""

    request_id: str
    audit_id: Optional[str] = None
    execution_id: Optional[str] = None
    payment_id: Optional[str] = None
    reconciliation_id: Optional[str] = None
    agent_id: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    events: List[Dict[str, Any]] = field(default_factory=list)
    finalized: bool = False

    def set_audit_id(self, audit_id: str) -> None:
        self.audit_id = audit_id
        self._add_event("audit_id_set", {"audit_id": audit_id})

    def set_execution_id(self, execution_id: str) -> None:
        self.execution_id = execution_id
        self._add_event("execution_id_set", {"execution_id": execution_id})

    def set_payment_id(self, payment_id: str) -> None:
        self.payment_id = payment_id
        self._add_event("payment_id_set", {"payment_id": payment_id})

    def set_reconciliation_id(self, reconciliation_id: str) -> None:
        self.reconciliation_id = reconciliation_id
        self._add_event("reconciliation_id_set", {"reconciliation_id": reconciliation_id})

    def set_agent_id(self, agent_id: str) -> None:
        self.agent_id = agent_id

    def log_event(self, event_type: str, details: Optional[Dict[str, Any]] = None) -> None:
        self._add_event(event_type, details or {})

    def _add_event(self, event_type: str, details: Dict[str, Any]) -> None:
        self.events.append({
            "ts": time.time(),
            "event": event_type,
            "details": details,
        })

    def finalize(self) -> Dict[str, Any]:
        """Persist the complete trace and return the summary."""
        self.finalized = True
        summary = {
            "request_id": self.request_id,
            "audit_id": self.audit_id,
            "execution_id": self.execution_id,
            "payment_id": self.payment_id,
            "reconciliation_id": self.reconciliation_id,
            "agent_id": self.agent_id,
            "created_at": self.created_at,
            "finalized_at": time.time(),
            "event_count": len(self.events),
            "events": self.events,
        }
        _persist_trace(summary)
        return summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "audit_id": self.audit_id,
            "execution_id": self.execution_id,
            "payment_id": self.payment_id,
            "reconciliation_id": self.reconciliation_id,
            "agent_id": self.agent_id,
            "event_count": len(self.events),
        }


def _connect() -> sqlite3.Connection:
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(TRACE_DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS traces (
            request_id TEXT PRIMARY KEY,
            trace_json TEXT NOT NULL,
            created_at REAL NOT NULL,
            finalized_at REAL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_trace_agent
        ON traces (json_extract(trace_json, '$.agent_id'))
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_trace_audit
        ON traces (json_extract(trace_json, '$.audit_id'))
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_trace_execution
        ON traces (json_extract(trace_json, '$.execution_id'))
    """)
    return conn


def _persist_trace(summary: Dict[str, Any]) -> None:
    try:
        with contextlib.closing(_connect()) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO traces (request_id, trace_json, created_at, finalized_at)
                VALUES (?, ?, ?, ?)
            """, (
                summary["request_id"],
                json.dumps(summary, default=str),
                summary["created_at"],
                summary.get("finalized_at"),
            ))
            conn.commit()
    except Exception:
        logging.getLogger("kya").exception("Failed to persist trace %s", summary.get("request_id"))


def lookup_by_audit_id(audit_id: str) -> Optional[Dict[str, Any]]:
    """Find the trace for a given audit_id."""
    with contextlib.closing(_connect()) as conn:
        row = conn.execute(
            "SELECT trace_json FROM traces WHERE json_extract(trace_json, '$.audit_id') = ?",
            (audit_id,),
        ).fetchone()
    return json.loads(row[0]) if row else None


def lookup_by_execution_id(execution_id: str) -> Optional[Dict[str, Any]]:
    """Find the trace for a given execution_id."""
    with contextlib.closing(_connect()) as conn:
        row = conn.execute(
            "SELECT trace_json FROM traces WHERE json_extract(trace_json, '$.execution_id') = ?",
            (execution_id,),
        ).fetchone()
    return json.loads(row[0]) if row else None


def lookup_by_request_id(request_id: str) -> Optional[Dict[str, Any]]:
    """Find a trace by its request_id."""
    with contextlib.closing(_connect()) as conn:
        row = conn.execute(
            "SELECT trace_json FROM traces WHERE request_id = ?",
            (request_id,),
        ).fetchone()
    return json.loads(row[0]) if row else None


def get_recent_traces(limit: int = 50) -> List[Dict[str, Any]]:
    """Return the most recent traces."""
    with contextlib.closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT trace_json FROM traces ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [json.loads(row[0]) for row in rows]


def get_trace_stats() -> Dict[str, Any]:
    """Return summary statistics for the trace store."""
    with contextlib.closing(_connect()) as conn:
        total = conn.execute("SELECT COUNT(*) FROM traces").fetchone()[0]
        finalized = conn.execute("SELECT COUNT(*) FROM traces WHERE finalized_at IS NOT NULL").fetchone()[0]
    return {"total_traces": total, "finalized": finalized, "pending": total - finalized}


def record_trace(audit_entry: Dict[str, Any]) -> None:
    """Record an audit entry into the trace store."""
    req_id = audit_entry.get("request_id") or f"req_{audit_entry.get('audit_id', 'unknown')}"
    ctx = TraceContext.create(request_id=req_id, agent_id=audit_entry.get("agent_id"))
    ctx.set_audit_id(audit_entry.get("audit_id", ""))
    if audit_entry.get("executed"):
        ctx.set_execution_id(audit_entry.get("execution_id", ""))
    payment = audit_entry.get("payment")
    if payment and isinstance(payment, dict) and payment.get("razorpay_order_id"):
        ctx.set_payment_id(payment["razorpay_order_id"])
    ctx.finalize()
