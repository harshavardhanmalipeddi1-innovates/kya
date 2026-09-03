"""
Rolling Behavioral Baselines.

Maintains a per-agent transaction history in SQLite so the risk scorer
can compute adaptive rolling statistics (mean, std, count) from actual
transaction amounts, instead of relying solely on static baselines
seeded in agents.json.

This replaces the static baseline_mean_amount / baseline_std_amount
with rolling values that update after each completed transaction.
The static baselines serve as cold-start defaults when fewer than
MIN_SAMPLES transactions have been recorded for an agent.

Design:
  - One SQLite DB per deployment (data/baselines.db)
  - WAL mode for concurrent reads without blocking
  - Each row stores (agent_id, amount, timestamp) — append-only
  - Rolling stats computed over a configurable window (default 100 txns)
  - Thread-safe: uses Python's sqlite3 file locking + busy_timeout

The baseline DB is separate from execution_claims.db and audit_trail.db
to keep concerns isolated and simplify backup/rotation.
"""

import json
import logging
import os
import sqlite3
import contextlib
import time
from typing import Optional, Dict, Any, List, Tuple

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
BASELINE_DB_PATH = os.path.join(DATA_DIR, "baselines.db")

# Minimum number of transactions before rolling stats replace static baselines.
# Below this threshold, the static baseline from agents.json is used.
MIN_SAMPLES = 5

# Maximum number of transactions to retain per agent (sliding window).
# Older transactions are pruned to keep the DB and computation bounded.
MAX_WINDOW = 100

# Poisoning detection: if the rolling mean deviates more than this
# factor from the static baseline, flag it. A factor of 3.0 means
# the rolling mean must be within 0.33x-3.0x the static baseline.
# This prevents an attacker from "teaching" the system that ₹1 is
# a normal spend by flooding it with tiny transactions.
POISONING_DEVIATION_FACTOR = 3.0

# Minimum ratio of rolling to static baseline to consider poisoned.
# If rolling_mean < static_mean / POISONING_DEVIATION_FACTOR, flag.
# If rolling_mean > static_mean * POISONING_DEVIATION_FACTOR, flag.
POISONING_MIN_RATIO = 1.0 / POISONING_DEVIATION_FACTOR
POISONING_MAX_RATIO = POISONING_DEVIATION_FACTOR

# Minimum effective standard deviation as a fraction of the static mean.
# Prevents an attacker from collapsing variance to near-zero by flooding
# identical tiny transactions, which would make even small amounts look
# like extreme outliers.
MIN_STD_FRACTION = 0.10  # std must be at least 10% of static mean

# Velocity window: number of seconds in which to detect rapid flooding.
# If more than VELOCITY_TXN_THRESHOLD transactions arrive within this
# window for a single agent, flag as potential baseline poisoning attack.
VELOCITY_WINDOW_SECONDS = 300  # 5 minutes
VELOCITY_TXN_THRESHOLD = 20    # more than 20 txns in 5 min = suspicious

# ---------------------------------------------------------------------
# Connection management — mirrors registry.py's pattern
# ---------------------------------------------------------------------

def _connect() -> sqlite3.Connection:
    """Open a SQLite connection with WAL mode and schema ready."""
    conn = sqlite3.connect(BASELINE_DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS transaction_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            amount REAL NOT NULL,
            timestamp INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_txn_agent_time
        ON transaction_history (agent_id, timestamp DESC)
        """
    )
    return conn


@contextlib.contextmanager
def _transaction():
    """Yields a connection, commits on clean exit, rolls back and re-raises,
    and always closes the connection."""
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

def record_transaction(agent_id: str, amount: float) -> None:
    """Record a completed transaction amount for an agent.

    Called after a successful payment execution. Appends a row to
    the history table and prunes old entries beyond MAX_WINDOW.
    """
    now = int(time.time())
    with _transaction() as conn:
        conn.execute(
            "INSERT INTO transaction_history (agent_id, amount, timestamp) VALUES (?, ?, ?)",
            (agent_id, amount, now),
        )
        # Prune: keep only the most recent MAX_WINDOW transactions per agent
        conn.execute(
            """
            DELETE FROM transaction_history
            WHERE agent_id = ? AND id NOT IN (
                SELECT id FROM transaction_history
                WHERE agent_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            )
            """,
            (agent_id, agent_id, MAX_WINDOW),
        )


def get_rolling_stats(agent_id: str) -> Optional[Dict[str, Any]]:
    """Compute rolling mean/std/count for an agent's recent transactions.

    Returns None if the agent has no transaction history yet.
    Returns a dict with mean, std, count, and individual amounts for
    the caller to use in risk scoring.
    """
    with contextlib.closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT amount FROM transaction_history WHERE agent_id = ? ORDER BY timestamp DESC LIMIT ?",
            (agent_id, MAX_WINDOW),
        ).fetchall()

    if not rows:
        return None

    amounts = [row[0] for row in rows]
    n = len(amounts)
    mean = sum(amounts) / n
    variance = sum((a - mean) ** 2 for a in amounts) / max(n - 1, 1)
    std = variance ** 0.5

    return {
        "mean": round(mean, 2),
        "std": round(std, 2),
        "count": n,
        "min": round(min(amounts), 2),
        "max": round(max(amounts), 2),
    }


def get_transaction_count(agent_id: str) -> int:
    """Return the number of recorded transactions for an agent."""
    with contextlib.closing(_connect()) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM transaction_history WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
    return row[0] if row else 0



def check_velocity(agent_id: str) -> Dict[str, Any]:
    """Detect rapid transaction flooding that could poison the baseline.

    Returns a dict with 'suspicious' bool and details about the
    transaction rate within the velocity window.
    """
    cutoff = int(time.time()) - VELOCITY_WINDOW_SECONDS
    with contextlib.closing(_connect()) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM transaction_history WHERE agent_id = ? AND timestamp > ?",
            (agent_id, cutoff),
        ).fetchone()
    recent_count = row[0] if row else 0

    suspicious = recent_count > VELOCITY_TXN_THRESHOLD
    result = {
        "suspicious": suspicious,
        "recent_count": recent_count,
        "window_seconds": VELOCITY_WINDOW_SECONDS,
        "threshold": VELOCITY_TXN_THRESHOLD,
    }

    if suspicious:
        logging.getLogger("kya").warning(
            f"VELOCITY ANOMALY for {agent_id}: {recent_count} transactions in "
            f"{VELOCITY_WINDOW_SECONDS}s (threshold={VELOCITY_TXN_THRESHOLD})"
        )

    return result


def clamp_baseline(rolling_mean: float, rolling_std: float,
                    static_mean: float, static_std: float) -> Tuple[float, float, str]:
    """Clamp rolling baseline to safe bounds relative to static baseline.

    Prevents an attacker from manipulating the rolling baseline beyond
    the poisoning deviation factor. When clamping is applied, returns
    source='clamped' so the audit trail records that protection activated.
    """
    if static_mean <= 0:
        return rolling_mean, rolling_std, "rolling"

    # Compute safe bounds
    floor_mean = static_mean * POISONING_MIN_RATIO
    ceiling_mean = static_mean * POISONING_MAX_RATIO
    min_std = static_mean * MIN_STD_FRACTION

    clamped = False
    effective_mean = rolling_mean
    effective_std = rolling_std

    if effective_mean < floor_mean:
        effective_mean = floor_mean
        clamped = True
    elif effective_mean > ceiling_mean:
        effective_mean = ceiling_mean
        clamped = True

    if effective_std < min_std:
        effective_std = min_std
        clamped = True

    source = "clamped" if clamped else "rolling"
    return effective_mean, effective_std, source


def get_effective_baseline(agent_id: str, static_mean: float, static_std: float) -> Tuple[float, float, str]:
    """Return the effective (mean, std, source) for risk scoring.

    If enough rolling samples exist (>= MIN_SAMPLES), returns the
    rolling statistics clamped to safe bounds. Otherwise falls back
    to the static baseline from agents.json.

    Active protection:
    1. If poisoning is detected, falls back to static baseline.
    2. Rolling stats are clamped within POISONING_DEVIATION_FACTOR.
    3. Std is floored at MIN_STD_FRACTION of static mean.
    4. Velocity anomalies are checked and logged.
    """
    # Check velocity first (logging only)
    check_velocity(agent_id)

    stats = get_rolling_stats(agent_id)
    if stats and stats["count"] >= MIN_SAMPLES:
        # Check if poisoning is active — if so, fall back to static
        poisoning = detect_poisoning(agent_id, static_mean, static_std)
        if poisoning:
            logging.getLogger("kya").warning(
                f"Poisoning detected for {agent_id}, falling back to static baseline"
            )
            return static_mean, static_std, "static_fallback"

        # Clamp rolling stats to safe bounds
        effective_mean, effective_std, source = clamp_baseline(
            stats["mean"], stats["std"], static_mean, static_std
        )
        return effective_mean, effective_std, source

    # Cold-start: not enough data yet, use static baseline
    return static_mean, static_std, "static"


def detect_poisoning(agent_id: str, static_mean: float, static_std: float) -> Optional[Dict[str, Any]]:
    """Check if the rolling baseline has been poisoned (deviates excessively
    from the static baseline).

    Returns None if no poisoning detected.
    Returns a dict with poisoning details if detected.

    Poisoning is detected when:
    - Enough rolling samples exist (>= MIN_SAMPLES)
    - The rolling mean deviates beyond POISONING_DEVIATION_FACTOR
      from the static baseline

    This catches an attacker who floods the system with tiny transactions
    to lower the baseline, then makes a large transaction that passes
    risk scoring.
    """
    stats = get_rolling_stats(agent_id)
    if not stats or stats["count"] < MIN_SAMPLES:
        return None

    if static_mean <= 0:
        return None

    rolling_mean = stats["mean"]
    ratio = rolling_mean / static_mean

    if ratio < POISONING_MIN_RATIO or ratio > POISONING_MAX_RATIO:
        direction = "below" if ratio < POISONING_MIN_RATIO else "above"
        deviation_pct = abs(ratio - 1.0) * 100

        poisoning_info = {
            "detected": True,
            "direction": direction,
            "rolling_mean": rolling_mean,
            "static_mean": static_mean,
            "ratio": round(ratio, 3),
            "deviation_pct": round(deviation_pct, 1),
            "threshold_factor": POISONING_DEVIATION_FACTOR,
            "rolling_count": stats["count"],
            "message": (
                f"Rolling baseline for {agent_id} has deviated {direction} "
                f"static baseline by {deviation_pct:.0f}% "
                f"(rolling mean={rolling_mean:.0f}, static mean={static_mean:.0f}, "
                f"ratio={ratio:.3f}). Possible baseline poisoning."
            ),
        }

        logging.getLogger("kya").warning(
            f"BASELINE POISONING DETECTED for {agent_id}: "
            f"rolling_mean={rolling_mean:.0f}, static_mean={static_mean:.0f}, "
            f"ratio={ratio:.3f}, direction={direction}, "
            f"deviation={deviation_pct:.0f}%"
        )

        return poisoning_info

    return None


# ---------------------------------------------------------------------
# Admin / debug helpers
# ---------------------------------------------------------------------

def get_all_baselines() -> Dict[str, Dict[str, Any]]:
    """Return rolling stats for all agents with transaction history.
    Useful for monitoring / admin dashboards."""
    with contextlib.closing(_connect()) as conn:
        agents = conn.execute(
            "SELECT DISTINCT agent_id FROM transaction_history"
        ).fetchall()

    result = {}
    for (agent_id,) in agents:
        stats = get_rolling_stats(agent_id)
        if stats:
            result[agent_id] = stats
    return result


def clear_history(agent_id: Optional[str] = None) -> int:
    """Clear transaction history. If agent_id is given, only clears
    that agent's history. Returns the number of rows deleted."""
    with _transaction() as conn:
        if agent_id:
            cursor = conn.execute(
                "DELETE FROM transaction_history WHERE agent_id = ?",
                (agent_id,),
            )
        else:
            cursor = conn.execute("DELETE FROM transaction_history")
        return cursor.rowcount
