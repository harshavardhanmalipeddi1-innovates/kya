"""
Structured security event logging.

Captures security-relevant events (auth failures, rate limits, replay
attempts, payment decisions) in a structured JSON format for
observability, alerting, and audit correlation.

Uses only the Python standard library -- no external dependencies.
Events are written to stderr (for container/daemon log collection)
and optionally to a file for persistent audit.
"""

import json
import logging
import os
import time
from typing import Any, Dict, Optional

# Logger for security events -- separate from application logs so
# they can be routed independently (e.g. to a SIEM, Datadog, etc.)
_security_logger = logging.getLogger("kya.security")
_security_logger.setLevel(logging.INFO)

# Default: structured JSON to stderr
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(message)s"))
_security_logger.addHandler(_handler)

# Optional: file-based audit log
_audit_file_path = os.environ.get("KYA_AUDIT_LOG_FILE")
if _audit_file_path:
    _file_handler = logging.FileHandler(_audit_file_path)
    _file_handler.setFormatter(logging.Formatter("%(message)s"))
    _security_logger.addHandler(_file_handler)


def log_event(
    event_type: str,
    *,
    outcome: str = "success",
    client_ip: Optional[str] = None,
    agent_id: Optional[str] = None,
    audit_id: Optional[str] = None,
    request_id: Optional[str] = None,
    detail: Optional[str] = None,
    **extra: Any,
) -> None:
    """Log a structured security event.

    event_type: category (auth_failure, rate_limit, replay, payment, etc.)
    outcome: success, failure, blocked, step_up
    """
    event: Dict[str, Any] = {
        "ts": int(time.time()),
        "event": event_type,
        "outcome": outcome,
    }
    if client_ip:
        event["ip"] = client_ip
    if agent_id:
        event["agent_id"] = agent_id
    if audit_id:
        event["audit_id"] = audit_id
    if request_id:
        event["request_id"] = request_id
    if detail:
        event["detail"] = detail
    event.update(extra)

    try:
        _security_logger.info(json.dumps(event, default=str))
    except Exception:
        # Logging must never crash the request path
        pass


def log_auth_failure(client_ip: str, endpoint: str, reason: str = "invalid_key",
                     request_id: Optional[str] = None) -> None:
    log_event("auth_failure", outcome="blocked", client_ip=client_ip,
              request_id=request_id, detail=f"{endpoint}: {reason}")


def log_rate_limit(client_ip: str, endpoint: str, limit: int,
                    request_id: Optional[str] = None) -> None:
    log_event("rate_limit", outcome="blocked", client_ip=client_ip,
              request_id=request_id, detail=f"{endpoint} limit={limit}/min")


def log_payment_decision(agent_id: str, decision: str, total_amount: float,
                         risk_score: float, audit_id: str,
                         request_id: Optional[str] = None) -> None:
    log_event("payment_decision", outcome=decision.lower().split()[0],
              agent_id=agent_id, audit_id=audit_id, request_id=request_id,
              total_amount=total_amount, risk_score=risk_score)


def log_replay_attempt(agent_id: str, audit_id: str, jti: Optional[str] = None,
                        request_id: Optional[str] = None) -> None:
    log_event("replay_attempt", outcome="blocked",
              agent_id=agent_id, audit_id=audit_id, jti=jti,
              request_id=request_id)


def log_step_up_confirm(audit_id: str, outcome: str, agent_id: Optional[str] = None,
                         request_id: Optional[str] = None) -> None:
    log_event("step_up_confirm", outcome=outcome,
              agent_id=agent_id, audit_id=audit_id, request_id=request_id)
