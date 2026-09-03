"""
Reconciliation Worker — Phase 3F-3H.

Resolves PAYMENT_UNKNOWN states by querying the payment provider.

Flow:
  PAYMENT_UNKNOWN
      -> search provider for matching order
      -> EXACT_MATCH: inspect order + payments -> determine state
      -> NO_MATCH: retry per policy, eventually MANUAL_REQUIRED
      -> AMBIGUOUS: MANUAL_REQUIRED immediately
      -> QUERY_FAILED: retry per policy

Rules:
  - NEVER release token during reconciliation
  - NEVER blindly create a second order
  - NO_MATCH != order definitely doesn't exist
  - Token stays RESERVED throughout
"""

import logging
import time
from typing import Dict, Any, Optional, List

from payment_provider import (
    PaymentProvider, OrderSearchCriteria, OrderSearchStatus,
)

logger = logging.getLogger("kya")

# Reconciliation retry policy: (attempt_number -> delay_seconds)
# Attempt 1: immediate (0), Attempt 2: 30s, Attempt 3: 5min, etc.
RETRY_DELAYS = [0, 30, 300, 1800, 7200]  # 0, 30s, 5m, 30m, 2h
MAX_AUTO_RECONCILIATION_ATTEMPTS = 5


class ReconciliationResult:
    """Result of a reconciliation attempt."""

    def __init__(
        self,
        action: str,
        execution_state: str = None,
        order_id: str = None,
        payment_status: str = None,
        details: str = None,
        requires_manual: bool = False,
    ):
        self.action = action  # "finalized", "retry", "manual_required", "still_unknown"
        self.execution_state = execution_state
        self.order_id = order_id
        self.payment_status = payment_status
        self.details = details
        self.requires_manual = requires_manual

    def to_dict(self):
        return {
            "action": self.action,
            "execution_state": self.execution_state,
            "order_id": self.order_id,
            "payment_status": self.payment_status,
            "details": self.details,
            "requires_manual": self.requires_manual,
        }


def reconcile(
    provider: PaymentProvider,
    execution_id: str,
    agent_id: str = None,
    amount: float = None,
    currency: str = "INR",
    attempt_number: int = 1,
) -> ReconciliationResult:
    """Attempt to reconcile a PAYMENT_UNKNOWN execution.

    Args:
        provider: PaymentProvider to query
        execution_id: KYA execution_id (used as receipt correlation)
        agent_id: Agent ID for additional filtering
        amount: Expected amount for validation
        currency: Expected currency
        attempt_number: Current attempt (1-based) for retry policy

    Returns:
        ReconciliationResult with action and state recommendations
    """
    logger.info(
        f"Reconciliation attempt {attempt_number} for execution {execution_id}"
    )

    # Search for the order using execution_id as receipt correlation
    criteria = OrderSearchCriteria(
        receipt=execution_id[:40],  # Razorpay max receipt length
        agent_id=agent_id,
        amount=amount,
        currency=currency,
    )

    search_result = provider.search_orders(criteria)

    if search_result.status == OrderSearchStatus.EXACT_MATCH:
        return _handle_exact_match(provider, search_result.orders[0])

    elif search_result.status == OrderSearchStatus.NO_MATCH:
        return _handle_no_match(attempt_number, execution_id)

    elif search_result.status == OrderSearchStatus.AMBIGUOUS:
        return ReconciliationResult(
            action="manual_required",
            requires_manual=True,
            details=f"Ambiguous: {len(search_result.orders)} candidate orders found",
        )

    elif search_result.status == OrderSearchStatus.QUERY_FAILED:
        return _handle_query_failure(attempt_number, execution_id, search_result.error)

    else:
        return ReconciliationResult(
            action="still_unknown",
            details=f"Unexpected search status: {search_result.status}",
        )


def _handle_exact_match(provider, order) -> ReconciliationResult:
    """Handle exact order match — inspect order and payment status."""
    logger.info(f"Exact match found: order {order.id}, status={order.status}")

    # Fetch payments for this order
    payments = provider.get_order_payments(order.id)

    if not payments:
        # Order exists but no payments yet
        if order.status == "created":
            return ReconciliationResult(
                action="retry",
                execution_state="PAYMENT_CREATED",
                order_id=order.id,
                details="Order created, no payments yet",
            )
        elif order.status == "paid":
            return ReconciliationResult(
                action="finalized",
                execution_state="EXECUTED",
                order_id=order.id,
                payment_status="captured",
                details="Order paid, no payment records (legacy)",
            )

    # Check payment statuses
    for payment in payments:
        if payment.status == "captured":
            return ReconciliationResult(
                action="finalized",
                execution_state="EXECUTED",
                order_id=order.id,
                payment_status="captured",
                details=f"Payment {payment.id} captured",
            )
        elif payment.status == "authorized":
            return ReconciliationResult(
                action="retry",
                execution_state="PAYMENT_CREATED",
                order_id=order.id,
                payment_status="authorized",
                details=f"Payment {payment.id} authorized, awaiting capture",
            )
        elif payment.status == "failed":
            return ReconciliationResult(
                action="finalized",
                execution_state="PAYMENT_FAILED",
                order_id=order.id,
                payment_status="failed",
                details=f"Payment {payment.id} failed",
            )

    return ReconciliationResult(
        action="retry",
        execution_state="PAYMENT_CREATED",
        order_id=order.id,
        details=f"Order found with {len(payments)} payments, none in terminal state",
    )


def _handle_no_match(attempt_number, execution_id) -> ReconciliationResult:
    """Handle no match — apply retry policy."""
    if attempt_number >= MAX_AUTO_RECONCILIATION_ATTEMPTS:
        return ReconciliationResult(
            action="manual_required",
            requires_manual=True,
            details=f"No match after {attempt_number} attempts for {execution_id}",
        )

    next_delay = RETRY_DELAYS[min(attempt_number, len(RETRY_DELAYS) - 1)]
    return ReconciliationResult(
        action="retry",
        details=f"No match on attempt {attempt_number}, next retry in {next_delay}s",
    )


def _handle_query_failure(attempt_number, execution_id, error) -> ReconciliationResult:
    """Handle provider query failure — retry per policy."""
    if attempt_number >= MAX_AUTO_RECONCILIATION_ATTEMPTS:
        return ReconciliationResult(
            action="manual_required",
            requires_manual=True,
            details=f"Query failed after {attempt_number} attempts: {error}",
        )

    return ReconciliationResult(
        action="retry",
        details=f"Query failed on attempt {attempt_number}: {error}",
    )


def get_retry_delay(attempt_number: int) -> int:
    """Return the delay in seconds before the next reconciliation attempt."""
    idx = min(attempt_number - 1, len(RETRY_DELAYS) - 1)
    return RETRY_DELAYS[idx]
