"""
Razorpay Provider Adapter — Phase 2.

Implements the PaymentProvider interface for real Razorpay API calls.
Requires the `razorpay` package and environment variables:
  - RAZORPAY_KEY_ID
  - RAZORPAY_KEY_SECRET

This adapter is NOT used by default. The application selects the
provider based on KYA_PAYMENT_PROVIDER env var:
  - "mock" (default): uses MockPaymentProvider for testing
  - "razorpay": uses RazorpayProvider for real payments

The mock remains the default to preserve deterministic regression testing.
"""

import os
import time
import logging
from typing import Dict, List, Optional
from enum import Enum

from payment_provider import (
    PaymentProvider,
    OrderResult,
    OrderDetail,
    PaymentDetail,
    OrderSearchCriteria,
    SearchResult,
    OrderSearchStatus,
)

logger = logging.getLogger("kya")

class ProviderErrorType(Enum):
    """Classification of provider errors for KYA state mapping."""
    EXPLICIT_REJECTION = "explicit_rejection"   # 4xx, invalid request
    TIMEOUT = "timeout"                         # network timeout
    CONNECTION_ERROR = "connection_error"        # connection reset, DNS failure
    UNKNOWN = "unknown"                          # 5xx, unexpected errors


# Razorpay expects amounts in the smallest currency unit (paise for INR).
# KYA stores amounts as float INR. This multiplier converts between them.
RAZORPAY_PAISE_MULTIPLIER = 100

# Maximum receipt length supported by Razorpay (40 characters).
RAZORPAY_MAX_RECEIPT_LENGTH = 40


class RazorpayProvider(PaymentProvider):
    """Real Razorpay API adapter.

    Implements PaymentProvider for live Razorpay test-mode or production.
    Requires the `razorpay` Python package and valid credentials.

    Usage:
        provider = RazorpayProvider()  # reads env vars
        result = provider.create_order(amount=500.0, currency="INR", receipt="exec_abc123")

    The receipt field is used as KYA's correlation key for reconciliation.
    Razorpay does NOT guarantee idempotent order creation via receipt —
    this is used for search/reconciliation only, not as an idempotency key.
    """

    def __init__(self):
        self._key_id = os.environ.get("RAZORPAY_KEY_ID")
        self._key_secret = os.environ.get("RAZORPAY_KEY_SECRET")

        if not self._key_id or not self._key_secret:
            raise RuntimeError(
                "RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET must be set "
                "when using RazorpayProvider. "
                "Set KYA_PAYMENT_PROVIDER=mock to use the mock provider."
            )

        try:
            import razorpay
            self._client = razorpay.Client(auth=(self._key_id, self._key_secret))
        except ImportError:
            raise RuntimeError(
                "The 'razorpay' package is required for RazorpayProvider. "
                "Install it with: pip install razorpay"
            )

    @staticmethod
    def _validate_amount(amount):
        """Validate and convert INR amount to paise."""
        if not isinstance(amount, (int, float)):
            raise ValueError(f"Amount must be numeric, got {type(amount).__name__}")
        if amount != amount:  # NaN
            raise ValueError("Amount must not be NaN")
        if amount == float("inf") or amount == float("-inf"):
            raise ValueError("Amount must not be infinite")
        if amount <= 0:
            raise ValueError(f"Amount must be positive, got {amount}")
        paise = int(amount * RAZORPAY_PAISE_MULTIPLIER)
        if paise <= 0:
            raise ValueError(f"Amount too small: {amount} INR = {paise} paise")
        return paise


    @staticmethod
    def _classify_error(e):
        """Classify an exception into a provider error type."""
        msg = str(e).lower()
        if "timeout" in msg or "timed out" in msg:
            return ProviderErrorType.TIMEOUT
        if "connection" in msg or "refused" in msg or "reset" in msg:
            return ProviderErrorType.CONNECTION_ERROR
        if any(code in msg for code in ("400", "401", "403", "404")):
            return ProviderErrorType.EXPLICIT_REJECTION
        if "invalid" in msg and ("key" in msg or "auth" in msg):
            return ProviderErrorType.EXPLICIT_REJECTION
        return ProviderErrorType.UNKNOWN
    def create_order(
        self,
        amount: float,
        currency: str,
        receipt: str,
        notes: Optional[Dict[str, str]] = None,
    ) -> OrderResult:
        """Create a Razorpay order.

        Args:
            amount: Amount in INR (will be converted to paise)
            currency: Currency code (e.g., "INR")
            receipt: KYA execution_id (max 40 chars)
            notes: Additional metadata

        Returns:
            OrderResult with success status and order details
        """
        # Validate amount before any API call
        try:
            amount_paise = self._validate_amount(amount)
        except ValueError as e:
            logger.error(f"Razorpay order rejected: {e}")
            return OrderResult(success=False, error=f"Invalid amount: {e}")

        # Truncate receipt to Razorpay's 40-char limit
        receipt = receipt[:RAZORPAY_MAX_RECEIPT_LENGTH]

        try:
            order = self._client.order.create({
                "amount": amount_paise,
                "currency": currency,
                "receipt": receipt,
                "notes": notes or {},
            })

            logger.info(f"Razorpay order created: {order.get('id')} for {amount_paise} paise")

            return OrderResult(
                success=True,
                order_id=order.get("id"),
                amount=amount,
                currency=currency,
                status=order.get("status", "created"),
                receipt=receipt,
                notes=notes,
                created_at=order.get("created_at"),
            )

        except Exception as e:
            error_type = self._classify_error(e)
            logger.error(f"Razorpay order creation failed ({error_type.value}): {e}")
            return OrderResult(
                success=False,
                error=f"[{error_type.value}] {e}",
            )

    def search_orders(self, criteria: OrderSearchCriteria, retries: int = 3, delay: float = 5.0) -> SearchResult:
        """Search for Razorpay orders matching criteria.

        Razorpay's fetch_all does NOT support server-side receipt filtering,
        so we fetch all and filter client-side.

        IMPORTANT: Newly created orders may take a few seconds to appear
        in fetch_all. We retry up to `retries` times with `delay` seconds
        between attempts to handle this propagation delay.
        """
        import time as _time

        def _filter_orders(orders_list):
            candidates = []
            for order in orders_list:
                detail = OrderDetail(
                    id=order.get("id"),
                    amount=order.get("amount", 0) / RAZORPAY_PAISE_MULTIPLIER,
                    currency=order.get("currency", "INR"),
                    status=order.get("status", "created"),
                    receipt=order.get("receipt"),
                    notes=order.get("notes"),
                    created_at=order.get("created_at"),
                )
                if criteria.receipt and detail.receipt != criteria.receipt:
                    continue
                if criteria.agent_id:
                    agent = (detail.notes or {}).get("initiated_by_agent", "")
                    if agent != criteria.agent_id:
                        continue
                if criteria.amount is not None and abs(detail.amount - criteria.amount) > 0.01:
                    continue
                if criteria.currency and detail.currency != criteria.currency:
                    continue
                candidates.append(detail)
            return candidates

        for attempt in range(retries):
            try:
                orders_response = self._client.order.fetch_all({"count": 100})
                orders = orders_response.get("items", [])
                candidates = _filter_orders(orders)
                if candidates or attempt == retries - 1:
                    break
                _time.sleep(delay)
            except Exception as e:
                if attempt == retries - 1:
                    error_type = self._classify_error(e)
                    logger.error(f"Razorpay order search failed ({error_type.value}): {e}")
                    return SearchResult(
                        status=OrderSearchStatus.QUERY_FAILED,
                        error=f"[{error_type.value}] {e}",
                    )
                _time.sleep(delay)
                candidates = []

        if len(candidates) == 0:
            return SearchResult(status=OrderSearchStatus.NO_MATCH)
        elif len(candidates) == 1:
            return SearchResult(status=OrderSearchStatus.EXACT_MATCH, orders=candidates)
        else:
            return SearchResult(status=OrderSearchStatus.AMBIGUOUS, orders=candidates)

    def get_order(self, order_id: str) -> Optional[OrderDetail]:
        """Fetch a specific Razorpay order by ID."""
        try:
            order = self._client.order.fetch(order_id)
            return OrderDetail(
                id=order.get("id"),
                amount=order.get("amount", 0) / RAZORPAY_PAISE_MULTIPLIER,
                currency=order.get("currency", "INR"),
                status=order.get("status", "created"),
                receipt=order.get("receipt"),
                notes=order.get("notes"),
                created_at=order.get("created_at"),
            )
        except Exception as e:
            logger.error(f"Razorpay order fetch failed for {order_id}: {e}")
            return None

    def get_order_payments(self, order_id: str) -> List[PaymentDetail]:
        """Fetch payments linked to a Razorpay order.

        Uses the SDK's fetch_all_payments method. Returns empty list
        if the order has no payments yet (normal for newly created orders).
        """
        try:
            payments_response = self._client.order.fetch_all_payments(order_id)
            payments = payments_response.get("items", [])

            return [
                PaymentDetail(
                    id=p.get("id"),
                    order_id=order_id,
                    amount=p.get("amount", 0) / RAZORPAY_PAISE_MULTIPLIER,
                    currency=p.get("currency", "INR"),
                    status=p.get("status", "created"),
                    created_at=p.get("created_at"),
                )
                for p in payments
            ]
        except Exception as e:
            logger.error(f"Razorpay payment fetch failed for order {order_id}: {e}")
            return []


def create_razorpay_provider() -> RazorpayProvider:
    """Factory function to create a RazorpayProvider.

    Raises RuntimeError if credentials are not configured.
    """
    return RazorpayProvider()
