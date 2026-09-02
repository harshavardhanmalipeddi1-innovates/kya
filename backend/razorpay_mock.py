"""
Razorpay Test-Mode Mock.

Implements the PaymentProvider interface with deterministic behavior
for testing. Supports configurable scenarios for reconciliation testing.

Swapping for a real Razorpay adapter requires implementing the same
PaymentProvider interface with actual API calls.
"""

import uuid
import time
from typing import Dict, List, Optional

from payment_provider import (
    PaymentProvider,
    OrderResult,
    OrderDetail,
    PaymentDetail,
    OrderSearchCriteria,
    SearchResult,
    OrderSearchStatus,
)


# In-memory store for mock orders (deterministic for testing)
_orders: Dict[str, OrderDetail] = {}
_payments: Dict[str, List[PaymentDetail]] = {}

# Configurable behavior for testing
_search_returns_empty: bool = False
_search_returns_ambiguous: bool = False
_search_query_fails: bool = False
_create_order_fails: bool = False


def reset_mock():
    """Reset all mock state. Called between tests."""
    global _orders, _payments
    global _search_returns_empty, _search_returns_ambiguous
    global _search_query_fails, _create_order_fails
    _orders = {}
    _payments = {}
    _search_returns_empty = False
    _search_returns_ambiguous = False
    _search_query_fails = False
    _create_order_fails = False


def configure_mock(
    search_returns_empty: Optional[bool] = None,
    search_returns_ambiguous: Optional[bool] = None,
    search_query_fails: Optional[bool] = None,
    create_order_fails: Optional[bool] = None,
):
    """Configure mock behavior for specific test scenarios."""
    global _search_returns_empty, _search_returns_ambiguous
    global _search_query_fails, _create_order_fails
    if search_returns_empty is not None:
        _search_returns_empty = search_returns_empty
    if search_returns_ambiguous is not None:
        _search_returns_ambiguous = search_returns_ambiguous
    if search_query_fails is not None:
        _search_query_fails = search_query_fails
    if create_order_fails is not None:
        _create_order_fails = create_order_fails


def seed_order(order_id: str, amount: float, receipt: str,
               status: str = "created", agent_id: str = "test_agent"):
    """Seed a mock order for reconciliation testing."""
    _orders[order_id] = OrderDetail(
        id=order_id,
        amount=amount,
        currency="INR",
        status=status,
        receipt=receipt,
        notes={"initiated_by_agent": agent_id, "mode": "test"},
        created_at=int(time.time()),
    )


def seed_payment(order_id: str, payment_id: str, status: str = "captured"):
    """Seed a mock payment for an order."""
    if order_id not in _payments:
        _payments[order_id] = []
    order = _orders.get(order_id)
    _payments[order_id].append(PaymentDetail(
        id=payment_id,
        order_id=order_id,
        amount=order.amount if order else 0,
        currency="INR",
        status=status,
        created_at=int(time.time()),
    ))


class MockPaymentProvider(PaymentProvider):
    """Deterministic mock payment provider for testing.
    
    Supports configurable scenarios:
    - Normal order creation
    - Order search with exact/no/ambiguous match
    - Payment states (created, authorized, captured, failed)
    - Provider query failures
    """
    
    def create_order(
        self,
        amount: float,
        currency: str,
        receipt: str,
        notes: Optional[Dict[str, str]] = None,
    ) -> OrderResult:
        """Create a mock order. Fails if configure_mock(create_order_fails=True)."""
        if _create_order_fails:
            return OrderResult(
                success=False,
                error="Mock: order creation failed",
            )
        
        order_id = f"order_TEST_{uuid.uuid4().hex[:14]}"
        _orders[order_id] = OrderDetail(
            id=order_id,
            amount=amount,
            currency=currency,
            status="created",
            receipt=receipt,
            notes=notes or {},
            created_at=int(time.time()),
        )
        
        return OrderResult(
            success=True,
            order_id=order_id,
            amount=amount,
            currency=currency,
            status="created",
            receipt=receipt,
            notes=notes,
            created_at=int(time.time()),
        )
    
    def search_orders(self, criteria: OrderSearchCriteria) -> SearchResult:
        """Search mock orders. Behavior depends on configuration."""
        if _search_query_fails:
            return SearchResult(
                status=OrderSearchStatus.QUERY_FAILED,
                error="Mock: provider query failed",
            )
        
        if _search_returns_empty:
            return SearchResult(status=OrderSearchStatus.NO_MATCH)
        
        # Match by receipt if provided
        candidates = []
        for order in _orders.values():
            if criteria.receipt and order.receipt != criteria.receipt:
                continue
            if criteria.agent_id:
                agent = (order.notes or {}).get("initiated_by_agent", "")
                if agent != criteria.agent_id:
                    continue
            if criteria.amount is not None and order.amount != criteria.amount:
                continue
            if criteria.currency and order.currency != criteria.currency:
                continue
            if criteria.created_at_from and order.created_at and order.created_at < criteria.created_at_from:
                continue
            if criteria.created_at_to and order.created_at and order.created_at > criteria.created_at_to:
                continue
            candidates.append(order)
        
        if _search_returns_ambiguous and len(candidates) >= 1:
            # Return extra candidates for ambiguity testing
            extra = OrderDetail(
                id=f"order_EXTRA_{uuid.uuid4().hex[:8]}",
                amount=candidates[0].amount,
                currency=candidates[0].currency,
                status="created",
                receipt=candidates[0].receipt,
                notes=candidates[0].notes,
                created_at=candidates[0].created_at,
            )
            candidates.append(extra)
        
        if len(candidates) == 0:
            return SearchResult(status=OrderSearchStatus.NO_MATCH)
        elif len(candidates) == 1:
            return SearchResult(status=OrderSearchStatus.EXACT_MATCH, orders=candidates)
        else:
            return SearchResult(status=OrderSearchStatus.AMBIGUOUS, orders=candidates)
    
    def get_order(self, order_id: str) -> Optional[OrderDetail]:
        """Fetch a mock order by ID."""
        return _orders.get(order_id)
    
    def get_order_payments(self, order_id: str) -> List[PaymentDetail]:
        """Fetch mock payments for an order."""
        return _payments.get(order_id, [])


# Module-level instance for use throughout the app
mock_provider = MockPaymentProvider()


def create_test_order(amount: float, agent_id: str) -> dict:
    """Legacy interface: create order via mock provider.
    
    Maintains backward compatibility with existing main.py code.
    """
    execution_id = f"exec_{uuid.uuid4().hex[:12]}"
    result = mock_provider.create_order(
        amount=amount,
        currency="INR",
        receipt=execution_id,
        notes={"initiated_by_agent": agent_id, "mode": "test"},
    )
    if not result.success:
        raise Exception(result.error or "Order creation failed")
    return {
        "razorpay_order_id": result.order_id,
        "amount": result.amount,
        "currency": result.currency,
        "status": result.status,
        "notes": result.notes,
        "created_at": result.created_at,
        "execution_id": execution_id,
    }
