"""
Payment Provider Adapter Interface.

All provider-specific payment behavior (Razorpay, Stripe, etc.) is
behind this interface. The reconciliation logic in registry.py and
main.py never calls provider APIs directly — it goes through this
adapter.

This enables:
  - Deterministic mock for testing without credentials
  - Real Razorpay adapter for production
  - Provider-neutral reconciliation logic

State model:

  KYA execution_state:
    EXECUTION_PENDING    — calling provider
    PAYMENT_UNKNOWN      — provider status unknown
    RECONCILIATION_REQUIRED — awaiting reconciliation
    FINALIZATION_PENDING — outbox written, awaiting finalize
    EXECUTED             — token finalized
    PAYMENT_FAILED       — explicit provider failure
    MANUAL_REQUIRED      — needs admin intervention

  Provider order_state:
    UNKNOWN   — not yet queried
    NOT_FOUND — search completed, no orders match
    CREATED   — order exists, not yet attempted payment
    ATTEMPTED — payment attempted, not yet captured
    PAID      — payment captured
    AMBIGUOUS — multiple orders match

  Provider payment_state:
    UNKNOWN   — not yet queried
    NONE      — no payments on order
    CREATED   — payment created
    AUTHORIZED — payment authorized, not captured
    CAPTURED  — payment captured (final success)
    FAILED    — payment failed
    REFUNDED  — payment refunded
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any


class OrderSearchStatus(Enum):
    EXACT_MATCH = "exact_match"
    NO_MATCH = "no_match"
    AMBIGUOUS = "ambiguous"
    QUERY_FAILED = "query_failed"


class OrderState(Enum):
    UNKNOWN = "UNKNOWN"
    NOT_FOUND = "NOT_FOUND"
    CREATED = "CREATED"
    ATTEMPTED = "ATTEMPTED"
    PAID = "PAID"
    AMBIGUOUS = "AMBIGUOUS"


class PaymentState(Enum):
    UNKNOWN = "UNKNOWN"
    NONE = "NONE"
    CREATED = "CREATED"
    AUTHORIZED = "AUTHORIZED"
    CAPTURED = "CAPTURED"
    FAILED = "FAILED"
    REFUNDED = "REFUNDED"


@dataclass
class OrderResult:
    """Result of creating an order."""
    success: bool
    order_id: Optional[str] = None
    amount: Optional[float] = None
    currency: Optional[str] = None
    status: Optional[str] = None
    receipt: Optional[str] = None
    notes: Optional[Dict[str, str]] = None
    created_at: Optional[int] = None
    error: Optional[str] = None


@dataclass
class OrderDetail:
    """Detailed order information from provider."""
    id: str
    amount: float
    currency: str
    status: str  # created, attempted, paid
    receipt: Optional[str] = None
    notes: Optional[Dict[str, str]] = None
    created_at: Optional[int] = None


@dataclass
class PaymentDetail:
    """Detailed payment information from provider."""
    id: str
    order_id: str
    amount: float
    currency: str
    status: str  # created, authorized, captured, failed, refunded
    created_at: Optional[int] = None


@dataclass
class OrderSearchCriteria:
    """Search criteria for finding orders."""
    receipt: Optional[str] = None
    agent_id: Optional[str] = None
    amount: Optional[float] = None
    currency: Optional[str] = None
    created_at_from: Optional[int] = None
    created_at_to: Optional[int] = None


@dataclass
class SearchResult:
    """Result of searching for orders."""
    status: OrderSearchStatus
    orders: List[OrderDetail] = field(default_factory=list)
    error: Optional[str] = None


class PaymentProvider:
    """Interface for payment provider operations.
    
    All provider-specific behavior is behind this interface.
    The mock implements deterministic responses for testing.
    The real Razorpay adapter implements actual API calls.
    """
    
    def create_order(
        self,
        amount: float,
        currency: str,
        receipt: str,
        notes: Optional[Dict[str, str]] = None,
    ) -> OrderResult:
        """Create a payment order.
        
        Args:
            amount: Amount in smallest currency unit (paise for INR)
            currency: Currency code (e.g., "INR")
            receipt: KYA execution_id used as correlation key
            notes: Additional metadata
        
        Returns:
            OrderResult with success status and order details
        """
        raise NotImplementedError
    
    def search_orders(self, criteria: OrderSearchCriteria) -> SearchResult:
        """Search for orders matching criteria.
        
        The provider determines which criteria are supported.
        KYA passes all known fields; the adapter uses what it can.
        
        Returns:
            SearchResult with status and matching orders
        """
        raise NotImplementedError
    
    def get_order(self, order_id: str) -> Optional[OrderDetail]:
        """Fetch a specific order by ID.
        
        Returns:
            OrderDetail if found, None if not found
        """
        raise NotImplementedError
    
    def get_order_payments(self, order_id: str) -> List[PaymentDetail]:
        """Fetch payments linked to an order.
        
        Returns:
            List of PaymentDetail objects
        """
        raise NotImplementedError
