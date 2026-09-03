"""
Platformization — Phase 13.

Defines KYA as a standalone platform with:
1. KYA Gateway (API gateway pattern)
2. KYA Identity (delegation/credential management)
3. KYA Intent (intent verification service)
4. KYA Risk (risk scoring service)
5. KYA Policy (policy engine service)
6. KYA Audit (audit trail service)
7. KYA Reconciliation (payment reconciliation service)
8. KYA Payment (payment execution service)

Each service has a well-defined interface that can be:
- Used in-process (current architecture)
- Exposed as a separate microservice (future)
- Replaced with a different implementation

This module provides the service registry and inter-service communication.
"""

import json
import os
import time
from typing import Dict, Any, List, Optional, Callable
from pathlib import Path

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


class ServiceInterface:
    """Base class for all KYA services."""

    name: str = "base"

    def health(self) -> Dict[str, Any]:
        """Return service health status."""
        return {"status": "healthy", "service": self.name}


class IdentityService(ServiceInterface):
    """KYA Identity — delegation/credential management."""

    name = "identity"

    def __init__(self):
        from identity import get_identity_provider
        self._provider = get_identity_provider()

    def issue_token(
        self,
        agent_id: str,
        human_id: str,
        max_amount: float,
        categories: List[str],
        ttl_seconds: int = 3600,
    ) -> str:
        """Issue a delegation token."""
        import registry
        return registry.issue_delegation_token(
            agent_id, human_id, max_amount, categories, ttl_seconds
        )

    def verify_token(self, token: str, now: Optional[int] = None) -> Dict[str, Any]:
        """Verify a delegation token."""
        import registry
        return registry.verify_delegation_token(token, now=now)

    def health(self) -> Dict[str, Any]:
        return {
            "status": "healthy",
            "service": self.name,
            "mode": self._provider.mode,
        }


class IntentService(ServiceInterface):
    """KYA Intent — intent verification service."""

    name = "intent"

    def __init__(self):
        from intent_match import check_intent_match as _default
        self._checker = _default

    def check_intent(self, stated_intent: str, cart: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check if stated intent matches the cart."""
        return self._checker(stated_intent, cart)


class RiskService(ServiceInterface):
    """KYA Risk — risk scoring service."""

    name = "risk"

    def compute_risk(
        self,
        amount: float,
        agent: Dict[str, Any],
        identity_ok: bool,
        delegation_ok: bool,
        intent_result: Dict[str, Any],
        baseline_override: Optional[tuple] = None,
    ) -> Dict[str, Any]:
        """Compute risk score."""
        from risk_scorer import compute_risk
        return compute_risk(
            amount, agent, identity_ok, delegation_ok, intent_result, baseline_override
        )


class PolicyService(ServiceInterface):
    """KYA Policy — policy engine service."""

    name = "policy"

    def evaluate(
        self,
        agent_id: str,
        category: str,
        amount: float,
        now: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Evaluate a transaction against policy rules."""
        from policy_engine import get_policy_engine
        return get_policy_engine().evaluate(agent_id, category, amount, now)


class AuditService(ServiceInterface):
    """KYA Audit — audit trail service."""

    name = "audit"

    def record(self, entry: Dict[str, Any]) -> str:
        """Record an audit entry."""
        import audit
        return audit.record(entry)

    def get_all(self) -> List[Dict[str, Any]]:
        """Get all audit entries."""
        import audit
        return audit.get_all()

    def get_one(self, audit_id: str) -> Optional[Dict[str, Any]]:
        """Get one audit entry."""
        import audit
        return audit.get_one(audit_id)


class ReconciliationService(ServiceInterface):
    """KYA Reconciliation — payment reconciliation service."""

    name = "reconciliation"

    def record_attempt(
        self,
        audit_id: str,
        execution_id: str,
        attempt_number: int,
        search_criteria: dict,
        query_result: dict,
        confidence_level: int,
        action_taken: str,
    ) -> None:
        """Record a reconciliation attempt."""
        from registry import record_reconciliation_attempt
        record_reconciliation_attempt(
            audit_id, execution_id, attempt_number,
            search_criteria, query_result, confidence_level, action_taken,
        )


class PaymentService(ServiceInterface):
    """KYA Payment — payment execution service."""

    name = "payment"

    def __init__(self):
        from razorpay_mock import create_test_order
        self._create_order = create_test_order

    def create_order(self, amount: float, agent_id: str) -> Dict[str, Any]:
        """Create a payment order."""
        return self._create_order(amount, agent_id)


class KYAPlatform:
    """KYA Platform — the unified service registry.

    Provides access to all KYA services through a single interface.
    """

    def __init__(self):
        self.identity = IdentityService()
        self.intent = IntentService()
        self.risk = RiskService()
        self.policy = PolicyService()
        self.audit = AuditService()
        self.reconciliation = ReconciliationService()
        self.payment = PaymentService()

    def health(self) -> Dict[str, Any]:
        """Get health status of all services."""
        services = {
            "identity": self.identity.health(),
            "intent": self.intent.health(),
            "risk": self.risk.health(),
            "policy": self.policy.health(),
            "audit": self.audit.health(),
            "reconciliation": self.reconciliation.health(),
            "payment": self.payment.health(),
        }

        all_healthy = all(s["status"] == "healthy" for s in services.values())

        return {
            "status": "healthy" if all_healthy else "degraded",
            "services": services,
            "version": "0.2.0",
        }


# Module-level singleton
_platform = None


def get_platform() -> KYAPlatform:
    global _platform
    if _platform is None:
        _platform = KYAPlatform()
    return _platform
