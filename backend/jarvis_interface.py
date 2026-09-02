"""
JARVIS Integration Interface — Phase 12.

Defines the integration boundary between KYA and a broader
AI agent ecosystem (JARVIS). Provides:

1. Agent Router interface (for routing requests to KYA)
2. Memory interface (for agent context/history)
3. Security gateway (KYA as the sensitive-operation boundary)

Architecture:
                    JARVIS
                       │
              ┌────────┼────────┐
              │        │        │
           Planner   Memory   Security
              │                 │
              ▼                 ▼
        Agent Router           KYA
              │
      ┌───────┼────────┐
      │       │        │
    Coding  Browser   System
      │       │        │
      ▼       ▼        ▼
  Freebuff  Web      Windows

KYA becomes the boundary for sensitive operations:
  AI → "buy / pay / transfer" → KYA → identity → delegation
       → scope → intent → risk → policy → payment

This module defines the interfaces — the actual JARVIS integration
is a separate project that imports these interfaces.
"""

import json
import os
import time
from typing import Dict, Any, List, Optional, Callable
from pathlib import Path

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


class AgentRequest:
    """Standardized request format for JARVIS → KYA integration."""

    def __init__(
        self,
        agent_id: str,
        delegation_token: str,
        stated_intent: str,
        cart: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.agent_id = agent_id
        self.delegation_token = delegation_token
        self.stated_intent = stated_intent
        self.cart = cart
        self.metadata = metadata or {}
        self.timestamp = int(time.time())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "delegation_token": self.delegation_token,
            "stated_intent": self.stated_intent,
            "cart": self.cart,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }


class AgentResponse:
    """Standardized response format for KYA → JARVIS."""

    def __init__(
        self,
        decision: str,
        reasons: List[str],
        audit_id: Optional[str] = None,
        risk_score: Optional[float] = None,
        payment: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.decision = decision
        self.reasons = reasons
        self.audit_id = audit_id
        self.risk_score = risk_score
        self.payment = payment
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "reasons": self.reasons,
            "audit_id": self.audit_id,
            "risk_score": self.risk_score,
            "payment": self.payment,
            "metadata": self.metadata,
        }


class AgentRouter:
    """Routes agent requests through the KYA pipeline.

    This is the primary integration point between JARVIS and KYA.
    It accepts standardized requests and returns standardized responses.
    """

    def __init__(self, kya_base_url: str = "http://localhost:8000"):
        self.base_url = kya_base_url
        self._pipeline_fn: Optional[Callable] = None

    def set_pipeline(self, pipeline_fn: Callable) -> None:
        """Set a custom pipeline function (for offline/testing use)."""
        self._pipeline_fn = pipeline_fn

    def route_request(self, request: AgentRequest) -> AgentResponse:
        """Route a request through KYA.

        In production, this makes an HTTP call to the KYA API.
        In testing, it calls the pipeline directly.
        """
        if self._pipeline_fn:
            return self._route_through_pipeline(request)
        else:
            return self._route_through_http(request)

    def _route_through_pipeline(self, request: AgentRequest) -> AgentResponse:
        """Route through the pipeline directly (for testing)."""
        result = self._pipeline_fn(
            agent_id=request.agent_id,
            delegation_token=request.delegation_token,
            stated_intent=request.stated_intent,
            cart=request.cart,
        )
        return AgentResponse(
            decision=result["decision"],
            reasons=result["reasons"],
            audit_id=result.get("audit_id"),
            risk_score=result.get("risk", {}).get("total_score"),
            payment=result.get("payment"),
        )

    def _route_through_http(self, request: AgentRequest) -> AgentResponse:
        """Route through HTTP (for production use)."""
        import requests

        resp = requests.post(
            f"{self.base_url}/verify",
            json={
                "agent_id": request.agent_id,
                "delegation_token": request.delegation_token,
                "stated_intent": request.stated_intent,
                "cart": request.cart,
            },
            headers={"Content-Type": "application/json"},
        )
        data = resp.json()
        return AgentResponse(
            decision=data["decision"],
            reasons=data["reasons"],
            audit_id=data.get("audit_id"),
            risk_score=data.get("risk", {}).get("total_score"),
            payment=data.get("payment"),
        )


class MemoryInterface:
    """Interface for agent context/history storage.

    In JARVIS, this would connect to the agent's memory system.
    For KYA integration, it provides:
    - Transaction history for risk scoring
    - Agent context for intent verification
    - Audit trail for compliance
    """

    def __init__(self, kya_base_url: str = "http://localhost:8000"):
        self.base_url = kya_base_url

    def get_agent_history(self, agent_id: str) -> List[Dict[str, Any]]:
        """Get transaction history for an agent."""
        import requests

        resp = requests.get(
            f"{self.base_url}/audit",
            headers={"Content-Type": "application/json"},
        )
        entries = resp.json()
        return [e for e in entries if e.get("agent_id") == agent_id]

    def get_agent_context(self, agent_id: str) -> Dict[str, Any]:
        """Get current context for an agent."""
        import requests

        resp = requests.get(
            f"{self.base_url}/agents",
            headers={"Content-Type": "application/json"},
        )
        agents = resp.json()
        return agents.get(agent_id, {})


class SecurityGateway:
    """KYA as the security gateway for AI agent operations.

    Provides a high-level interface for AI systems to:
    1. Check if an operation is authorized
    2. Get risk assessment
    3. Execute authorized operations
    """

    def __init__(self, router: AgentRouter):
        self.router = router

    def check_operation(
        self,
        agent_id: str,
        delegation_token: str,
        operation: str,
        amount: float,
        category: str,
    ) -> AgentResponse:
        """Check if an operation is authorized.

        Args:
            agent_id: The agent requesting the operation
            delegation_token: The agent's delegation credential
            operation: Description of the operation
            amount: Transaction amount
            category: Transaction category

        Returns:
            AgentResponse with decision and reasoning
        """
        request = AgentRequest(
            agent_id=agent_id,
            delegation_token=delegation_token,
            stated_intent=operation,
            cart=[{
                "item": operation,
                "category": category,
                "amount": amount,
            }],
        )
        return self.router.route_request(request)

    def execute_operation(
        self,
        agent_id: str,
        delegation_token: str,
        operation: str,
        amount: float,
        category: str,
    ) -> Dict[str, Any]:
        """Execute an authorized operation.

        First checks authorization, then executes if approved.
        """
        response = self.check_operation(
            agent_id, delegation_token, operation, amount, category
        )

        return {
            "authorized": response.decision == "APPROVE",
            "decision": response.decision,
            "reasons": response.reasons,
            "payment": response.payment,
            "audit_id": response.audit_id,
        }
