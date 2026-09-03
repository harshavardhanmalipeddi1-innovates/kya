"""
Governance & Policy Engine — Phase 10.

Separates authorization policy from application code. Defines explicit
policy rules that can be configured per-agent, per-category, per-amount,
and per-time without changing code.

Architecture:
  Transaction → Policy Engine → Decision
                 ↑
           Policy Rules (JSON/config)

Example policy:
{
  "agent_id": "agent_procure_bot_042",
  "rules": [
    {
      "category": "groceries",
      "max_amount": 5000,
      "max_daily_transactions": 10,
      "require_step_up_above": 2500,
      "allowed_hours": [6, 23]
    },
    {
      "category": "electronics",
      "max_amount": 50000,
      "max_daily_transactions": 2,
      "require_step_up_above": 10000,
      "allowed_hours": [8, 22]
    }
  ],
  "global": {
    "max_daily_total": 100000,
    "max_monthly_total": 500000,
    "require_human_above": 25000
  }
}
"""

import json
import os
import time
from typing import Dict, Any, List, Optional
from pathlib import Path

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
POLICIES_PATH = os.path.join(DATA_DIR, "policies.json")


class PolicyViolation:
    """Represents a policy rule violation."""

    def __init__(self, rule: str, message: str, severity: str = "block"):
        self.rule = rule
        self.message = message
        self.severity = severity  # "block", "step_up", "warn"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "message": self.message,
            "severity": self.severity,
        }


class PolicyEngine:
    """Evaluates transactions against configured policy rules."""

    def __init__(self):
        self._policies: Dict[str, Dict[str, Any]] = {}
        self._load_policies()

    def _load_policies(self) -> None:
        """Load policies from file if it exists."""
        if os.path.exists(POLICIES_PATH):
            try:
                with open(POLICIES_PATH) as f:
                    self._policies = json.load(f)
            except Exception:
                self._policies = {}

    def save_policies(self) -> None:
        """Save current policies to file."""
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(POLICIES_PATH, "w") as f:
            json.dump(self._policies, f, indent=2)

    def set_agent_policy(self, agent_id: str, policy: Dict[str, Any]) -> None:
        """Set or update policy for an agent."""
        self._policies[agent_id] = policy
        self.save_policies()

    def get_agent_policy(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get policy for an agent."""
        return self._policies.get(agent_id)

    def evaluate(
        self,
        agent_id: str,
        category: str,
        amount: float,
        now: Optional[int] = None,
        daily_transactions: int = 0,
        daily_total: float = 0.0,
    ) -> Dict[str, Any]:
        """Evaluate a transaction against policy rules.

        Returns:
            {
                "allowed": bool,
                "decision": str,  # "APPROVE", "STEP_UP", "BLOCK"
                "violations": list,
                "policy_applied": str,
            }
        """
        if now is None:
            now = int(time.time())

        policy = self.get_agent_policy(agent_id)
        violations = []

        if policy is None:
            # No policy defined — use defaults
            return {
                "allowed": True,
                "decision": "APPROVE",
                "violations": [],
                "policy_applied": "default",
            }

        # Check category-specific rules
        category_rules = None
        for rule in policy.get("rules", []):
            if rule.get("category") == category:
                category_rules = rule
                break

        if category_rules:
            # Amount limit
            max_amount = category_rules.get("max_amount")
            if max_amount and amount > max_amount:
                violations.append(PolicyViolation(
                    "category_max_amount",
                    f"Amount ₹{amount} exceeds category limit ₹{max_amount}",
                    "block",
                ))

            # Step-up threshold
            step_up_above = category_rules.get("require_step_up_above")
            if step_up_above and amount > step_up_above:
                violations.append(PolicyViolation(
                    "category_step_up",
                    f"Amount ₹{amount} exceeds step-up threshold ₹{step_up_above}",
                    "step_up",
                ))

            # Daily transaction count
            max_daily = category_rules.get("max_daily_transactions")
            if max_daily and daily_transactions >= max_daily:
                violations.append(PolicyViolation(
                    "category_daily_count",
                    f"Daily transaction count ({daily_transactions}) exceeds limit ({max_daily})",
                    "block",
                ))

            # Allowed hours
            allowed_hours = category_rules.get("allowed_hours")
            if allowed_hours:
                hour = (now % 86400) // 3600
                if len(allowed_hours) == 2:
                    start, end = allowed_hours
                    if not (start <= hour <= end):
                        violations.append(PolicyViolation(
                            "category_allowed_hours",
                            f"Transaction at hour {hour} outside allowed hours ({start}-{end})",
                            "block",
                        ))

        # Check global rules
        global_rules = policy.get("global", {})

        # Daily total limit
        max_daily_total = global_rules.get("max_daily_total")
        if max_daily_total and daily_total + amount > max_daily_total:
            violations.append(PolicyViolation(
                "global_daily_total",
                f"Daily total (₹{daily_total} + ₹{amount}) would exceed limit ₹{max_daily_total}",
                "block",
            ))

        # Human confirmation threshold
        require_human_above = global_rules.get("require_human_above")
        if require_human_above and amount > require_human_above:
            violations.append(PolicyViolation(
                "global_human_confirmation",
                f"Amount ₹{amount} exceeds human confirmation threshold ₹{require_human_above}",
                "step_up",
            ))

        # Determine decision from violations
        has_block = any(v.severity == "block" for v in violations)
        has_step_up = any(v.severity == "step_up" for v in violations)

        if has_block:
            decision = "BLOCK"
        elif has_step_up:
            decision = "STEP_UP"
        else:
            decision = "APPROVE"

        return {
            "allowed": not has_block,
            "decision": decision,
            "violations": [v.to_dict() for v in violations],
            "policy_applied": f"agent:{agent_id}" if policy else "default",
        }


# Module-level instance
_policy_engine = None


def get_policy_engine() -> PolicyEngine:
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = PolicyEngine()
    return _policy_engine
