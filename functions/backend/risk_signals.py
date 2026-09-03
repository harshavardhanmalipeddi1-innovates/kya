"""
Multi-Signal Risk Intelligence — Phase 5.

Extends the z-score behavioral drift detector with additional risk signals:
1. Time-of-day anomaly (unusual transaction times)
2. Frequency anomaly (too many transactions in short period)
3. Category diversity (unusual category switches)
4. Amount velocity (sudden spending increases)
5. Agent reputation (historical success rate)

Each signal produces a sub-score in [0, 100]. The composite risk
score is a weighted combination of all signals.

The existing risk_scorer.py remains the default. This module provides
the enhanced multi-signal scorer that can be swapped in via
KYA_RISK_MODEL=multi_signal env var.
"""

import time
import math
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict


class RiskSignal:
    """Base class for risk signals."""

    name: str = "base"
    weight: float = 0.0

    def compute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Compute the signal score.

        Returns:
            {
                "signal": str,
                "score": float,  # 0-100
                "weight": float,
                "detail": str,
            }
        """
        raise NotImplementedError


class TimeOfDaySignal(RiskSignal):
    """Detects transactions at unusual hours.

    Normal business hours (8am-10pm) get low risk.
    Late night (10pm-6am) gets higher risk.
    """

    name = "time_of_day"
    weight = 0.10

    def compute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        now = context.get("now", int(time.time()))
        hour = (now % 86400) // 3600  # Hour in UTC

        if 8 <= hour <= 22:
            score = 0.0
            detail = f"Normal business hours ({hour}:00 UTC)"
        elif 2 <= hour <= 6:
            score = 60.0
            detail = f"Late night transaction ({hour}:00 UTC) — elevated risk"
        else:
            score = 30.0
            detail = f"Unusual hour ({hour}:00 UTC)"

        return {"signal": self.name, "score": score, "weight": self.weight, "detail": detail}


class FrequencySignal(RiskSignal):
    """Detects unusual transaction frequency.

    Tracks transactions per agent per time window.
    High frequency = elevated risk.
    """

    name = "frequency"
    weight = 0.15

    def __init__(self):
        self._recent_txns: Dict[str, List[float]] = defaultdict(list)
        self._window_seconds = 3600  # 1 hour window
        self._threshold = 10  # transactions per window

    def compute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        agent_id = context.get("agent_id", "")
        now = context.get("now", int(time.time()))

        # Prune old entries
        window = self._recent_txns[agent_id]
        self._recent_txns[agent_id] = [
            t for t in window if now - t < self._window_seconds
        ]

        count = len(self._recent_txns[agent_id])

        if count >= self._threshold:
            score = min(100.0, (count / self._threshold) * 80.0)
            detail = f"{count} transactions in {self._window_seconds}s window (threshold: {self._threshold})"
        else:
            score = 0.0
            detail = f"{count} transactions in window (normal)"

        return {"signal": self.name, "score": score, "weight": self.weight, "detail": detail}

    def record_transaction(self, agent_id: str, now: float) -> None:
        """Record a completed transaction for frequency tracking."""
        self._recent_txns[agent_id].append(now)


class CategoryDiversitySignal(RiskSignal):
    """Detects unusual category switches.

    If an agent usually buys groceries and suddenly buys electronics,
    that's a higher-risk signal than continuing to buy groceries.
    """

    name = "category_diversity"
    weight = 0.10

    def __init__(self):
        self._category_history: Dict[str, List[str]] = defaultdict(list)
        self._max_history = 20

    def compute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        agent_id = context.get("agent_id", "")
        cart_categories = context.get("cart_categories", set())

        history = self._category_history[agent_id]
        if not history:
            return {
                "signal": self.name,
                "score": 0.0,
                "weight": self.weight,
                "detail": "No category history — neutral",
            }

        # Calculate how many unique categories this agent has used
        unique_categories = set(history)
        new_categories = cart_categories - unique_categories

        if not new_categories:
            score = 0.0
            detail = f"All cart categories {list(cart_categories)} are in agent history"
        elif len(new_categories) <= 1:
            score = 20.0
            detail = f"1 new category: {list(new_categories)}"
        else:
            score = 50.0
            detail = f"Multiple new categories: {list(new_categories)}"

        return {"signal": self.name, "score": score, "weight": self.weight, "detail": detail}

    def record_categories(self, agent_id: str, categories: List[str]) -> None:
        """Record categories from a completed transaction."""
        history = self._category_history[agent_id]
        history.extend(categories)
        # Keep bounded
        if len(history) > self._max_history:
            self._category_history[agent_id] = history[-self._max_history:]


class AmountVelocitySignal(RiskSignal):
    """Detects sudden spending increases.

    Compares current amount to the agent's recent average.
    A 3x increase is suspicious; 10x is very suspicious.
    """

    name = "amount_velocity"
    weight = 0.25

    def __init__(self):
        self._recent_amounts: Dict[str, List[float]] = defaultdict(list)
        self._max_history = 20

    def compute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        agent_id = context.get("agent_id", "")
        amount = context.get("total_amount", 0)

        history = self._recent_amounts[agent_id]
        if not history:
            return {
                "signal": self.name,
                "score": 0.0,
                "weight": self.weight,
                "detail": "No amount history — neutral",
            }

        avg = sum(history) / len(history)
        if avg <= 0:
            ratio = 0
        else:
            ratio = amount / avg

        if ratio <= 2.0:
            score = max(0.0, (ratio - 1.0) * 20.0)  # 0-20 for 1-2x
            detail = f"Amount {ratio:.1f}x recent average (₹{avg:.0f})"
        elif ratio <= 5.0:
            score = 20.0 + (ratio - 2.0) * 20.0  # 20-80 for 2-5x
            detail = f"Amount {ratio:.1f}x recent average — elevated risk"
        else:
            score = min(100.0, 80.0 + (ratio - 5.0) * 4.0)  # 80-100 for 5x+
            detail = f"Amount {ratio:.1f}x recent average — extreme deviation"

        return {"signal": self.name, "score": score, "weight": self.weight, "detail": detail}

    def record_amount(self, agent_id: str, amount: float) -> None:
        """Record a completed transaction amount."""
        history = self._recent_amounts[agent_id]
        history.append(amount)
        if len(history) > self._max_history:
            self._recent_amounts[agent_id] = history[-self._max_history:]


class AgentReputationSignal(RiskSignal):
    """Tracks agent success/failure history.

    Agents with many successful transactions get lower risk.
    Agents with recent failures get higher risk.
    """

    name = "agent_reputation"
    weight = 0.15

    def __init__(self):
        self._successes: Dict[str, int] = defaultdict(int)
        self._failures: Dict[str, int] = defaultdict(int)

    def compute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        agent_id = context.get("agent_id", "")
        successes = self._successes[agent_id]
        failures = self._failures[agent_id]
        total = successes + failures

        if total == 0:
            score = 50.0  # New agent — neutral
            detail = "New agent — no reputation history"
        else:
            success_rate = successes / total
            score = (1.0 - success_rate) * 100.0
            detail = f"Success rate: {success_rate:.0%} ({successes}/{total})"

        return {"signal": self.name, "score": score, "weight": self.weight, "detail": detail}

    def record_success(self, agent_id: str) -> None:
        self._successes[agent_id] += 1

    def record_failure(self, agent_id: str) -> None:
        self._failures[agent_id] += 1


class MultiSignalRiskScorer:
    """Enhanced risk scorer using multiple signals."""

    def __init__(self):
        self.signals: List[RiskSignal] = [
            TimeOfDaySignal(),
            FrequencySignal(),
            CategoryDiversitySignal(),
            AmountVelocitySignal(),
            AgentReputationSignal(),
        ]

    def compute_risk(
        self,
        amount: float,
        agent: Dict[str, Any],
        identity_ok: bool,
        delegation_ok: bool,
        intent_result: Dict[str, Any],
        baseline_override: Optional[Tuple[float, float, str]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Compute multi-signal risk score."""
        from risk_scorer import amount_drift_score

        if context is None:
            context = {}

        # Base signals from existing scorer
        if baseline_override:
            effective_mean, effective_std, baseline_source = baseline_override
        else:
            effective_mean = agent.get("baseline_mean_amount", 0)
            effective_std = agent.get("baseline_std_amount", 0)
            baseline_source = "static"

        drift = amount_drift_score(amount, effective_mean, effective_std)

        components = {
            "behavioral_drift": drift["sub_score"],
            "identity_penalty": 0 if identity_ok else 60,
            "delegation_penalty": 0 if delegation_ok else 70,
        }

        mismatch_map = {"none": 0, "low": 15, "medium": 35, "high": 65}
        components["intent_mismatch_penalty"] = mismatch_map.get(
            intent_result.get("mismatch_severity", "medium"), 35
        )

        # Add context for signal computation
        signal_context = {
            "agent_id": agent.get("agent_id", ""),
            "total_amount": amount,
            "cart_categories": set(context.get("cart_categories", [])),
            "now": context.get("now", int(time.time())),
        }

        # Compute additional signals
        signal_results = []
        for signal in self.signals:
            result = signal.compute(signal_context)
            signal_results.append(result)
            # Weighted contribution to total score
            components[signal.name] = round(result["score"] * result["weight"], 1)

        total = sum(components.values())
        total = max(0.0, min(100.0, total))

        return {
            "total_score": round(total, 1),
            "components": components,
            "drift_detail": drift,
            "baseline_source": baseline_source,
            "signals": signal_results,
        }


# Module-level instance
_multi_signal_scorer = None


def get_multi_signal_scorer() -> MultiSignalRiskScorer:
    global _multi_signal_scorer
    if _multi_signal_scorer is None:
        _multi_signal_scorer = MultiSignalRiskScorer()
    return _multi_signal_scorer
