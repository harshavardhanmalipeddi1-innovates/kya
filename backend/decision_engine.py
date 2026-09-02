"""
Decision Engine.

Deterministic, rule-based gate on top of the risk score and hard
checks. This is intentional: the LLM/heuristics do interpretation
(intent matching, drift explanation) but the actual money-gating
decision is rule-based and auditable, not "trust the model."
"""

from typing import Dict, Any

BLOCK_THRESHOLD = 55
STEP_UP_THRESHOLD = 25


def decide(
    identity_ok: bool,
    delegation_ok: bool,
    delegation_reason: str,
    scope_ok: bool,
    within_delegated_limit: bool,
    intent_result: Dict[str, Any],
    risk: Dict[str, Any],
) -> Dict[str, Any]:
    reasons = []

    # Hard gates -- these block regardless of risk score
    if not identity_ok:
        return _result("BLOCK", ["Agent identity is not registered/verified -- cannot confirm this agent is who it claims to be."], risk)

    if not delegation_ok:
        return _result("BLOCK", [f"Delegation token invalid: {delegation_reason}"], risk)

    if not scope_ok:
        return _result("BLOCK", ["Purchase category is outside the human-authorized scope for this agent."], risk)

    if not within_delegated_limit:
        return _result("BLOCK", ["Requested amount exceeds the human-authorized delegation limit for this agent."], risk)

    # Soft gates -- based on composite risk score
    score = risk["total_score"]

    if intent_result["mismatch_severity"] == "high":
        reasons.append(intent_result["reason"])

    if score >= BLOCK_THRESHOLD:
        reasons.append(f"Composite risk score {score}/100 exceeds block threshold ({BLOCK_THRESHOLD}).")
        return _result("BLOCK", reasons, risk)

    if score >= STEP_UP_THRESHOLD:
        reasons.append(f"Composite risk score {score}/100 exceeds step-up threshold ({STEP_UP_THRESHOLD}) -- human confirmation required.")
        return _result("STEP_UP", reasons, risk)

    reasons.append(f"All checks passed. Composite risk score {score}/100 is within normal range.")
    return _result("APPROVE", reasons, risk)


def _result(decision: str, reasons, risk: Dict[str, Any]) -> Dict[str, Any]:
    return {"decision": decision, "reasons": reasons, "risk": risk}
