"""
Risk Scorer.

Combines behavioral drift (is this transaction size normal for this
agent?) with identity/delegation/intent signals into one composite
score in [0, 100]. Deterministic and explainable by design -- every
component of the score is named, because a merchant or panel will
ask "why did you block this."

Rolling baselines: when enough transaction history exists for an
agent (>= MIN_SAMPLES in baseline.py), the risk scorer uses adaptive
rolling statistics instead of the static baselines from agents.json.
This makes the system learn from actual transaction patterns over
time while falling back to static defaults during cold-start.
"""

from typing import Dict, Any, Optional, Tuple


def amount_drift_score(amount: float, baseline_mean: float, baseline_std: float) -> Dict[str, Any]:
    if baseline_std <= 0:
        baseline_std = max(baseline_mean * 0.25, 1.0)
    z = (amount - baseline_mean) / baseline_std
    # map z-score to a 0-100 sub-score, clipped
    sub_score = max(0.0, min(100.0, z * 12.5))  # z=8 -> 100
    return {
        "z_score": round(z, 2),
        "sub_score": round(sub_score, 1),
        "explanation": f"Amount is {round(amount / baseline_mean, 1)}x this agent's historical average (z={round(z,2)})"
        if baseline_mean > 0
        else "No reliable baseline for this agent yet",
    }


def compute_risk(
    amount: float,
    agent: Dict[str, Any],
    identity_ok: bool,
    delegation_ok: bool,
    intent_result: Dict[str, Any],
    baseline_override: Optional[Tuple[float, float, str]] = None,
) -> Dict[str, Any]:
    """Compute composite risk score.

    baseline_override: optional (mean, std, source) tuple from
    baseline.py's get_effective_baseline(). When provided, these
    values replace the static baseline for drift calculation. The
    source string ("rolling" or "static") is included in the output
    for audit trail visibility.
    """
    components = {}

    # Determine which baseline to use for drift scoring
    if baseline_override:
        effective_mean, effective_std, baseline_source = baseline_override
    else:
        effective_mean = agent["baseline_mean_amount"]
        effective_std = agent["baseline_std_amount"]
        baseline_source = "static"

    drift = amount_drift_score(amount, effective_mean, effective_std)
    components["behavioral_drift"] = drift["sub_score"]

    components["identity_penalty"] = 0 if identity_ok else 60
    components["delegation_penalty"] = 0 if delegation_ok else 70

    mismatch_map = {"none": 0, "low": 15, "medium": 35, "high": 65}
    components["intent_mismatch_penalty"] = mismatch_map.get(intent_result["mismatch_severity"], 35)

    total = sum(components.values())
    total = max(0.0, min(100.0, total))

    return {
        "total_score": round(total, 1),
        "components": components,
        "drift_detail": drift,
        "baseline_source": baseline_source,
    }
