"""
REFERENCE ONLY -- reconstructed pre-fix version of backend/intent_match.py,
kept so the before/after numbers in eval_report.md are independently
reproducible (run `python harness.py intent_match_pre_fix_reference` from
eval/ vs `python harness.py intent_match`). Not imported by the app.

Intent-Match Checker.

An AI shopping agent is given a natural-language intent by its human
("buy groceries for the week", "reorder office printer paper"). At
checkout, KYA checks whether the actual cart matches that stated
intent -- catching cases where prompt injection, a compromised
storefront, or an agent bug has caused the agent to buy something
the human never asked for.

This is a lightweight category + amount-plausibility check for the
MVP. In production this would use an embedding-similarity model
between stated intent and cart contents, plus category taxonomies.
"""

from typing import List, Dict, Any

# naive keyword -> category map, standing in for a real intent classifier
INTENT_KEYWORDS = {
    "groceries": ["grocery", "groceries", "food", "vegetables", "milk", "snacks"],
    "electronics": ["electronics", "laptop", "phone", "headphones", "gadget", "tv", "camera"],
    "office_supplies": ["office", "stationery", "paper", "printer", "pens"],
}


def infer_intent_category(stated_intent: str) -> str:
    text = stated_intent.lower()
    for category, keywords in INTENT_KEYWORDS.items():
        if any(k in text for k in keywords):
            return category
    return "unknown"


def check_intent_match(stated_intent: str, cart: List[Dict[str, Any]]) -> Dict[str, Any]:
    inferred_category = infer_intent_category(stated_intent)
    cart_categories = {item["category"] for item in cart}

    if inferred_category == "unknown":
        return {
            "match": False,
            "inferred_category": inferred_category,
            "cart_categories": list(cart_categories),
            "reason": "Could not classify stated intent -- treat as unverified",
            "mismatch_severity": "medium",
        }

    if inferred_category in cart_categories and len(cart_categories) == 1:
        return {
            "match": True,
            "inferred_category": inferred_category,
            "cart_categories": list(cart_categories),
            "reason": "Cart contents match the stated intent category",
            "mismatch_severity": "none",
        }

    if inferred_category in cart_categories:
        return {
            "match": True,
            "inferred_category": inferred_category,
            "cart_categories": list(cart_categories),
            "reason": "Cart partially matches stated intent (mixed categories)",
            "mismatch_severity": "low",
        }

    return {
        "match": False,
        "inferred_category": inferred_category,
        "cart_categories": list(cart_categories),
        "reason": f"Stated intent implies '{inferred_category}' but cart contains {list(cart_categories)} -- possible hijack/injection",
        "mismatch_severity": "high",
    }
