"""
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
        # No classifiable category is an absence of evidence, not evidence
        # of a mismatch. Vague-but-legitimate phrasing ("pick up some
        # essentials for home", "handle the usual weekly errand") should
        # not carry the same penalty as a *confident* mismatch (e.g.
        # "buy electronics" against a grocery cart) -- conflating the two
        # is exactly what caused every ambiguous-phrasing false positive
        # in eval/eval_report.md. We still surface this in the audit trail
        # for visibility, we just don't let it alone force a step-up.
        return {
            "match": True,
            "inferred_category": inferred_category,
            "cart_categories": list(cart_categories),
            "reason": "Stated intent phrasing was not confidently classifiable into a known category -- not treated as evidence of mismatch, but flagged for audit visibility",
            "mismatch_severity": "low",
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
