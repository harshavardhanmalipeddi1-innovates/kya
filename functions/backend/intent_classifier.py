"""
Advanced Intent Verification — Phase 4.

Enhances the keyword-based intent matcher with:
1. Structured intent extraction (amount, category, action keywords)
2. Multi-signal scoring (keyword match + amount plausibility + category coherence)
3. Pluggable classifier interface for future embedding models

The existing intent_match.py remains the default classifier.
This module provides an enhanced classifier that can be swapped in
via KYA_INTENT_CLASSIFIER=advanced env var.

Architecture:
  intent_match.py (keyword)  ←→  intent_classifier.py (structured)
                    ↕
            pipeline.py selects based on env config
"""

import re
from typing import List, Dict, Any, Optional, Tuple

# ── Structured Intent Extraction ──────────────────────────────────

CATEGORY_SYNONYMS = {
    "groceries": [
        "grocery", "groceries", "food", "vegetables", "milk", "snacks",
        "fruit", "rice", "bread", "eggs", "meat", "fish", "produce",
        "supermarket", "market", "essentials", "pantry",
    ],
    "electronics": [
        "electronics", "laptop", "phone", "headphones", "gadget", "tv",
        "camera", "monitor", "speaker", "tablet", "earbuds", "charger",
        "computer", "keyboard", "mouse", "printer", "tech", "device",
    ],
    "office_supplies": [
        "office", "stationery", "paper", "printer", "pens", "toner",
        "notebook", "folder", "stapler", "tape", "supplies", "desk",
        "furniture", "chair", "whiteboard", "marker",
    ],
}

ACTION_KEYWORDS = {
    "buy": ["buy", "purchase", "order", "get", "acquire", "shop"],
    "reorder": ["reorder", "restock", "refill", "replenish", "resupply"],
    "return": ["return", "refund", "exchange"],
    "cancel": ["cancel", "stop", "abort"],
}

AMOUNT_PATTERNS = [
    (r"(\d+(?:\.\d+)?)\s*(?:k|thousand)", lambda m: float(m.group(1)) * 1000),
    (r"(\d+(?:\.\d+)?)\s*(?:lakh|lac)", lambda m: float(m.group(1)) * 100000),
    (r"(\d+(?:\.\d+)?)\s*(?:crore|cr)", lambda m: float(m.group(1)) * 10000000),
    (r"rs\.?\s*(\d+(?:,\d+)*(?:\.\d+)?)", lambda m: float(m.group(1).replace(",", ""))),
    (r"₹\s*(\d+(?:,\d+)*(?:\.\d+)?)", lambda m: float(m.group(1).replace(",", ""))),
    (r"(\d+(?:,\d+)*(?:\.\d+)?)\s*(?:rs|inr)", lambda m: float(m.group(1).replace(",", ""))),
]


class StructuredIntent:
    """Parsed representation of a stated intent."""

    def __init__(self, text: str):
        self.text = text
        self.lower_text = text.lower()
        self.action = self._extract_action()
        self.categories = self._extract_categories()
        self.mentioned_amount = self._extract_amount()
        self.action_score = self._score_action()
        self.category_score = self._score_categories()

    def _extract_action(self) -> str:
        for action, keywords in ACTION_KEYWORDS.items():
            if any(kw in self.lower_text for kw in keywords):
                return action
        return "unknown"

    def _extract_categories(self) -> List[str]:
        found = []
        for category, synonyms in CATEGORY_SYNONYMS.items():
            if any(syn in self.lower_text for syn in synonyms):
                found.append(category)
        return found

    def _extract_amount(self) -> Optional[float]:
        for pattern, extractor in AMOUNT_PATTERNS:
            match = re.search(pattern, self.lower_text)
            if match:
                return extractor(match)
        return None

    def _score_action(self) -> float:
        """Score how clear the action intent is (0-1)."""
        if self.action == "unknown":
            return 0.2  # Low confidence but not zero
        return 0.8

    def _score_categories(self) -> float:
        """Score how many categories the intent mentions (0-1)."""
        if not self.categories:
            return 0.3  # Unclassifiable
        if len(self.categories) == 1:
            return 0.9  # Clear single category
        return 0.6  # Multiple categories mentioned


class AdvancedIntentMatcher:
    """Enhanced intent matcher with structured extraction and multi-signal scoring."""

    def check_intent_match(self, stated_intent: str, cart: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check if stated intent matches the cart contents.

        Returns the same interface as intent_match.check_intent_match():
        {
            "match": bool,
            "inferred_category": str,
            "cart_categories": list,
            "reason": str,
            "mismatch_severity": str,  # none/low/medium/high
        }
        """
        intent = StructuredIntent(stated_intent)
        cart_categories = {item["category"] for item in cart}
        total_amount = sum(item["amount"] for item in cart)

        # Signal 1: Category match
        category_match = self._compute_category_match(intent, cart_categories)

        # Signal 2: Amount plausibility (if intent mentions an amount)
        amount_plausibility = self._compute_amount_plausibility(
            intent, total_amount
        )

        # Signal 3: Action coherence
        action_coherence = self._compute_action_coherence(intent, cart_categories)

        # Composite score
        composite = self._composite_score(
            category_match, amount_plausibility, action_coherence
        )

        # Determine mismatch severity
        severity = self._determine_severity(composite, intent, cart_categories)

        # Build reason
        reason = self._build_reason(
            intent, cart_categories, category_match, amount_plausibility, composite
        )

        return {
            "match": severity in ("none", "low"),
            "inferred_category": intent.categories[0] if intent.categories else "unknown",
            "cart_categories": list(cart_categories),
            "reason": reason,
            "mismatch_severity": severity,
            "intent_signals": {
                "action": intent.action,
                "mentioned_amount": intent.mentioned_amount,
                "category_match": round(category_match, 3),
                "amount_plausibility": round(amount_plausibility, 3),
                "action_coherence": round(action_coherence, 3),
                "composite_score": round(composite, 3),
            },
        }

    def _compute_category_match(
        self, intent: StructuredIntent, cart_categories: set
    ) -> float:
        """How well do the intent's categories match the cart?"""
        if not intent.categories:
            return 0.5  # No classifiable category

        intent_set = set(intent.categories)
        overlap = intent_set & cart_categories

        if not overlap:
            return 0.0  # Complete mismatch

        # Partial match if some categories overlap
        coverage = len(overlap) / len(cart_categories)
        return 0.5 + 0.5 * coverage

    def _compute_amount_plausibility(
        self, intent: StructuredIntent, cart_total: float
    ) -> float:
        """If the intent mentions an amount, how close is it to the cart total?"""
        if intent.mentioned_amount is None:
            return 0.7  # No amount mentioned — neutral

        ratio = cart_total / intent.mentioned_amount if intent.mentioned_amount > 0 else 0

        if 0.8 <= ratio <= 1.2:
            return 1.0  # Very close
        elif 0.5 <= ratio <= 2.0:
            return 0.6  # Plausible range
        else:
            return 0.1  # Very different

    def _compute_action_coherence(
        self, intent: StructuredIntent, cart_categories: set
    ) -> float:
        """Is the action coherent with what's in the cart?"""
        if intent.action in ("buy", "reorder", "unknown"):
            return 0.8  # Standard purchase actions
        elif intent.action in ("return", "cancel"):
            return 0.5  # Different flow, but legitimate
        return 0.7

    def _composite_score(
        self,
        category_match: float,
        amount_plausibility: float,
        action_coherence: float,
    ) -> float:
        """Weighted composite of all signals."""
        return (
            0.55 * category_match
            + 0.25 * amount_plausibility
            + 0.20 * action_coherence
        )

    def _determine_severity(
        self,
        composite: float,
        intent: StructuredIntent,
        cart_categories: set,
    ) -> str:
        """Map composite score to mismatch severity."""
        if composite >= 0.7:
            return "none"
        elif composite >= 0.5:
            return "low"
        elif composite >= 0.3:
            return "medium"
        else:
            return "high"

    def _build_reason(
        self,
        intent: StructuredIntent,
        cart_categories: set,
        category_match: float,
        amount_plausibility: float,
        composite: float,
    ) -> str:
        """Build a human-readable reason string."""
        if not intent.categories:
            return (
                "Stated intent phrasing was not confidently classifiable "
                "into a known category"
            )

        if category_match >= 0.7:
            return "Cart contents match the stated intent category"

        if intent.categories and not (set(intent.categories) & cart_categories):
            return (
                f"Stated intent implies '{intent.categories[0]}' but cart "
                f"contains {list(cart_categories)} -- possible hijack/injection"
            )

        return (
            f"Partial match: intent categories {intent.categories} "
            f"overlap with cart {list(cart_categories)} "
            f"(composite score: {composite:.2f})"
        )


# Module-level instance
_advanced_matcher = None


def get_advanced_matcher() -> AdvancedIntentMatcher:
    """Get the singleton advanced intent matcher."""
    global _advanced_matcher
    if _advanced_matcher is None:
        _advanced_matcher = AdvancedIntentMatcher()
    return _advanced_matcher
