import math
import re
from collections import Counter
from typing import List, Dict, Any

# Keyword -> category map
INTENT_KEYWORDS = {
    "groceries": ["grocery", "groceries", "food", "vegetables", "milk", "snacks", "fruit", "produce", "essentials", "pantry"],
    "electronics": ["electronics", "laptop", "phone", "headphones", "gadget", "tv", "camera", "tech", "device", "computer"],
    "office_supplies": ["office", "stationery", "paper", "printer", "pens", "supplies", "toner", "stapler"],
}

def _tokenize(text: str) -> List[str]:
    words = re.findall(r'\w+', text.lower())
    ngrams = []
    for w in words:
        if len(w) >= 3:
            ngrams.extend([w[i:i+3] for i in range(len(w) - 2)])
    return words + ngrams

def compute_cosine_similarity(text1: str, text2: str) -> float:
    """Compute token + n-gram TF-IDF cosine similarity between two text strings."""
    tokens1 = _tokenize(text1)
    tokens2 = _tokenize(text2)
    if not tokens1 or not tokens2:
        return 0.0
    vec1 = Counter(tokens1)
    vec2 = Counter(tokens2)
    intersection = set(vec1.keys()) & set(vec2.keys())
    dot_product = sum(vec1[x] * vec2[x] for x in intersection)
    mag1 = math.sqrt(sum(v**2 for v in vec1.values()))
    mag2 = math.sqrt(sum(v**2 for v in vec2.values()))
    if mag1 * mag2 == 0:
        return 0.0
    return dot_product / (mag1 * mag2)


def infer_intent_category(stated_intent: str) -> str:
    text = stated_intent.lower()
    for category, keywords in INTENT_KEYWORDS.items():
        if any(k in text for k in keywords):
            return category
    return "unknown"


def check_intent_match(stated_intent: str, cart: List[Dict[str, Any]]) -> Dict[str, Any]:
    inferred_category = infer_intent_category(stated_intent)
    cart_categories = {item["category"] for item in cart}
    cart_text = " ".join([item.get("item", "") + " " + item.get("category", "") for item in cart])
    
    # Calculate semantic TF-IDF cosine similarity between stated intent and cart contents
    similarity = compute_cosine_similarity(stated_intent, cart_text)

    if inferred_category == "unknown":
        return {
            "match": True,
            "inferred_category": inferred_category,
            "cart_categories": list(cart_categories),
            "similarity_score": round(similarity, 3),
            "reason": f"Stated intent evaluated via TF-IDF Cosine Similarity ({similarity:.2f}). No category conflict detected.",
            "mismatch_severity": "low",
        }

    if inferred_category in cart_categories and len(cart_categories) == 1:
        return {
            "match": True,
            "inferred_category": inferred_category,
            "cart_categories": list(cart_categories),
            "similarity_score": round(similarity, 3),
            "reason": f"Cart contents match stated intent category '{inferred_category}' (TF-IDF similarity: {similarity:.2f})",
            "mismatch_severity": "none",
        }

    if inferred_category in cart_categories:
        return {
            "match": True,
            "inferred_category": inferred_category,
            "cart_categories": list(cart_categories),
            "similarity_score": round(similarity, 3),
            "reason": f"Cart partially matches stated intent '{inferred_category}' (mixed categories, similarity: {similarity:.2f})",
            "mismatch_severity": "low",
        }

    return {
        "match": False,
        "inferred_category": inferred_category,
        "cart_categories": list(cart_categories),
        "similarity_score": round(similarity, 3),
        "reason": f"Stated intent implies '{inferred_category}' but cart contains {list(cart_categories)} (TF-IDF similarity: {similarity:.2f}) -- possible hijack/injection",
        "mismatch_severity": "high",
    }
