"""
Generates a labeled synthetic dataset of AI-agent purchase requests
covering every failure mode KYA is designed to catch, plus clean
legitimate traffic, so we can report real precision/recall instead
of cherry-picked demo scenarios.
"""

import random
import json
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from registry import issue_delegation_token  # noqa: E402

random.seed(42)

# --- Deterministic-evaluation fix ---------------------------------
# The dataset used to bake real wall-clock timestamps into every
# token's absolute expiry. That made the reported precision/recall/F1
# a function of *when you happened to run the harness*, not of the
# code: shortly after generation, real legit tokens (long TTL) were
# still valid and everything scored fine; an hour later they'd all
# expired too and the system correctly-but-uselessly BLOCKed almost
# everything, cratering the numbers for reasons having nothing to do
# with the intent matcher or risk engine being evaluated.
#
# Fix: every token below is issued relative to a fixed EPOCH (not
# real time), and the harness evaluates them against an explicit,
# versioned `eval_time` recorded in eval_manifest.json rather than
# whatever `time.time()` happens to return when someone runs it.
# Regenerating the dataset regenerates the manifest to match, so the
# two never drift apart, and re-running the harness next year against
# the same dataset file reproduces the same numbers.
EPOCH = 1_700_000_000  # arbitrary fixed base, not real time
GEN_OFFSET = 0          # all tokens "issued" at EPOCH + GEN_OFFSET
EVAL_OFFSET = 200        # harness evaluates as if "now" = EPOCH + EVAL_OFFSET
#   -> after the delegation_expired tokens' expiry (issued_at=EPOCH-1000,
#      ttl_seconds=100 -> expires at EPOCH-900), and well before the
#      legit tokens' expiry (EPOCH + 3600), so both populations land on
#      their intended side of "now" regardless of wall-clock time.

AGENTS = {
    "agent_procure_bot_042": {"mean": 1200.0, "std": 350.0, "categories": ["groceries", "office_supplies"], "human": "user_priya_88"},
    "agent_shopgenie_777": {"mean": 900.0, "std": 400.0, "categories": ["electronics", "groceries"], "human": "user_rahul_12"},
}

GROCERY_ITEMS = ["Vegetables box", "Milk (2L)", "Rice (5kg)", "Snacks pack", "Fruit basket"]
OFFICE_ITEMS = ["Printer paper", "Pens (box)", "Notebooks", "Toner cartridge"]
ELECTRONICS_ITEMS = ["Wireless earbuds", "Gaming laptop", "Smartphone", "4K monitor", "Bluetooth speaker"]

CATEGORY_ITEMS = {"groceries": GROCERY_ITEMS, "office_supplies": OFFICE_ITEMS, "electronics": ELECTRONICS_ITEMS}
CATEGORY_INTENT_PHRASE = {
    "groceries": "buy groceries for the week",
    "office_supplies": "reorder office supplies",
    "electronics": "buy electronics",
}


def make_cart(category, amount):
    item = random.choice(CATEGORY_ITEMS[category])
    return [{"item": item, "category": category, "amount": round(amount, 2)}]


def sample_normal_amount(mean, std):
    amt = random.gauss(mean, std * 0.6)
    return max(50.0, amt)


def gen_legit_normal(i):
    agent_id = random.choice(list(AGENTS.keys()))
    a = AGENTS[agent_id]
    category = random.choice(a["categories"])
    amount = sample_normal_amount(a["mean"], a["std"])
    token = issue_delegation_token(agent_id, a["human"], max_amount=a["mean"] * 5, allowed_categories=a["categories"], issued_at=EPOCH + GEN_OFFSET)
    return {
        "id": f"req_{i:04d}", "case_type": "legit_normal", "expected_decision": "APPROVE",
        "agent_id": agent_id, "delegation_token": token,
        "stated_intent": CATEGORY_INTENT_PHRASE[category],
        "cart": make_cart(category, amount),
    }


def gen_spoofed_identity(i):
    fake_id = f"agent_unknown_{random.randint(1000,9999)}"
    fake_token = json.dumps({"payload": "{}", "signature": "0" * 64})
    category = random.choice(list(CATEGORY_ITEMS.keys()))
    amount = random.uniform(200, 3000)
    return {
        "id": f"req_{i:04d}", "case_type": "spoofed_identity", "expected_decision": "BLOCK",
        "agent_id": fake_id, "delegation_token": fake_token,
        "stated_intent": CATEGORY_INTENT_PHRASE[category],
        "cart": make_cart(category, amount),
    }


def gen_intent_hijack(i):
    agent_id = random.choice(list(AGENTS.keys()))
    a = AGENTS[agent_id]
    stated_category = random.choice(a["categories"])
    other_categories = [c for c in CATEGORY_ITEMS.keys() if c != stated_category]
    cart_category = random.choice(other_categories)
    amount = sample_normal_amount(a["mean"] * 3, a["std"])
    token = issue_delegation_token(agent_id, a["human"], max_amount=a["mean"] * 20, allowed_categories=list(CATEGORY_ITEMS.keys()), issued_at=EPOCH + GEN_OFFSET)
    return {
        "id": f"req_{i:04d}", "case_type": "intent_hijack", "expected_decision": "BLOCK",
        "agent_id": agent_id, "delegation_token": token,
        "stated_intent": CATEGORY_INTENT_PHRASE[stated_category],
        "cart": make_cart(cart_category, amount),
    }


def gen_scope_violation(i):
    agent_id = random.choice(list(AGENTS.keys()))
    a = AGENTS[agent_id]
    allowed = [a["categories"][0]]  # token only allows one category
    violating_category = random.choice([c for c in CATEGORY_ITEMS.keys() if c not in allowed])
    amount = sample_normal_amount(a["mean"], a["std"])
    token = issue_delegation_token(agent_id, a["human"], max_amount=a["mean"] * 10, allowed_categories=allowed, issued_at=EPOCH + GEN_OFFSET)
    return {
        "id": f"req_{i:04d}", "case_type": "scope_violation", "expected_decision": "BLOCK",
        "agent_id": agent_id, "delegation_token": token,
        "stated_intent": CATEGORY_INTENT_PHRASE[violating_category],
        "cart": make_cart(violating_category, amount),
    }


def gen_drift_moderate(i):
    agent_id = random.choice(list(AGENTS.keys()))
    a = AGENTS[agent_id]
    category = random.choice(a["categories"])
    amount = a["mean"] + random.uniform(3.0, 4.2) * a["std"]  # z roughly 3-4.2 -> step-up band
    token = issue_delegation_token(agent_id, a["human"], max_amount=a["mean"] * 50, allowed_categories=a["categories"], issued_at=EPOCH + GEN_OFFSET)
    return {
        "id": f"req_{i:04d}", "case_type": "drift_moderate", "expected_decision": "STEP_UP",
        "agent_id": agent_id, "delegation_token": token,
        "stated_intent": CATEGORY_INTENT_PHRASE[category],
        "cart": make_cart(category, amount),
    }


def gen_drift_extreme(i):
    agent_id = random.choice(list(AGENTS.keys()))
    a = AGENTS[agent_id]
    category = random.choice(a["categories"])
    amount = a["mean"] + random.uniform(6.0, 12.0) * a["std"]  # far beyond step-up -> block band
    token = issue_delegation_token(agent_id, a["human"], max_amount=a["mean"] * 100, allowed_categories=a["categories"], issued_at=EPOCH + GEN_OFFSET)
    return {
        "id": f"req_{i:04d}", "case_type": "drift_extreme", "expected_decision": "BLOCK",
        "agent_id": agent_id, "delegation_token": token,
        "stated_intent": CATEGORY_INTENT_PHRASE[category],
        "cart": make_cart(category, amount),
    }


def gen_delegation_expired(i):
    agent_id = random.choice(list(AGENTS.keys()))
    a = AGENTS[agent_id]
    category = random.choice(a["categories"])
    amount = sample_normal_amount(a["mean"], a["std"])
    token = issue_delegation_token(agent_id, a["human"], max_amount=a["mean"] * 5, allowed_categories=a["categories"], ttl_seconds=100, issued_at=EPOCH - 1000)
    return {
        "id": f"req_{i:04d}", "case_type": "delegation_expired", "expected_decision": "BLOCK",
        "agent_id": agent_id, "delegation_token": token,
        "stated_intent": CATEGORY_INTENT_PHRASE[category],
        "cart": make_cart(category, amount),
    }


def gen_delegation_replay(i):
    """Token issued for one agent, presented by a different agent_id -- simulates token theft/replay."""
    agents = list(AGENTS.keys())
    issued_for, presented_by = random.sample(agents, 2) if len(agents) > 1 else (agents[0], agents[0])
    a = AGENTS[issued_for]
    category = random.choice(a["categories"])
    amount = sample_normal_amount(a["mean"], a["std"])
    token = issue_delegation_token(issued_for, a["human"], max_amount=a["mean"] * 5, allowed_categories=a["categories"], issued_at=EPOCH + GEN_OFFSET)
    return {
        "id": f"req_{i:04d}", "case_type": "delegation_replay", "expected_decision": "BLOCK",
        "agent_id": presented_by, "delegation_token": token,
        "stated_intent": CATEGORY_INTENT_PHRASE[category],
        "cart": make_cart(category, amount),
    }


# --- Adversarial / hard cases: these are expected to stress-test known
# weak points (the keyword-based intent matcher, threshold boundaries)
# rather than confirm the system works. Mixing them in is the honest
# version of evaluation -- a dataset built from the same taxonomy as
# the detector will always score close to 100%.

AMBIGUOUS_INTENT_PHRASES = [
    "pick up some essentials for home",
    "handle the usual weekly errand",
    "take care of the recurring order",
    "get the items on the list",
    "place the usual order",
]


def gen_ambiguous_intent_legit(i):
    """Legitimate purchase, but phrased in a way the keyword-based
    intent matcher cannot classify -- tests whether an 'unknown intent'
    reading causes an unnecessary block/step-up on real traffic."""
    agent_id = random.choice(list(AGENTS.keys()))
    a = AGENTS[agent_id]
    category = random.choice(a["categories"])
    amount = sample_normal_amount(a["mean"], a["std"])
    token = issue_delegation_token(agent_id, a["human"], max_amount=a["mean"] * 5, allowed_categories=a["categories"], issued_at=EPOCH + GEN_OFFSET)
    return {
        "id": f"req_{i:04d}", "case_type": "ambiguous_intent_legit", "expected_decision": "APPROVE",
        "agent_id": agent_id, "delegation_token": token,
        "stated_intent": random.choice(AMBIGUOUS_INTENT_PHRASES),
        "cart": make_cart(category, amount),
    }


def gen_boundary_drift(i):
    """Amount placed right at the step-up/block threshold boundary --
    tests whether the discrete APPROVE/STEP_UP/BLOCK bands behave
    sensibly at the edges rather than just in the easy middle of each band."""
    agent_id = random.choice(list(AGENTS.keys()))
    a = AGENTS[agent_id]
    category = random.choice(a["categories"])
    # z around 2.0 (edge of step-up band, from decision_engine STEP_UP_THRESHOLD=25 -> sub_score=25 -> z=2.0)
    z = random.choice([1.8, 2.0, 2.2, 4.2, 4.3, 4.6])
    amount = a["mean"] + z * a["std"]
    token = issue_delegation_token(agent_id, a["human"], max_amount=a["mean"] * 50, allowed_categories=a["categories"], issued_at=EPOCH + GEN_OFFSET)
    expected = "STEP_UP" if 2.0 <= z <= 4.4 else ("APPROVE" if z < 2.0 else "BLOCK")
    return {
        "id": f"req_{i:04d}", "case_type": "boundary_drift", "expected_decision": expected,
        "agent_id": agent_id, "delegation_token": token,
        "stated_intent": CATEGORY_INTENT_PHRASE[category],
        "cart": make_cart(category, amount),
        "_z": z,
    }


GENERATORS_WEIGHTED = [
    (gen_legit_normal, 40),
    (gen_spoofed_identity, 15),
    (gen_intent_hijack, 15),
    (gen_scope_violation, 10),
    (gen_drift_moderate, 12),
    (gen_drift_extreme, 8),
    (gen_delegation_expired, 6),
    (gen_delegation_replay, 6),
]

ADVERSARIAL_GENERATORS = [
    (gen_ambiguous_intent_legit, 15),
    (gen_boundary_drift, 15),
]


def generate_dataset(n=150, include_adversarial=True):
    pool = []
    for gen, weight in GENERATORS_WEIGHTED:
        pool.extend([gen] * weight)
    dataset = []
    for i in range(n):
        gen = random.choice(pool)
        dataset.append(gen(i))

    if include_adversarial:
        idx = n
        for gen, count in ADVERSARIAL_GENERATORS:
            for _ in range(count):
                dataset.append(gen(idx))
                idx += 1

    return dataset


if __name__ == "__main__":
    data = generate_dataset(150)
    out_path = os.path.join(os.path.dirname(__file__), "synthetic_dataset.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    # Manifest: pins the evaluation clock to this dataset so the
    # harness never has to guess "now." Regenerating the dataset
    # regenerates this alongside it, so they can't drift apart.
    manifest = {
        "dataset_version": 2,
        "epoch": EPOCH,
        "generated_at_offset": GEN_OFFSET,
        "eval_time": EPOCH + EVAL_OFFSET,
        "note": (
            "eval_time is a fixed logical clock, not wall time. "
            "eval/harness.py evaluates every delegation token's "
            "expiry against this value. Do not replace it with "
            "time.time() -- that reintroduces the original "
            "non-determinism bug (results depending on when the "
            "harness happens to be run)."
        ),
    }
    manifest_path = os.path.join(os.path.dirname(__file__), "eval_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    from collections import Counter
    counts = Counter(d["case_type"] for d in data)
    print(f"Generated {len(data)} synthetic requests -> {out_path}")
    print(f"Wrote eval clock manifest -> {manifest_path} (eval_time={manifest['eval_time']})")
    for k, v in counts.items():
        print(f"  {k}: {v}")
