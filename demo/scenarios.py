"""
Run all four KYA demo scenarios against the local API.
Usage: python3 scenarios.py   (make sure the server is running on :8000)
"""

import sys
import os

# Ensure UTF-8 output on Windows (cp1252 can't encode ₹ and other
# Unicode characters used in the scenario titles below).
if sys.stdout.encoding and sys.stdout.encoding.lower().replace("-", "") != "utf8":
    sys.stdout.reconfigure(encoding="utf-8")

import requests
import json

BASE = "http://localhost:8000"
DEMO_KEY = os.environ.get("KYA_DEMO_ISSUER_KEY")
if not DEMO_KEY:
    print("ERROR: KYA_DEMO_ISSUER_KEY environment variable is not set.")
    print("Set it before running:")
    print("  PowerShell: $env:KYA_DEMO_ISSUER_KEY=\"your-key\"")
    print("  CMD:        set KYA_DEMO_ISSUER_KEY=your-key")
    print("  Bash:       export KYA_DEMO_ISSUER_KEY=your-key")
    sys.exit(1)
AUTH_HEADERS = {"X-Kya-Demo-Key": DEMO_KEY}


def pretty(title, resp):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)
    print(json.dumps(resp, indent=2))


def scenario_1_legit_purchase():
    """Registered agent, valid delegation, cart matches intent, normal amount."""
    token_resp = requests.post(
        f"{BASE}/issue-token",
        headers=AUTH_HEADERS,
        json={
            "agent_id": "agent_procure_bot_042",
            "human_id": "user_priya_88",
            "max_amount": 5000,
            "categories": ["groceries", "office_supplies"],
        },
    ).json()

    req = {
        "agent_id": "agent_procure_bot_042",
        "delegation_token": token_resp["delegation_token"],
        "stated_intent": "buy groceries for the week",
        "cart": [
            {"item": "Vegetables box", "category": "groceries", "amount": 600},
            {"item": "Milk (2L)", "category": "groceries", "amount": 300},
        ],
    }
    resp = requests.post(f"{BASE}/verify", json=req).json()
    pretty("SCENARIO 1 — Legitimate purchase, verified agent, matching intent", resp)


def scenario_2_unregistered_agent():
    """Unknown/spoofed agent attempts checkout with a fake token."""
    fake_token = json.dumps({"payload": "{}", "signature": "not-a-real-signature"})
    req = {
        "agent_id": "agent_shadow_bot_999",
        "delegation_token": fake_token,
        "stated_intent": "buy electronics",
        "cart": [{"item": "Wireless earbuds", "category": "electronics", "amount": 2500}],
    }
    resp = requests.post(f"{BASE}/verify", json=req).json()
    pretty("SCENARIO 2 — Unregistered / spoofed agent identity", resp)


def scenario_3_intent_mismatch():
    """Registered + delegated agent, but cart doesn't match stated intent
    (simulates prompt-injection / hijack mid-task)."""
    token_resp = requests.post(
        f"{BASE}/issue-token",
        headers=AUTH_HEADERS,
        json={
            "agent_id": "agent_shopgenie_777",
            "human_id": "user_rahul_12",
            "max_amount": 50000,
            "categories": ["electronics", "groceries"],
        },
    ).json()

    req = {
        "agent_id": "agent_shopgenie_777",
        "delegation_token": token_resp["delegation_token"],
        "stated_intent": "buy groceries for the week",
        "cart": [{"item": "Gaming laptop", "category": "electronics", "amount": 42000}],
    }
    resp = requests.post(f"{BASE}/verify", json=req).json()
    pretty("SCENARIO 3 — Intent mismatch (stated groceries, cart is a ₹42k laptop)", resp)


def scenario_4_behavioral_drift_step_up():
    """Registered + delegated agent, category matches, but amount is a
    huge deviation from its historical baseline -> step-up required."""
    token_resp = requests.post(
        f"{BASE}/issue-token",
        headers=AUTH_HEADERS,
        json={
            "agent_id": "agent_procure_bot_042",
            "human_id": "user_priya_88",
            "max_amount": 100000,
            "categories": ["groceries", "office_supplies"],
        },
    ).json()

    req = {
        "agent_id": "agent_procure_bot_042",
        "delegation_token": token_resp["delegation_token"],
        "stated_intent": "reorder office printer paper",
        "cart": [{"item": "Bulk printer paper (large order)", "category": "office_supplies", "amount": 2500}],
    }
    resp = requests.post(f"{BASE}/verify", json=req).json()
    pretty("SCENARIO 4 — Behavioral drift (~2x this agent's normal spend) -> STEP_UP", resp)

    if resp["decision"] == "STEP_UP":
        confirm = requests.post(
            f"{BASE}/step-up/confirm",
            json={"audit_id": resp["audit_id"], "human_confirmed": True},
        ).json()
        pretty("SCENARIO 4b — Human confirms the step-up challenge", confirm)


if __name__ == "__main__":
    scenario_1_legit_purchase()
    scenario_2_unregistered_agent()
    scenario_3_intent_mismatch()
    scenario_4_behavioral_drift_step_up()
