import pytest
from fastapi.testclient import TestClient
from main import app, DEMO_ISSUER_KEY
from registry import get_agent, update_agent_limit, issue_delegation_token
from pipeline import run_pipeline

client = TestClient(app)

def test_update_agent_limit_endpoint():
    # Test unauthorized request
    resp = client.put("/agents/agent_procure_bot_042/limit", json={"owner_max_amount": 5000})
    assert resp.status_code == 401

    # Test authorized request
    headers = {"X-Kya-Demo-Key": DEMO_ISSUER_KEY}
    resp = client.put("/agents/agent_procure_bot_042/limit", json={"owner_max_amount": 7500}, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["owner_max_amount"] == 7500

    # Verify updated in registry
    agent = get_agent("agent_procure_bot_042")
    assert agent["owner_max_amount"] == 7500

    # Reset back to default ₹6000
    client.put("/agents/agent_procure_bot_042/limit", json={"owner_max_amount": 6000}, headers=headers)

def test_owner_limit_enforcement_in_pipeline():
    try:
        # Set limit to 1200
        update_agent_limit("agent_procure_bot_042", 1200.0)
        token = issue_delegation_token("agent_procure_bot_042", "user_priya_88", 5000.0, ["groceries"])

        # Transaction within limit (600)
        res1 = run_pipeline("agent_procure_bot_042", token, "buy groceries for the week", [{"item": "Vegetables box", "category": "groceries", "amount": 600.0}])
        assert res1["within_delegated_limit"] is True
        assert res1["decision"] == "APPROVE"

        # Transaction exceeding limit (1201)
        res2 = run_pipeline("agent_procure_bot_042", token, "buy groceries for the week", [{"item": "Vegetables box", "category": "groceries", "amount": 1201.0}])
        assert res2["within_delegated_limit"] is False
        assert res2["decision"] == "BLOCK"
    finally:
        update_agent_limit("agent_procure_bot_042", 6000.0)
