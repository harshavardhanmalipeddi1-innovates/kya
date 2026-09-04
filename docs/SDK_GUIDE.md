# KYA — Developer Integration & AI Agent SDK Guide

> Know Your Agent: Cross-transaction identity, delegation, intent and risk verification
> layer for AI-agent-initiated payments on Razorpay.

## Table of Contents

1. [Overview](#overview)
2. [REST API Reference](#rest-api-reference)
3. [Python SDK (Direct)](#python-sdk-direct)
4. [LangChain Integration](#langchain-integration)
5. [CrewAI Integration](#crewai-integration)
6. [AutoGen Integration](#autogen-integration)
7. [Webhook Handling](#webhook-handling)
8. [Compliance & Audit](#compliance--audit)
9. [Security Best Practices](#security-best-practices)

---

## Overview

KYA (Know Your Agent) sits between your AI agent and the payment provider (Razorpay),
enforcing a 5-stage security gate before any money moves:

```
🤖 AI Agent  →  🛡 KYA Gate  →  💳 Razorpay
```

**Pipeline stages:**
1. **Identity** — Is this agent registered and verified?
2. **Delegation** — Is there a signed, scoped, unexpired human mandate?
3. **Scope + Limit** — Is the purchase category and amount within the mandate?
4. **Intent Match** — Does the cart match the agent's stated intent?
5. **Risk Score** — Behavioral drift + composite risk scoring

**Decisions:** `APPROVE` | `STEP_UP` (human confirmation required) | `BLOCK`

---

## REST API Reference

### Base URL
```
https://kya-backend.onrender.com   (production)
http://localhost:8000               (local development)
```

### Authentication
All endpoints require the `X-Kya-Demo-Key` header:
```
X-Kya-Demo-Key: <your-demo-key>
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/verify` | Run full KYA pipeline on a purchase request |
| `POST` | `/issue-token` | Issue a delegation token (demo only) |
| `POST` | `/step-up/confirm` | Confirm/decline a step-up challenge |
| `GET` | `/agents` | List registered agents |
| `GET` | `/audit` | List audit trail |
| `GET` | `/health` | Health check |
| `POST` | `/webhooks/razorpay` | Razorpay webhook receiver |
| `POST` | `/razorpay-webhook` | Alias for `/webhooks/razorpay` |
| `GET` | `/metrics` | Prometheus metrics |

### `POST /verify` — Verify a Purchase Request

**Request:**
```json
{
  "agent_id": "agent_procure_bot_042",
  "delegation_token": "<token-from-issue-token>",
  "stated_intent": "buy groceries for the week",
  "cart": [
    {"item": "Rice (5kg)", "category": "groceries", "amount": 450},
    {"item": "Milk (2L)", "category": "groceries", "amount": 80}
  ]
}
```

**Response (APPROVE):**
```json
{
  "audit_id": "audit_a1b2c3d4e5",
  "decision": "APPROVE",
  "reasons": ["All checks passed. Composite risk score 0/100 is within normal range."],
  "risk": {
    "total_score": 0,
    "components": {
      "behavioral_drift": 0,
      "identity_penalty": 0,
      "delegation_penalty": 0,
      "intent_mismatch_penalty": 0
    }
  },
  "intent_result": {"mismatch_severity": "none", "reason": "Intent matches cart"},
  "payment": {
    "razorpay_order_id": "order_abc123",
    "amount": 530,
    "currency": "INR",
    "status": "created"
  }
}
```

**Response (STEP_UP):**
```json
{
  "audit_id": "audit_x9y8z7w6",
  "decision": "STEP_UP",
  "reasons": ["Composite risk score 35/100 exceeds step-up threshold (25)."],
  "risk": {"total_score": 35, "components": {...}},
  "intent_result": {...},
  "payment": null
}
```

**Response (BLOCK):**
```json
{
  "audit_id": "audit_m3n4o5p6",
  "decision": "BLOCK",
  "reasons": ["Agent identity is not registered/verified."],
  "risk": {"total_score": 100, "components": {...}},
  "intent_result": {...},
  "payment": null
}
```

### `POST /issue-token` — Issue Delegation Token

```json
{
  "agent_id": "agent_procure_bot_042",
  "human_id": "user_priya_88",
  "max_amount": 5000,
  "categories": ["groceries", "office_supplies"]
}
```

**Response:**
```json
{
  "delegation_token": "{\"payload\":\"{...}\",\"signature\":\"...\"}"
}
```

### `POST /step-up/confirm` — Confirm Step-Up

```json
{
  "audit_id": "audit_x9y8z7w6",
  "human_confirmed": true
}
```

---

## Python SDK (Direct)

Use the `requests` library to interact with KYA from any Python application:

```python
import requests

KYA_API = "http://localhost:8000"
DEMO_KEY = "your-demo-key-here"

headers = {
    "Content-Type": "application/json",
    "X-Kya-Demo-Key": DEMO_KEY,
}

# 1. Issue a delegation token
token_resp = requests.post(f"{KYA_API}/issue-token", headers=headers, json={
    "agent_id": "agent_procure_bot_042",
    "human_id": "user_priya_88",
    "max_amount": 5000,
    "categories": ["groceries", "office_supplies"],
})
token = token_resp.json()["delegation_token"]

# 2. Verify a purchase
verify_resp = requests.post(f"{KYA_API}/verify", headers=headers, json={
    "agent_id": "agent_procure_bot_042",
    "delegation_token": token,
    "stated_intent": "buy groceries for the week",
    "cart": [
        {"item": "Rice (5kg)", "category": "groceries", "amount": 450},
        {"item": "Milk (2L)", "category": "groceries", "amount": 80},
    ],
})
result = verify_resp.json()

if result["decision"] == "APPROVE":
    print(f"Payment order created: {result['payment']['razorpay_order_id']}")
elif result["decision"] == "STEP_UP":
    print(f"Human confirmation needed. Audit ID: {result['audit_id']}")
    # 3. Confirm step-up (e.g., after OTP verification)
    confirm_resp = requests.post(f"{KYA_API}/step-up/confirm", headers=headers, json={
        "audit_id": result["audit_id"],
        "human_confirmed": True,
    })
    print(f"Step-up result: {confirm_resp.json()['decision']}")
else:
    print(f"Transaction blocked: {result['reasons']}")
```

---

## LangChain Integration

KYA integrates with LangChain as a **tool** that your agent can call before executing payments.

### As a LangChain Tool

```python
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.tools import tool
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
import requests

KYA_API = "http://localhost:8000"
DEMO_KEY = "your-demo-key"
HEADERS = {"Content-Type": "application/json", "X-Kya-Demo-Key": DEMO_KEY}


@tool
def kya_verify_purchase(
    agent_id: str,
    delegation_token: str,
    stated_intent: str,
    cart_items: str,
) -> str:
    """Verify an AI agent purchase through KYA security gate.

    Args:
        agent_id: The agent's registered ID.
        delegation_token: The signed delegation token from the human owner.
        stated_intent: Natural language description of what the agent wants to buy.
        cart_items: JSON string of cart items, e.g. '[{"item": "Rice", "category": "groceries", "amount": 450}]'
    """
    import json
    cart = json.loads(cart_items)

    resp = requests.post(
        f"{KYA_API}/verify",
        headers=HEADERS,
        json={
            "agent_id": agent_id,
            "delegation_token": delegation_token,
            "stated_intent": stated_intent,
            "cart": cart,
        },
    )
    result = resp.json()
    return (
        f"Decision: {result['decision']}\n"
        f"Risk Score: {result['risk']['total_score']}/100\n"
        f"Reasons: {', '.join(result['reasons'])}\n"
        f"Audit ID: {result.get('audit_id', 'N/A')}\n"
        f"Payment: {result.get('payment', {}).get('razorpay_order_id', 'N/A') if result.get('payment') else 'N/A'}"
    )


@tool
def kya_issue_token(
    agent_id: str,
    human_id: str,
    max_amount: float,
    categories: str,
) -> str:
    """Issue a delegation token for an AI agent.

    Args:
        agent_id: The agent's registered ID.
        human_id: The human owner's ID.
        max_amount: Maximum amount the agent can spend.
        categories: Comma-separated allowed categories, e.g. 'groceries,office_supplies'.
    """
    resp = requests.post(
        f"{KYA_API}/issue-token",
        headers=HEADERS,
        json={
            "agent_id": agent_id,
            "human_id": human_id,
            "max_amount": max_amount,
            "categories": [c.strip() for c in categories.split(",")],
        },
    )
    return resp.json().get("delegation_token", "ERROR")


# Create the agent
llm = ChatOpenAI(model="gpt-4o", temperature=0)
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are an AI shopping assistant. Always use KYA verification before making purchases."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])

agent = create_tool_calling_agent(llm, [kya_verify_purchase, kya_issue_token], prompt)
executor = AgentExecutor(agent=agent, tools=[kya_verify_purchase, kya_issue_token], verbose=True)

# Run the agent
response = executor.invoke({
    "input": "Buy 5kg of rice and 2L of milk for the office kitchen. I'm agent_procure_bot_042."
})
print(response["output"])
```

### As a LangChain Callback / Guard

```python
from langchain_core.callbacks import BaseCallbackHandler


class KYAGuardCallback(BaseCallbackHandler):
    """Callback that intercepts tool calls and routes payment
    actions through KYA verification."""

    def __init__(self, kya_api: str, demo_key: str):
        self.kya_api = kya_api
        self.headers = {"Content-Type": "application/json", "X-Kya-Demo-Key": demo_key}

    def on_tool_start(self, serialized, input_str, *, run_id, **kwargs):
        """Check if this is a payment tool call."""
        tool_name = serialized.get("name", "")
        if "pay" in tool_name.lower() or "purchase" in tool_name.lower():
            # Pre-verify with KYA before allowing the tool to execute
            # Your implementation would extract agent_id, amount, etc. from input_str
            print(f"[KYAGuard] Payment tool intercepted: {tool_name}")
            print(f"[KYAGuard] Running KYA verification before execution...")
```

---

## CrewAI Integration

KYA integrates with CrewAI as a **tool** for agent crews that handle purchasing workflows.

```python
from crewai import Agent, Task, Crew, Tool
import requests

KYA_API = "http://localhost:8000"
DEMO_KEY = "your-demo-key"
HEADERS = {"Content-Type": "application/json", "X-Kya-Demo-Key": DEMO_KEY}


class KYAVerificationTool(Tool):
    name = "kya_payment_verifier"
    description = (
        "Verify a purchase transaction through the KYA security gate. "
        "Returns APPROVE, STEP_UP (needs human confirmation), or BLOCK. "
        "Use this BEFORE any payment execution."
    )

    def _run(self, agent_id: str, intent: str, cart_json: str, token: str) -> str:
        import json
        cart = json.loads(cart_json)
        resp = requests.post(
            f"{KYA_API}/verify",
            headers=HEADERS,
            json={
                "agent_id": agent_id,
                "delegation_token": token,
                "stated_intent": intent,
                "cart": cart,
            },
        )
        result = resp.json()
        return (
            f"KYA Decision: {result['decision']} | "
            f"Risk: {result['risk']['total_score']}/100 | "
            f"Reasons: {'; '.join(result['reasons'])}"
        )


class KYATokenIssuer(Tool):
    name = "kya_token_issuer"
    description = "Issue a delegation token granting an agent spending authority."

    def _run(self, agent_id: str, human_id: str, max_amount: str, categories: str) -> str:
        resp = requests.post(
            f"{KYA_API}/issue-token",
            headers=HEADERS,
            json={
                "agent_id": agent_id,
                "human_id": human_id,
                "max_amount": float(max_amount),
                "categories": [c.strip() for c in categories.split(",")],
            },
        )
        return resp.json().get("delegation_token", "ERROR")


# Define agents
procurement_agent = Agent(
    role="Procurement Specialist",
    goal="Find the best deals on office supplies within budget",
    backstory="You are an expert at finding deals and managing procurement.",
    tools=[KYAVerificationTool(), KYATokenIssuer()],
    verbose=True,
)

# Define tasks
procurement_task = Task(
    description=(
        "Buy office supplies: 10 reams of A4 paper and 5 packs of pens. "
        "Agent ID: agent_procure_bot_042. Budget: ₹5000. "
        "Always verify the purchase through KYA before executing."
    ),
    agent=procurement_agent,
    expected_output="KYA verification result and purchase confirmation",
)

# Run the crew
crew = Crew(
    agents=[procurement_agent],
    tasks=[procurement_task],
    verbose=True,
)

result = crew.kickoff()
print(result)
```

---

## AutoGen Integration

KYA integrates with AutoGen as a function tool for multi-agent purchasing workflows.

```python
import autogen
from autogen import register_function
import requests
import json

KYA_API = "http://localhost:8000"
DEMO_KEY = "your-demo-key"
HEADERS = {"Content-Type": "application/json", "X-Kya-Demo-Key": DEMO_KEY}


def kya_verify(
    agent_id: str,
    delegation_token: str,
    stated_intent: str,
    cart_json: str,
) -> str:
    """Verify a purchase transaction through the KYA security gate.

    Args:
        agent_id: The registered agent ID.
        delegation_token: Signed delegation token from the human owner.
        stated_intent: Natural language purchase intent.
        cart_json: JSON string of cart items with item, category, and amount fields.

    Returns:
        KYA decision (APPROVE/STEP_UP/BLOCK) with risk score and reasons.
    """
    cart = json.loads(cart_json)
    resp = requests.post(
        f"{KYA_API}/verify",
        headers=HEADERS,
        json={
            "agent_id": agent_id,
            "delegation_token": delegation_token,
            "stated_intent": stated_intent,
            "cart": cart,
        },
    )
    result = resp.json()
    return json.dumps({
        "decision": result["decision"],
        "risk_score": result["risk"]["total_score"],
        "reasons": result["reasons"],
        "audit_id": result.get("audit_id"),
        "payment_order_id": result.get("payment", {}).get("razorpay_order_id") if result.get("payment") else None,
    })


def kya_issue_token(
    agent_id: str,
    human_id: str,
    max_amount: float,
    categories: str,
) -> str:
    """Issue a delegation token granting an agent spending authority.

    Args:
        agent_id: The agent's registered ID.
        human_id: The human owner's ID.
        max_amount: Maximum spending limit in INR.
        categories: Comma-separated list of allowed categories.

    Returns:
        The delegation token string.
    """
    resp = requests.post(
        f"{KYA_API}/issue-token",
        headers=HEADERS,
        json={
            "agent_id": agent_id,
            "human_id": human_id,
            "max_amount": max_amount,
            "categories": [c.strip() for c in categories.split(",")],
        },
    )
    return resp.json().get("delegation_token", "ERROR")


def kya_step_up(audit_id: str, confirmed: bool) -> str:
    """Confirm or decline a KYA step-up challenge.

    Args:
        audit_id: The audit ID from a STEP_UP decision.
        confirmed: True to approve, False to decline.

    Returns:
        The step-up confirmation result.
    """
    resp = requests.post(
        f"{KYA_API}/step-up/confirm",
        headers=HEADERS,
        json={"audit_id": audit_id, "human_confirmed": confirmed},
    )
    return json.dumps(resp.json())


# Create LLM config
llm_config = {
    "config_list": [{"model": "gpt-4o", "api_key": "your-api-key"}],
    "temperature": 0,
}

# Create agents
shopping_agent = autogen.AssistantAgent(
    name="ShoppingAgent",
    system_message=(
        "You are an AI shopping agent. You MUST verify every purchase "
        "through the KYA security gate using the kya_verify tool BEFORE "
        "executing any payment. Never skip this step."
    ),
    llm_config=llm_config,
)

admin_agent = autogen.AssistantAgent(
    name="AdminAgent",
    system_message=(
        "You are the human administrator. You issue delegation tokens "
        "and handle step-up confirmations. Always verify purchases are "
        "legitimate before approving."
    ),
    llm_config=llm_config,
)

user_proxy = autogen.UserProxyAgent(
    name="HumanOwner",
    human_input_mode="NEVER",
    max_consecutive_auto_reply=10,
    is_termination_msg=lambda x: x.get("content", "").rstrip().endswith("TERMINATE"),
    code_execution_config=False,
)

# Register tools
register_function(
    kya_verify,
    caller=shopping_agent,
    executor=user_proxy,
    name="kya_verify",
    description="Verify a purchase through KYA security gate",
)

register_function(
    kya_issue_token,
    caller=admin_agent,
    executor=user_proxy,
    name="kya_issue_token",
    description="Issue a delegation token for an agent",
)

register_function(
    kya_step_up,
    caller=admin_agent,
    executor=user_proxy,
    name="kya_step_up",
    description="Confirm or decline a step-up challenge",
)

# Start the conversation
user_proxy.initiate_chat(
    shopping_agent,
    message=(
        "I need to buy office supplies: 10 reams of paper (₹250 each) and "
        "5 packs of pens (₹120 each). My agent ID is agent_procure_bot_042. "
        "Issue a delegation token and verify the purchase through KYA."
    ),
)
```

---

## Webhook Handling

When using Razorpay, KYA receives webhook events at `POST /webhooks/razorpay` (or `POST /razorpay-webhook`).

### Webhook Event Flow

```
Razorpay → POST /razorpay-webhook
  → HMAC-SHA256 signature verification (X-Razorpay-Signature)
  → Event parsing
  → Idempotency check (deduplication)
  → KYA execution state mapping
  → Audit record update
```

### Supported Events

| Razorpay Event | KYA State |
|---|---|
| `order.created` | `PAYMENT_CREATED` |
| `order.paid` | `EXECUTED` |
| `payment.authorized` | `PAYMENT_CREATED` |
| `payment.captured` | `EXECUTED` |
| `payment.failed` | `PAYMENT_FAILED` |
| `payment.refunded` | `PAYMENT_FAILED` |

### Webhook Signature Verification

```python
import hmac
import hashlib

def verify_razorpay_webhook(raw_body: bytes, signature: str, secret: str) -> bool:
    """Verify Razorpay webhook signature."""
    expected = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
```

---

## Compliance & Audit

### Export Audit Trail

```python
import requests
import json
import csv
from datetime import datetime

def export_audit_trail(api_url: str, demo_key: str, format: str = "json"):
    """Export full KYA audit trail."""
    headers = {"X-Kya-Demo-Key": demo_key}
    resp = requests.get(f"{api_url}/audit", headers=headers)
    entries = resp.json()

    if format == "json":
        filename = f"kya_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w") as f:
            json.dump(entries, f, indent=2, default=str)
        return filename

    elif format == "csv":
        filename = f"kya_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "audit_id", "timestamp", "agent_id", "agent_name",
                "stated_intent", "total_amount", "decision", "risk_score",
                "identity_ok", "delegation_ok", "scope_ok",
                "intent_mismatch", "execution_state",
            ])
            for entry in entries:
                risk = entry.get("risk", {})
                writer.writerow([
                    entry.get("audit_id"),
                    entry.get("timestamp"),
                    entry.get("agent_id"),
                    entry.get("agent_name"),
                    entry.get("stated_intent"),
                    entry.get("total_amount"),
                    entry.get("decision"),
                    risk.get("total_score"),
                    entry.get("identity_ok"),
                    entry.get("delegation_ok"),
                    entry.get("scope_ok"),
                    entry.get("intent_result", {}).get("mismatch_severity"),
                    entry.get("execution_state"),
                ])
        return filename


# Usage
export_audit_trail("http://localhost:8000", "your-demo-key", format="json")
export_audit_trail("http://localhost:8000", "your-demo-key", format="csv")
```

### Cryptographic Compliance Certificate

```python
import hashlib
import json

def generate_compliance_certificate(audit_entry: dict) -> dict:
    """Generate a cryptographic compliance certificate for an audit entry.

    The certificate includes a SHA-256 fingerprint of the audit data,
    creating a tamper-evident record for regulatory compliance.
    """
    # Canonicalize the audit entry
    canonical = json.dumps(audit_entry, sort_keys=True, default=str)
    fingerprint = hashlib.sha256(canonical.encode()).hexdigest()

    return {
        "certificate_version": "1.0",
        "platform": "KYA - Know Your Agent",
        "audit_id": audit_entry.get("audit_id"),
        "timestamp": audit_entry.get("timestamp"),
        "agent_id": audit_entry.get("agent_id"),
        "decision": audit_entry.get("decision"),
        "total_amount": audit_entry.get("total_amount"),
        "risk_score": audit_entry.get("risk", {}).get("total_score"),
        "execution_state": audit_entry.get("execution_state"),
        "verification_checks": {
            "identity_verified": audit_entry.get("identity_ok", False),
            "delegation_valid": audit_entry.get("delegation_ok", False),
            "scope_compliant": audit_entry.get("scope_ok", False),
            "intent_matched": audit_entry.get("intent_result", {}).get("mismatch_severity") == "none",
        },
        "cryptographic_fingerprint": f"sha256:{fingerprint}",
        "fingerprint_algorithm": "SHA-256",
    }
```

---

## Security Best Practices

1. **Never expose demo keys in client-side code.** The `X-Kya-Demo-Key` must be kept server-side.

2. **Always verify webhook signatures.** KYA rejects webhooks with invalid HMAC-SHA256 signatures.

3. **Delegation tokens are single-use.** Each token can only execute one transaction. Once used, it's consumed.

4. **Use STEP_UP for high-risk transactions.** When KYA returns STEP_UP, always route through human confirmation.

5. **Monitor the audit trail.** Use `/audit` and `/metrics` endpoints to detect anomalies.

6. **Set owner limits.** Use the owner control panel to set per-agent spending ceilings.

7. **Enable reconciliation.** The `/reconcile/{audit_id}` endpoint helps resolve payment state mismatches.

8. **Rotate signing secrets.** In production, use `KYA_IDENTITY_MODE=ed25519` for asymmetric key pairs.

---

## Quick Start

```bash
# 1. Clone and start the KYA backend
cd kya/backend
export KYA_DEMO_ISSUER_KEY="my-secret-key"
export KYA_SIGNING_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
python -m uvicorn main:app --reload --port 8000

# 2. Issue a token
curl -X POST http://localhost:8000/issue-token \
  -H "Content-Type: application/json" \
  -H "X-Kya-Demo-Key: my-secret-key" \
  -d '{"agent_id":"agent_procure_bot_042","human_id":"user_1","max_amount":5000,"categories":["groceries"]}'

# 3. Verify a purchase
curl -X POST http://localhost:8000/verify \
  -H "Content-Type: application/json" \
  -H "X-Kya-Demo-Key: my-secret-key" \
  -d '{"agent_id":"agent_procure_bot_042","delegation_token":"<token>","stated_intent":"buy groceries","cart":[{"item":"Rice","category":"groceries","amount":450}]}'

# 4. Check audit trail
curl http://localhost:8000/audit -H "X-Kya-Demo-Key: my-secret-key"
```

---

*Generated by KYA Platform — Know Your Agent*
*For more information, see the [Architecture Documentation](ARCHITECTURE.md)*
