"""
KYA -- Know Your Agent
Cross-transaction identity, delegation, intent and risk verification
layer for AI-agent-initiated payments on Razorpay.

Pipeline:
  Incoming agent purchase request
        -> Identity check         (is this a registered/verified agent?)
        -> Delegation check       (signed, scoped, unexpired human mandate?)
        -> Scope + limit check    (category and amount within the mandate?)
        -> Intent-match check     (does the cart match the stated intent?)
        -> Risk scoring           (behavioral drift + all of the above)
        -> Decision               (APPROVE / STEP_UP / BLOCK)
        -> Razorpay test order    (only if approved -- exactly once, ever,
                                    per delegation token; see replay/
                                    idempotency notes below)
        -> Audit trail            (always, regardless of outcome)

Changes from the original version, each tied to a specific issue
found in review:

  * The identity->decision chain now lives in pipeline.py and is
    imported here, instead of being duplicated inline. eval/harness.py
    imports the same module, so "what the offline eval measured" and
    "what a live request experiences" can no longer silently diverge.
  * /issue-token now requires a demo bearer key (KYA_DEMO_ISSUER_KEY).
    It's still not a real human-authorization service -- see the
    docstring on issue_token() -- but an agent (or anyone who can
    reach the API) can no longer mint its own spending authority
    with zero credentials, which is what the original endpoint let
    happen.
  * CORS is restricted to an explicit allow-list instead of "*".
  * A delegation token can now only ever be *executed* once. Verifying
    it (a client checking risk before committing) doesn't consume it;
    creating a Razorpay order does, via registry.reserve_token() --
    an atomic check-and-set, not a separate check-then-mark, so two
    concurrent requests for the same token can't both slip through
    and both create an order.
  * /step-up/confirm uses audit.update()'s atomic status transition
    instead of get-then-append, so a STEP_UP audit record can't be
    confirmed twice. It also claims that transition (STEP_UP ->
    CONFIRMING) *before* touching reserve_token() or the payment
    call at all, so a second concurrent confirm for the same
    audit_id is rejected immediately instead of being able to
    overwrite the winning request's outcome out from under it after
    a real payment has already been created (see confirm_step_up()'s
    docstring for the exact race this closes).
"""

import collections
import hmac
import logging
import math
import os
import time
import uuid

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional

# --- Configurable logging level ---
# Set KYA_LOG_LEVEL to DEBUG, INFO, WARNING, ERROR (default: INFO)
LOG_LEVEL = os.environ.get("KYA_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("kya")

from registry import issue_delegation_token, reserve_token, release_token, finalize_execution, write_outbox_entry, replay_pending_finalizations, get_pending_outbox_count, recover_orphaned_reservations, record_reconciliation_attempt, get_reconciliation_log, get_reconciliation_attempts_count
from pipeline import run_pipeline
from razorpay_mock import create_test_order as _mock_create_test_order, MockPaymentProvider
from payment_provider import PaymentProvider

# --- Payment Provider Selection ---
# KYA_PAYMENT_PROVIDER=mock (default) — deterministic mock for testing
# KYA_PAYMENT_PROVIDER=razorpay — real Razorpay API (requires credentials)
PAYMENT_PROVIDER_MODE = os.environ.get("KYA_PAYMENT_PROVIDER", "mock").lower()

def _get_payment_provider() -> PaymentProvider:
    """Factory: return the configured payment provider.
    
    mock:     MockPaymentProvider (default, no credentials needed)
    razorpay: RazorpayProvider (requires RAZORPAY_KEY_ID + KEY_SECRET)
    """
    if PAYMENT_PROVIDER_MODE == "razorpay":
        key_id = os.environ.get("RAZORPAY_KEY_ID")
        key_secret = os.environ.get("RAZORPAY_KEY_SECRET")
        if not key_id or not key_secret:
            raise RuntimeError(
                "KYA_PAYMENT_PROVIDER=razorpay but RAZORPAY_KEY_ID and/or "
                "RAZORPAY_KEY_SECRET are not set. "
                "Set KYA_PAYMENT_PROVIDER=mock to use the mock provider."
            )
        try:
            from razorpay_provider import RazorpayProvider
            return RazorpayProvider()
        except ImportError:
            raise RuntimeError(
                "The 'razorpay' package is required for RazorpayProvider. "
                "Install with: pip install razorpay"
            )
    elif PAYMENT_PROVIDER_MODE == "mock":
        return MockPaymentProvider()
    else:
        raise RuntimeError(
            f"Unknown KYA_PAYMENT_PROVIDER: {PAYMENT_PROVIDER_MODE}. "
            "Valid values: mock, razorpay"
        )

_payment_provider = _get_payment_provider()
import audit as audit_store
import security_log
import baseline

# --- Input validation constants ---
KNOWN_CATEGORIES = {"groceries", "electronics", "office_supplies"}
MAX_CART_SIZE = 50
MAX_CART_ITEM_AMOUNT = 1_000_000  # per-item, in INR
MAX_DELEGATION_AMOUNT = 1_000_000  # per-token, in INR

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app):
    """Startup: replay pending outbox entries and recover crash states."""
    try:
        # Pass 1: Outbox replay (finalize known-good payments)
        replayed = replay_pending_finalizations(finalize_execution)
        if replayed > 0:
            print(f"[KYA] Outbox replay: finalized {replayed} pending transaction(s)")

        # Pass 2: Orphaned reservation recovery (Phase 1G-A)
        recovery = recover_orphaned_reservations(
            audit_store.find_audit_by_jti,
            audit_store.update_execution_state,
        )
        if recovery["released"] > 0:
            print(f"[KYA] Recovery: released {recovery['released']} failed-payment reservation(s)")
        if recovery["flagged_payment_unknown"] > 0:
            print(f"[KYA] Recovery: flagged {recovery['flagged_payment_unknown']} PAYMENT_UNKNOWN (requires reconciliation)")
        if recovery["orphaned"] > 0:
            print(f"[KYA] Recovery: {recovery['orphaned']} orphaned reservation(s) (requires admin cleanup)")
    except Exception as e:
        print(f"[KYA] Startup recovery failed: {e}")
    yield

app = FastAPI(title="KYA -- Know Your Agent", version="0.2.0", lifespan=lifespan)

# --- Security Headers ---
# Applied to every response via middleware below.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """Attach a unique request ID to every request for distributed tracing.
    Uses client-provided X-Request-ID if present (for end-to-end tracing
    across services), otherwise generates one."""
    request_id = request.headers.get("x-request-id", uuid.uuid4().hex[:16])
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Inject security headers into every response."""
    response = await call_next(request)
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response


@app.middleware("http")
async def request_timing_middleware(request: Request, call_next):
    """Log request duration for latency monitoring and metrics."""
    start = time.monotonic()
    response = await call_next(request)
    duration_ms = (time.monotonic() - start) * 1000
    response.headers["X-Response-Time"] = f"{duration_ms:.1f}ms"
    # Record metrics
    _metrics.request_latency.observe(duration_ms / 1000.0)
    _metrics.requests_total.inc()
    # Log slow requests (>100ms) at warning level
    if duration_ms > 100:
        logger.warning(f"Slow request: {request.method} {request.url.path} took {duration_ms:.1f}ms")
    return response


# --- Rate Limiting ---
# Sliding-window per-IP rate limiter. Uses the provider-neutral
# rate_limiter module. In-memory by default — swap to RedisRateLimiter
# for multi-worker deployments.
#
# Limits are per-endpoint per-IP per 60-second window.
RATE_LIMITS = {
    "/issue-token": 10,
    "/verify": 100,
    "/step-up/confirm": 20,
    "/agents": 60,
    "/audit": 60,
}
from rate_limiter import LocalRateLimiter
from metrics import get_metrics
from policy_engine import get_policy_engine
from reliability import get_payment_circuit_breaker
from trace import get_recent_traces, get_trace_stats, record_trace
_rate_limiter = LocalRateLimiter()
_metrics = get_metrics()
_policy_engine = get_policy_engine()
_payment_breaker = get_payment_circuit_breaker()

MAX_REQUEST_BYTES = 1_048_576  # 1 MB


def _get_client_ip(request: Request) -> str:
    """Extract client IP, respecting X-Forwarded-For for proxied setups."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.middleware("http")
async def rate_limit_and_body_size_middleware(request: Request, call_next):
    """Enforce per-IP rate limits and request body size."""
    client_ip = _get_client_ip(request)
    path = request.url.path

    # Request body size check (only for POST/PUT/PATCH)
    if request.method in ("POST", "PUT", "PATCH"):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_REQUEST_BYTES:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body too large"},
            )    # Rate limit check
    limit = RATE_LIMITS.get(path)
    if limit is not None:
        key = f"{client_ip}:{path}"
        result = _rate_limiter.check_and_increment(key, limit, window_seconds=60)
        if not result["allowed"]:
            req_id = getattr(request.state, 'request_id', None)
            security_log.log_rate_limit(client_ip, path, limit, request_id=req_id)
            _metrics.record_rate_limit()
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded", "retry_after_seconds": result["retry_after"]},
                headers={"Retry-After": str(result["retry_after"])},
            )

    response = await call_next(request)
    return response

# Restrict to known frontend origins instead of "*". Override via env
# var for local dev on a different port; never fall back to "*".
_default_origins = "http://localhost:3000,http://localhost:5173,http://127.0.0.1:5500"
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("KYA_ALLOWED_ORIGINS", _default_origins).split(",") if o.strip()]
# Always allow the Firebase frontend and the backend itself
for extra in ["https://kya-frontend.web.app", "https://kya-backend.onrender.com"]:
    if extra not in ALLOWED_ORIGINS:
        ALLOWED_ORIGINS.append(extra)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Kya-Demo-Key"],
)

# Reject wildcard CORS origins at startup -- fail-closed so a
# misconfigured env var can't silently open the API.
if "*" in ALLOWED_ORIGINS:
    raise RuntimeError(
        "KYA_ALLOWED_ORIGINS must not contain '*' -- "
        "wildcard CORS origins are not allowed."
    )

# DEMO-ONLY shared secret gating who may mint a delegation token.
# This is NOT a real authorization model -- see issue_token() below.
#
# CRITICAL: This key gates who may create delegation tokens (spending
# authority). In production this must be replaced with real human
# authentication. Do not embed this key in client-side code.
_demo_issuer_key_raw = os.environ.get("KYA_DEMO_ISSUER_KEY")
if not _demo_issuer_key_raw:
    raise RuntimeError(
        "KYA_DEMO_ISSUER_KEY environment variable is not set. "
        "This gates who may mint delegation tokens. "
        "Set it to any random string before starting the server."
    )
DEMO_ISSUER_KEY = _demo_issuer_key_raw

# --- Agent fields safe for public display ---
# baseline_mean_amount, baseline_std_amount, baseline_txn_count, and
# certificate_fingerprint are internal operational data that must not
# be exposed to unauthenticated callers (baseline data enables
# precision drift attacks; fingerprint is infrastructure detail).
_AGENT_PUBLIC_FIELDS = {"agent_id", "name", "issuer", "verified", "category_scope"}


def _require_demo_key(x_kya_demo_key: Optional[str], request: Optional[Request] = None) -> None:
    """Gate an endpoint behind the demo issuer key using constant-time
    comparison. Raises HTTP 401 if the key is missing or wrong.

    Uses hmac.compare_digest to prevent timing side-channel attacks
    that could leak the key one character at a time via response-time
    measurement.
    """
    if not hmac.compare_digest(x_kya_demo_key or "", DEMO_ISSUER_KEY):
        client_ip = request.client.host if request and request.client else "unknown"
        req_id = getattr(request.state, 'request_id', None)
        security_log.log_auth_failure(client_ip, "demo_key_check", request_id=req_id)
        _metrics.record_auth_failure()
        raise HTTPException(status_code=401, detail="Missing/invalid demo key")


class CartItem(BaseModel):
    item: str = Field(min_length=1, max_length=256)
    category: str
    amount: float

    @field_validator("amount")
    @classmethod
    def validate_amount(cls, v):
        if math.isnan(v) or math.isinf(v):
            raise ValueError("amount must be a finite number")
        if v <= 0:
            raise ValueError("amount must be greater than zero")
        if v > MAX_CART_ITEM_AMOUNT:
            raise ValueError(f"amount must not exceed {MAX_CART_ITEM_AMOUNT}")
        return v

    @field_validator("category")
    @classmethod
    def validate_category(cls, v):
        if v not in KNOWN_CATEGORIES:
            raise ValueError(f"category must be one of {sorted(KNOWN_CATEGORIES)}")
        return v


class PurchaseRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    delegation_token: str = Field(min_length=1)
    stated_intent: str = Field(min_length=1, max_length=1000)
    cart: List[CartItem] = Field(min_length=1, max_length=MAX_CART_SIZE)


class StepUpConfirm(BaseModel):
    audit_id: str
    human_confirmed: bool


class IssueTokenRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    human_id: str = Field(min_length=1, max_length=128)
    max_amount: float
    categories: List[str]

    @field_validator("max_amount")
    @classmethod
    def validate_max_amount(cls, v):
        if math.isnan(v) or math.isinf(v):
            raise ValueError("max_amount must be a finite number")
        if v <= 0:
            raise ValueError("max_amount must be greater than zero")
        if v > MAX_DELEGATION_AMOUNT:
            raise ValueError(f"max_amount must not exceed {MAX_DELEGATION_AMOUNT}")
        return v

    @field_validator("categories")
    @classmethod
    def validate_categories(cls, v):
        if not v:
            raise ValueError("categories must not be empty")
        for cat in v:
            if not cat:
                raise ValueError("each category must be non-empty")
            if cat not in KNOWN_CATEGORIES:
                raise ValueError(f"category '{cat}' is not a known category; must be one of {sorted(KNOWN_CATEGORIES)}")
        return list(set(v))  # deduplicate while preserving first occurrence


@app.get("/health")
def health_check():
    """Health check endpoint for load balancers and monitoring.
    Reports pending outbox entries and reconciliation state."""
    pending_outbox = get_pending_outbox_count()
    pending_recon = audit_store.get_pending_reconciliation_count()
    total_pending = pending_outbox + pending_recon
    return {
        "status": "healthy" if total_pending == 0 else "degraded",
        "pending_finalizations": pending_outbox,
        "pending_reconciliations": pending_recon,
        "version": app.version,
    }


class UpdateAgentLimitRequest(BaseModel):
    owner_max_amount: float

    @field_validator("owner_max_amount")
    @classmethod
    def validate_owner_max_amount(cls, v):
        if math.isnan(v) or math.isinf(v):
            raise ValueError("owner_max_amount must be a finite number")
        if v <= 0:
            raise ValueError("owner_max_amount must be greater than zero")
        return v


@app.get("/agents")
def list_agents(request: Request, x_kya_demo_key: Optional[str] = Header(default=None)):
    """Returns the agent registry. Requires demo key authentication.

    Sensitive internal fields (baseline amounts, certificate
    fingerprints) are stripped — they are not needed by the frontend
    and their exposure would enable precision drift attacks.
    """
    _require_demo_key(x_kya_demo_key, request)
    from registry import load_registry
    registry = load_registry()
    return {
        agent_id: {k: v for k, v in agent.items() if k in _AGENT_PUBLIC_FIELDS}
        for agent_id, agent in registry.items()
    }


@app.put("/agents/{agent_id}/limit")
def update_agent_limit_route(
    agent_id: str,
    req: UpdateAgentLimitRequest,
    request: Request,
    x_kya_demo_key: Optional[str] = Header(default=None)
):
    """Update human owner's hard per-transaction limit for an agent.
    Requires demo key authentication (X-Kya-Demo-Key).
    """
    _require_demo_key(x_kya_demo_key, request)
    from registry import update_agent_limit
    agent = update_agent_limit(agent_id, req.owner_max_amount)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    return {
        "status": "success",
        "agent_id": agent_id,
        "owner_max_amount": agent["owner_max_amount"]
    }


@app.post("/issue-token")
def issue_token(request: Request, req: IssueTokenRequest, x_kya_demo_key: Optional[str] = Header(default=None)):
    """DEMO-ONLY mandate issuer -- NOT exposed like this in production.

    Real delegation issuance must happen through a human-authenticated
    flow: human logs into an authorization UI/app, reviews exactly
    what they're granting (agent, categories, limit, expiry), and a
    mandate service -- not the agent, and not this open endpoint --
    signs the credential. An agent can exercise authority; it must
    never be able to mint authority for itself.

    This endpoint keeps that architecture honest by, at minimum, not
    being callable by an unauthenticated caller: it now requires a
    shared demo key out-of-band from the request body. That's still
    just a shared secret, not real human authorization -- it exists
    so the endpoint can't be described as anything more than what it
    is: a MOCK ISSUER, gated for demo purposes only.
    """
    _require_demo_key(x_kya_demo_key, request)
    token = issue_delegation_token(req.agent_id, req.human_id, req.max_amount, req.categories)
    return {"delegation_token": token}


@app.post("/verify")
def verify_purchase(request: Request, req: PurchaseRequest, x_kya_demo_key: Optional[str] = Header(default=None)):
    _require_demo_key(x_kya_demo_key, request)
    request_id = getattr(request.state, 'request_id', None)
    # .model_dump() is the Pydantic v2 method (.dict() is deprecated
    # there but still works, just emits a warning); .dict() is what
    # v1 actually has. Since nothing in this repo pins a Pydantic
    # major version, use whichever the installed version actually
    # supports instead of assuming v2 and breaking on v1.
    cart_dicts = [
        item.model_dump() if hasattr(item, "model_dump") else item.dict()
        for item in req.cart
    ]

    result = run_pipeline(
        agent_id=req.agent_id,
        delegation_token=req.delegation_token,
        stated_intent=req.stated_intent,
        cart=cart_dicts,
    )

    # Policy engine evaluation (Phase 10 integration)
    # Evaluates per-agent rules AFTER pipeline but BEFORE payment.
    # Policy can override the pipeline's decision.
    primary_category = cart_dicts[0]["category"] if cart_dicts else "unknown"
    policy_result = _policy_engine.evaluate(
        agent_id=req.agent_id,
        category=primary_category,
        amount=result["total_amount"],
    )
    # Apply policy override if it has a stricter decision
    if policy_result["decision"] != "APPROVE" and result["decision"] == "APPROVE":
        result["decision"] = policy_result["decision"]
        result["reasons"].extend([v["message"] for v in policy_result["violations"]])
        result["policy_violations"] = policy_result["violations"]
    else:
        result["policy_violations"] = []

    payment = None
    executed = False
    jti = result.get("jti")

    if result["decision"] == "APPROVE":
        # Phase 1G-A: Create durable execution/audit record BEFORE
        # the external payment call. This ensures an audit trail exists
        # even if we crash during or after the payment call.
        execution_id = f"exec_{uuid.uuid4().hex[:12]}"

        if reserve_token(jti):
            # Record audit with EXECUTION_PENDING before calling provider
            audit_entry = {
                "agent_id": req.agent_id,
                "agent_name": result["agent"]["name"] if result["agent"] else "UNKNOWN / UNREGISTERED",
                "stated_intent": req.stated_intent,
                "cart": cart_dicts,
                "total_amount": result["total_amount"],
                "identity_ok": result["identity_ok"],
                "delegation_ok": result["delegation_ok"],
                "delegation_reason": result["delegation_reason"],
                "jti": jti,
                "scope_ok": result["scope_ok"],
                "within_delegated_limit": result["within_delegated_limit"],
                "intent_result": result["intent_result"],
                "risk": result["risk"],
                "decision": "APPROVE",
                "reasons": result["reasons"],
                "payment": None,
                "executed": False,
                "step_up_confirmed": None,
                "execution_state": "EXECUTION_PENDING",
                "execution_id": execution_id,
                "baseline_poisoning": result.get("baseline_poisoning"),
                "request_id": request_id,
            }
            # Log if baseline poisoning detected
            if result.get("baseline_poisoning"):
                log_security_event("baseline_poisoning_detected", {
                    "agent_id": req.agent_id,
                    "poisoning_info": result["baseline_poisoning"],
                    "request_id": request_id,
                }, client_ip=client_ip)

            audit_id = audit_store.record(audit_entry)

            try:
                if not _payment_breaker.allow_request():
                    raise Exception("Circuit breaker open — payment service unavailable")
                exec_id = f"exec_{uuid.uuid4().hex[:12]}"
                order_result = _payment_provider.create_order(
                    amount=result["total_amount"],
                    currency="INR",
                    receipt=exec_id[:40],  # Razorpay max receipt length
                    notes={"initiated_by_agent": req.agent_id, "mode": PAYMENT_PROVIDER_MODE},
                )
                if not order_result.success:
                    raise Exception(order_result.error or "Order creation failed")
                payment = {
                    "razorpay_order_id": order_result.order_id,
                    "amount": order_result.amount,
                    "currency": order_result.currency,
                    "status": order_result.status,
                    "notes": order_result.notes,
                    "created_at": order_result.created_at,
                    "execution_id": exec_id,
                }
                _payment_breaker.record_success()
            except Exception:
                _payment_breaker.record_failure()
                # Explicit payment failure: mark PAYMENT_FAILED, release token
                audit_store.update_execution_state(audit_id, "PAYMENT_FAILED")
                audit_store.update(audit_id, "APPROVE", {
                    "decision": "BLOCK",
                    "reasons": ["Payment order creation failed -- please retry"],
                    "executed": False,
                })
                release_token(jti)
                result["decision"] = "BLOCK"
                result["reasons"] = ["Payment order creation failed -- please retry"]
                payment = None
            else:
                # Payment succeeded: write outbox IMMEDIATELY,
                # then update audit, then finalize.
                # The outbox proves the payment was created.
                write_outbox_entry(
                    jti, audit_id,
                    payment_id=payment.get("razorpay_order_id"),
                    execution_id=execution_id,
                    agent_id=req.agent_id,
                    amount=result["total_amount"],
                )
                audit_store.update_execution_state(audit_id, "PAYMENT_CREATED")
                audit_store.update(audit_id, "APPROVE", {
                    "payment": payment,
        "policy_violations": result.get("policy_violations"),
                    "executed": True,
                })
                finalize_execution(jti, audit_id, payment.get("razorpay_order_id"))
                audit_store.update_execution_state(audit_id, "EXECUTED")
                executed = True
                # Update rolling baseline so risk scorer learns from this transaction
                baseline.record_transaction(req.agent_id, result["total_amount"])
        else:
            # Token already used -- replay detected
            result["decision"] = "BLOCK"
            result["reasons"] = ["Delegation token already used for a prior transaction -- replay detected"]
            audit_entry = {
                "agent_id": req.agent_id,
                "agent_name": result["agent"]["name"] if result["agent"] else "UNKNOWN / UNREGISTERED",
                "stated_intent": req.stated_intent,
                "cart": cart_dicts,
                "total_amount": result["total_amount"],
                "identity_ok": result["identity_ok"],
                "delegation_ok": result["delegation_ok"],
                "delegation_reason": result["delegation_reason"],
                "jti": jti,
                "scope_ok": result["scope_ok"],
                "within_delegated_limit": result["within_delegated_limit"],
                "intent_result": result["intent_result"],
                "risk": result["risk"],
                "decision": result["decision"],
                "reasons": result["reasons"],
                "payment": None,
                "executed": False,
                "step_up_confirmed": None,
            }
            audit_id = audit_store.record(audit_entry)
    else:
        # BLOCK or STEP_UP: no execution, record audit as before
        audit_entry = {
            "agent_id": req.agent_id,
            "agent_name": result["agent"]["name"] if result["agent"] else "UNKNOWN / UNREGISTERED",
            "stated_intent": req.stated_intent,
            "cart": cart_dicts,
            "total_amount": result["total_amount"],
            "identity_ok": result["identity_ok"],
            "delegation_ok": result["delegation_ok"],
            "delegation_reason": result["delegation_reason"],
            "jti": jti,
            "scope_ok": result["scope_ok"],
            "within_delegated_limit": result["within_delegated_limit"],
            "intent_result": result["intent_result"],
            "risk": result["risk"],
            "decision": result["decision"],
            "reasons": result["reasons"],
            "payment": None,
            "executed": False,
            "step_up_confirmed": None,
            "request_id": request_id,
        }
        audit_id = audit_store.record(audit_entry)
        try:
            record_trace(audit_entry)
        except Exception:
            pass

    security_log.log_payment_decision(
        agent_id=req.agent_id,
        decision=result["decision"],
        total_amount=result["total_amount"],
        risk_score=result["risk"]["total_score"],
        audit_id=audit_id,
        request_id=request_id,
    )

    # Record decision metrics
    _metrics.requests_by_decision[result["decision"]].inc()
    if result.get("baseline_poisoning"):
        _metrics.record_baseline_poisoning()
    if result["decision"] in ("BLOCK", "STEP_UP") and not result.get("identity_ok", True):
        pass  # auth failure already recorded
    if not result.get("delegation_ok", True):
        _metrics.record_replay_attempt() if "replay" in str(result.get("delegation_reason", "")).lower() else None

    return {
        "audit_id": audit_id,
        "decision": result["decision"],
        "reasons": result["reasons"],
        "risk": result["risk"],
        "intent_result": result["intent_result"],
        "payment": payment,
        "policy_violations": result.get("policy_violations"),
    }


@app.post("/step-up/confirm")
def confirm_step_up(request: Request, body: StepUpConfirm, x_kya_demo_key: Optional[str] = Header(default=None)):
    request_id = getattr(request.state, 'request_id', None)
    """Simulates the human confirming a step-up challenge (e.g. an
    OTP/push notification) for a transaction that KYA flagged as
    needing human sign-off rather than an outright block.

    Uses audit.update()'s atomic expected-status transition: the
    original entry's "decision" field is changed on disk from
    STEP_UP to a terminal state as part of the same operation that
    checks it's still STEP_UP. A second confirmation attempt against
    the same audit_id will find the entry no longer in STEP_UP state
    and be rejected -- previously the original entry was left at
    "STEP_UP" forever (only a new, separate audit row was appended),
    so the same audit_id could be replayed indefinitely to create
    additional orders.

    Ownership claim, closing a second race on top of that: the first
    thing this handler does -- before touching reserve_token() or
    create_test_order() at all -- is atomically flip the audit record
    from STEP_UP to CONFIRMING. Only the caller that wins that flip
    is allowed to decide this audit_id's outcome; every other
    concurrent call for the same audit_id (including a second
    /step-up/confirm firing for the same request, e.g. a client
    double-submit or retry) is rejected immediately, before it can
    reserve the token, call the payment mock, or write anything else.

    Without this, two concurrent confirms for the same audit_id could
    both pass the STEP_UP check, race reserve_token() (only one wins,
    correctly), and then the *loser* -- having lost the reservation --
    would immediately mark the audit record BLOCK, while the *winner*
    is still awaiting create_test_order(). The winner's order still
    gets created (a real payment happens), but its own final
    audit.update() call then loses to the loser's earlier BLOCK write
    and fails, and finalize_execution() (only called when that update
    succeeds) never runs -- so the transaction is left with: a
    completed payment, an audit trail reading "BLOCK", and a token
    reservation permanently stuck at RESERVED (never EXECUTED, never
    released). Claiming ownership up front means the loser in that
    scenario is rejected before it ever gets to write BLOCK, and the
    winner's later updates always have CONFIRMING (its own claim) to
    transition from, not a status some other request could have
    changed underneath it.
    """
    _require_demo_key(x_kya_demo_key, request)

    claimed = audit_store.update(body.audit_id, "STEP_UP", {"decision": "CONFIRMING"})
    if not claimed:
        entry = audit_store.get_one(body.audit_id)
        if entry is None:
            raise HTTPException(status_code=404, detail="Audit entry not found")
        if entry.get("decision") == "CONFIRMING":
            raise HTTPException(status_code=409, detail="Step-up confirmation already in progress")
        raise HTTPException(status_code=409, detail="Transaction is not in STEP_UP state")

    entry = audit_store.get_one(body.audit_id)

    if body.human_confirmed:
        jti = entry.get("jti")
        execution_id = f"exec_{uuid.uuid4().hex[:12]}"

        # Reserve second, now that this request exclusively owns the
        # audit record's outcome: reserve_token() is still the atomic
        # gate for the *token* (a jti can be shared across more than
        # one audit entry -- e.g. retried /verify calls -- so a
        # concurrent execution elsewhere can legitimately still lose
        # this race even after winning the CONFIRMING claim above).
        if jti and not reserve_token(jti):
            audit_store.update(body.audit_id, "CONFIRMING", {
                "decision": "BLOCK (step-up declined -- token already used)",
                "step_up_confirmed": False,
            })
            return {"decision": "BLOCK (step-up declined -- token already used)", "payment": None}

        # Phase 1G-A: Mark execution pending before payment call
        audit_store.update_execution_state(body.audit_id, "EXECUTION_PENDING")

        try:
            if not _payment_breaker.allow_request():
                raise Exception("Circuit breaker open — payment service unavailable")
            stepup_exec_id = f"exec_{uuid.uuid4().hex[:12]}"
            order_result = _payment_provider.create_order(
                amount=entry["total_amount"],
                currency="INR",
                receipt=stepup_exec_id[:40],
                notes={"initiated_by_agent": entry["agent_id"], "mode": PAYMENT_PROVIDER_MODE},
            )
            if not order_result.success:
                raise Exception(order_result.error or "Order creation failed")
            payment = {
                "razorpay_order_id": order_result.order_id,
                "amount": order_result.amount,
                "currency": order_result.currency,
                "status": order_result.status,
                "notes": order_result.notes,
                "created_at": order_result.created_at,
                "execution_id": stepup_exec_id,
            }
            _payment_breaker.record_success()
        except Exception:
            _payment_breaker.record_failure()
            # Explicit payment failure: mark PAYMENT_FAILED, release token
            audit_store.update_execution_state(body.audit_id, "PAYMENT_FAILED")
            audit_store.update(body.audit_id, "CONFIRMING", {
                "decision": "BLOCK (payment order creation failed -- please retry)",
                "step_up_confirmed": False,
            })
            if jti:
                release_token(jti)
            return {"decision": "BLOCK (payment order creation failed -- please retry)", "payment": None}

        # Payment succeeded: write outbox IMMEDIATELY
        if jti:
            write_outbox_entry(
                jti, body.audit_id,
                payment_id=payment.get("razorpay_order_id"),
                execution_id=execution_id,
                agent_id=entry["agent_id"],
                amount=entry["total_amount"],
            )
        audit_store.update_execution_state(body.audit_id, "PAYMENT_CREATED")

        # This update can no longer lose a race: nothing else could
        # have moved the record off CONFIRMING, since only this
        # request ever won that claim.
        audit_store.update(body.audit_id, "CONFIRMING", {
            "decision": "APPROVE (after step-up)",
            "step_up_confirmed": True,
            "payment": payment,
            "executed": True,
        })
        if jti:
            finalize_execution(jti, body.audit_id, payment.get("razorpay_order_id"))
        audit_store.update_execution_state(body.audit_id, "EXECUTED")
        # Update rolling baseline so risk scorer learns from this transaction
        baseline.record_transaction(entry["agent_id"], entry["total_amount"])
        security_log.log_step_up_confirm(body.audit_id, "approved", request_id=request_id)
        return {"decision": "APPROVE (after step-up)", "payment": payment}
    else:
        audit_store.update(body.audit_id, "CONFIRMING", {
            "decision": "BLOCK (step-up declined by human)",
            "step_up_confirmed": False,
        })
        security_log.log_step_up_confirm(body.audit_id, "declined", request_id=request_id)
        return {"decision": "BLOCK (step-up declined by human)", "payment": None}


@app.get("/audit")
def list_audit(request: Request, x_kya_demo_key: Optional[str] = Header(default=None)):
    _require_demo_key(x_kya_demo_key, request)
    return audit_store.get_all()


@app.get("/reconcile/{audit_id}")
def get_reconciliation_status(request: Request, audit_id: str, x_kya_demo_key: Optional[str] = Header(default=None)):
    """View reconciliation state for an audit entry.

    Shows execution_state, provider states, and reconciliation history.
    Read-only — does not trigger reconciliation.
    """
    _require_demo_key(x_kya_demo_key, request)
    entry = audit_store.get_one(audit_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Audit entry not found")
    log = get_reconciliation_log(audit_id)
    attempts = get_reconciliation_attempts_count(audit_id)
    return {
        "audit_id": audit_id,
        "execution_id": entry.get("execution_id"),
        "execution_state": entry.get("execution_state"),
        "decision": entry.get("decision"),
        "jti": entry.get("jti"),
        "agent_id": entry.get("agent_id"),
        "total_amount": entry.get("total_amount"),
        "reconciliation_attempts": attempts,
        "reconciliation_log": log,
    }


@app.post("/reconcile/{audit_id}/resolve")
def resolve_reconciliation(request: Request, audit_id: str, body: dict, x_kya_demo_key: Optional[str] = Header(default=None)):
    """Manually resolve a reconciliation.

    Admin endpoint for cases where automatic reconciliation cannot
    determine the provider state.

    body: {"resolution": "RELEASE_TOKEN" | "FINALIZE_WITH_ORDER", "order_id": "...", "reason": "..."}
    """
    _require_demo_key(x_kya_demo_key, request)
    entry = audit_store.get_one(audit_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Audit entry not found")

    resolution = body.get("resolution")
    reason = body.get("reason", "Manual resolution")
    order_id = body.get("order_id")

    if resolution == "RELEASE_TOKEN":
        jti = entry.get("jti")
        if jti:
            release_token(jti)
        audit_store.update_execution_state(audit_id, "PAYMENT_FAILED")
        audit_store.update(audit_id, entry.get("decision", "APPROVE"), {
            "decision": "BLOCK (manual resolution: " + reason + ")",
            "executed": False,
        })
        record_reconciliation_attempt(
            audit_id, entry.get("execution_id", ""), 0,
            {}, {"resolution": "RELEASE_TOKEN", "reason": reason},
            3, "release_token",
        )
        return {"status": "resolved", "action": "token_released"}

    elif resolution == "FINALIZE_WITH_ORDER":
        if not order_id:
            raise HTTPException(status_code=400, detail="order_id required for FINALIZE_WITH_ORDER")
        jti = entry.get("jti")
        if jti:
            write_outbox_entry(
                jti, audit_id,
                payment_id=order_id,
                execution_id=entry.get("execution_id"),
                agent_id=entry.get("agent_id"),
                amount=entry.get("total_amount"),
            )
            finalize_execution(jti, audit_id, order_id)
        audit_store.update_execution_state(audit_id, "EXECUTED")
        audit_store.update(audit_id, entry.get("decision", "APPROVE"), {
            "payment": {"razorpay_order_id": order_id},
            "executed": True,
        })
        record_reconciliation_attempt(
            audit_id, entry.get("execution_id", ""), 0,
            {}, {"resolution": "FINALIZE_WITH_ORDER", "order_id": order_id, "reason": reason},
            3, "finalize",
        )
        return {"status": "resolved", "action": "finalized", "order_id": order_id}

    else:
        raise HTTPException(status_code=400, detail="Invalid resolution type")



@app.get("/traces", tags=["observability"])
async def traces_endpoint(request: Request, limit: int = 20):
    """Return recent request traces for forensic analysis."""
    traces = get_recent_traces(limit=min(limit, 100))
    stats = get_trace_stats()
    return {"traces": traces, "stats": stats}
@app.get("/metrics")
def metrics_endpoint():
    """Prometheus-compatible metrics endpoint."""
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(_metrics.export_prometheus(), media_type="text/plain")


@app.get("/metrics/json")
def metrics_json():
    """JSON metrics endpoint (for dashboards)."""
    return _metrics.export_json()


@app.get("/")
def root():
    return {
        "service": "KYA -- Know Your Agent",
        "docs": "/docs",
        "endpoints": ["/health", "/metrics", "/agents", "/issue-token", "/verify", "/step-up/confirm", "/audit", "/reconcile/{audit_id}"],
    }


@app.post("/webhooks/razorpay")
async def razorpay_webhook(request: Request):
    """Handle Razorpay webhook events.

    Pipeline:
      raw body -> signature verification -> event parsing
      -> idempotency check -> execution-state update -> audit

    Invalid signature: 401, NO state change.
    Duplicate event: 200, NO repeated effects.
    """
    from webhook import verify_signature, is_duplicate_event, parse_event, map_event_to_state
    import audit as audit_store

    raw_body = await request.body()
    signature = request.headers.get("x-razorpay-signature", "")

    # 1. Signature verification
    if not verify_signature(raw_body, signature):
        security_log.log_security_event("webhook_signature_invalid", {
            "client_ip": _get_client_ip(request),
        })
        return JSONResponse(status_code=401, content={"detail": "Invalid webhook signature"})

    # 2. Parse event
    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError:
        return JSONResponse(status_code=400, content={"detail": "Invalid JSON"})

    event = parse_event(payload)
    if not event:
        return JSONResponse(status_code=400, content={"detail": "Unparseable event"})

    # 3. Idempotency check
    if is_duplicate_event(event["event_id"]):
        logger.info(f"Duplicate webhook event ignored: {event['event_id']}")
        return {"status": "ok", "duplicate": True}

    # 4. Map to KYA state
    new_state = map_event_to_state(event["event_type"])
    if not new_state:
        logger.info(f"Unrecognized webhook event: {event['event_type']}")
        return {"status": "ok", "ignored": True}

    # 5. Update execution state if order_id is available
    order_id = None
    if event.get("order"):
        order_id = event["order"].get("id")

    logger.info(
        f"Webhook processed: {event['event_type']} -> {new_state} "
        f"(order={order_id}, event_id={event['event_id']})"
    )

    return {"status": "ok", "event_type": event["event_type"], "new_state": new_state}


@app.get("/reconciliation/status")
def reconciliation_status(request: Request, x_kya_demo_key: Optional[str] = Header(default=None)):
    """View all PAYMENT_UNKNOWN entries requiring reconciliation."""
    _require_demo_key(x_kya_demo_key, request)
    import audit as audit_store
    pending = audit_store.get_pending_reconciliation_count()
    return {
        "pending_reconciliations": pending,
        "status": "action_required" if pending > 0 else "none_pending",
    }


# --- Serve frontend as static files ---
import pathlib
_frontend_dir = pathlib.Path(__file__).parent.parent / "frontend"
if _frontend_dir.is_dir():
    app.mount("/dashboard", StaticFiles(directory=str(_frontend_dir), html=True), name="frontend")
