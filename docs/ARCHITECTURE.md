# KYA Architecture

## Overview

KYA (Know Your Agent) is an AI-agent transaction authorization system.

## System Architecture

```
HTTP Request
    |
    v
Middleware (request_id, timing, security headers, rate limiting)
    |
    v
pipeline.run_pipeline()
    |-- identity check (HMAC or Ed25519)
    |-- delegation check (token verification)
    |-- scope + limit check
    |-- intent match (keyword or advanced classifier)
    |-- risk score (z-score or multi-signal)
    +-- decision (APPROVE/STEP_UP/BLOCK)
    |
    v
policy_engine.evaluate() -- can override decision
    |
    v
circuit_breaker.allow_request()
    |
    v
payment_provider.create_order()
    |-- MockPaymentProvider (default)
    +-- RazorpayProvider (when KYA_PAYMENT_PROVIDER=razorpay)
    |
    v
audit trail + metrics + tracing
```

## Core Invariants

1. PAYMENT_UNKNOWN never auto-released
2. No blind retry
3. Fail-closed credentials
4. Deterministic evaluation
5. Audit before payment

## Configuration

All configuration via environment variables (see .env.example).

## Payment Execution Safety

```
EXECUTION_PENDING -> PAYMENT_CREATED -> FINALIZATION_PENDING -> EXECUTED
        |                                      |
        v                                      v
   PAYMENT_FAILED                        PAYMENT_UNKNOWN
        |                                      |
   token released                    token RESERVED
                                      reconciliation required
```

## Testing

```
python -m pytest tests/ -q
python -m pytest tests/test_final_verification.py -v
python eval/harness.py
```
