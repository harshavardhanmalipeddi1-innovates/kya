# KYA Verification Report

**Date:** 2026-08-31
**State:** Known-good, all checks passing

---

## 1. Server command

```bash
cd kya/backend
uvicorn main:app --port 8000
```

Server confirmed running on `http://localhost:8000`.

---

## 2. Test command

```bash
cd kya
python -m pytest tests/ -v
```

Result: **22/22 passed** (2.07s)

Breakdown:
- `tests/test_http_attack_matrix.py` — 10/10 passed (legitimate purchase, /issue-token auth gate × 3, scope violation, expired delegation, identity spoof, replay, step-up flow, concurrent replay)
- `tests/test_security.py` — 12/12 passed (delegation expiry × 3, replay protection × 5, step-up cannot be replayed × 2, concurrent step-up confirmation × 2)

---

## 3. Scenarios executed (against live uvicorn on :8000)

```bash
cd kya
python demo/scenarios.py
```

---

## 4. Scenario results

| # | Scenario | Decision | Payment |
|---|----------|----------|---------|
| 1 | Legitimate purchase, verified agent, matching intent | APPROVE | order_TEST_… (created) |
| 2 | Unregistered/spoofed agent identity | BLOCK | none |
| 3 | Intent mismatch — stated "groceries", cart is ₹42k laptop | BLOCK | none |
| 4 | Behavioral drift ~2x normal spend | STEP_UP | none |
| 4b | Human confirms step-up challenge | APPROVE (after step-up) | order_TEST_… (created) |

---

## 5. Auth gate verification

| Request | HTTP Status | Detail |
|---------|-------------|--------|
| `/issue-token` without `X-Kya-Demo-Key` | 401 | `Missing/invalid demo issuer key` |
| `/issue-token` with correct `X-Kya-Demo-Key` | 200 | Returns delegation token |
| Frontend flow simulation (token → verify) | 200 | APPROVE + payment created |

---

## 6. Eval harness result

```bash
cd kya/eval
python harness.py
```

| Metric | Value |
|--------|-------|
| Precision | 0.979 |
| Recall | 1.000 |
| F1 | 0.989 |
| Mean latency | 6.8 ms |
| p95 latency | 10.1 ms |

Reproducibility: **3 consecutive runs — IDENTICAL** (TP=94, FP=2, FN=0, TN=84).

---

## 7. Code change made during this session

**File:** `demo/scenarios.py`

**Change:** Added UTF-8 stdout encoding fix at the top of the file (lines 5–11).

**Why:** On Windows, Python's default stdout encoding is cp1252, which cannot encode the `₹` (U+20B9) Unicode character used in scenario title strings. This caused `UnicodeEncodeError` when running `demo/scenarios.py` on Windows without `PYTHONIOENCODING=utf-8`. The fix auto-detects non-UTF-8 encoding and upgrades to UTF-8.

**Exact diff:**

```diff
 """
 Run all four KYA demo scenarios against the local API.
 Usage: python3 scenarios.py   (make sure the server is running on :8000)
 """
 
+import sys
 import os
+
+# Ensure UTF-8 output on Windows (cp1252 can't encode ₹ and other
+# Unicode characters used in the scenario titles below).
+if sys.stdout.encoding and sys.stdout.encoding.lower().replace("-", "") != "utf8":
+    sys.stdout.reconfigure(encoding="utf-8")
+
+import requests
+import json
 
 BASE = "http://localhost:8000"
```

**Verification:** All 22 tests still pass. All 5 scenarios pass on Windows natively without `PYTHONIOENCODING`. Eval harness numbers unchanged.

---

## 8. Runtime artifacts created and cleaned

Created during verification:
- `backend/data/audit_log.json`
- `backend/data/execution_claims.db` (+ `-wal`, `-shm`)

All cleaned up after verification. `.gitignore` already excludes these files.

---

## 9. Files modified across all sessions (cumulative)

| File | Change | Session |
|------|--------|---------|
| `frontend/index.html` | Added `X-Kya-Demo-Key` header to `issueToken()` | Earlier |
| `backend/registry.py` | `SIGNING_SECRET` reads from `KYA_SIGNING_SECRET` env var | Earlier |
| `.gitignore` | Added `audit_log.json` and `execution_claims.db` | Earlier |
| `docs/ARCHITECTURE.md` | Added crash-window limitation + §5.1 mandate model | Earlier |
| `tests/test_http_attack_matrix.py` | Updated stale "NOT RUN" docstring | Earlier |
| `demo/scenarios.py` | Added UTF-8 encoding fix for Windows | This session |
