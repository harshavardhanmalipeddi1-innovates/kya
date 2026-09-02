# KYA test suite

## Required environment variables

Both test modules require two environment variables to be set before
they can import the backend modules. The test files set these
correctly at module level, so you don't need to set them manually —
but if you run the tests from a fresh shell, you should know they're
required:

| Variable | Purpose | Test value (set by test files) |
|----------|---------|-------------------------------|
| `KYA_SIGNING_SECRET` | HMAC key for signing delegation tokens | `test-signing-secret-for-unit-tests` |
| `KYA_DEMO_ISSUER_KEY` | Gates who may mint delegation tokens | `test-demo-key-for-http-attack-matrix` |

These are test-only values. Never use them in production.

## Running tests

```
cd kya
python3 -m unittest discover -s tests -v
```

`test_security.py` needs nothing beyond the stdlib — no pytest, no
fastapi, no network. `test_http_attack_matrix.py` needs
`fastapi`/`uvicorn`/`httpx` installed to actually run; without them
it self-skips cleanly (see below) rather than failing the discover
run.

## What this covers

- Delegation expiry is evaluated correctly at, before, and after the
  boundary, and gives an identical answer no matter how many times
  you run it (the determinism bug).
- A valid token can be verified repeatedly (previewing risk) but can
  only ever pay for one transaction (the replay bug).
- A `STEP_UP` audit record can be confirmed once, and a second
  confirmation of the same `audit_id` is rejected instead of quietly
  creating a second order (the step-up bug).

## What this does NOT cover, and why

`tests/test_security.py` imports `backend/pipeline.py`, `registry.py`,
`audit.py`, and `razorpay_mock.py` directly. It deliberately does
**not** import `backend/main.py`, because `main.py` imports FastAPI,
and this sandbox has no network access to `pip install fastapi
uvicorn`.

That means: `test_security.py` proves the *logic* is correct once you
call it. It does not by itself prove the live HTTP surface
(`/verify`, `/step-up/confirm`, `/issue-token`, CORS headers, the 401
on a missing demo key) behaves the same way when actually hit over
HTTP. `main.py` now calls the exact same `pipeline.run_pipeline` /
`audit.update` / `registry.reserve_token` functions these tests
exercise, so there's no *known* reason it would differ — but "no
known reason" is an inference, not an observation.

`tests/test_http_attack_matrix.py` is a first attempt at closing that
gap — it drives the actual FastAPI app (via `fastapi.testclient
.TestClient`, in-process ASGI, no real socket needed) through the
legitimate flow, a scope-violation attack, expired-delegation,
identity spoofing, single-request replay, the full step-up cycle
including a replayed confirmation, and a 20-thread concurrent replay
against `/verify`. **It has now been run** (all 10 pass, alongside
the 12 in `test_security.py` — 22/22 total), and separately, the
live server was started with real `uvicorn` and hit with real HTTP
requests (`curl`, and `demo/scenarios.py` end-to-end) rather than
only through `TestClient` — see the note below for what that
additionally caught.

```
pip install fastapi uvicorn httpx
python -m unittest tests.test_http_attack_matrix -v
```

If anything in it fails, that's more informative than if it passes
clean on the first try — it means either the test's assumptions about
the request/response shapes are wrong, or there's a real gap between
what `test_security.py` verified and what the live endpoint does.
Either way, treat a first run's result as new information, not a
formality.

**What the live-server run caught that `TestClient` didn't:**
`demo/scenarios.py` called `/issue-token` without the `X-Kya-Demo-Key`
header that `main.py` now requires, so it 401'd against a real running
server even though every `TestClient`-based test passed. `TestClient`
tests exercised `/issue-token` with the header included by design; the
demo script was simply never updated after that endpoint was locked
down. Fixed by adding `AUTH_HEADERS = {"X-Kya-Demo-Key": ...}` to
`demo/scenarios.py`. This is exactly the class of gap the docstring
below warned `TestClient` alone can't catch — a real client (browser,
script, judge's `curl`) forgetting a header that every internal test
happened to already send correctly.

It's still not a full substitute for opening `/docs` and clicking
through by hand at least once (a `TestClient` can't catch a
misconfigured host/port or a reverse-proxy issue):

```
uvicorn main:app --reload
```

