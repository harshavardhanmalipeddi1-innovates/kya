# KYA Evaluation Report

Synthetic dataset size: 180 requests

> **Reproducibility note (added after review):** earlier versions of
> this report presented the numbers below as simply "the" result.
> They weren't reliably reproducible: delegation tokens carried
> absolute Unix expiry timestamps, so the same code/dataset scored
> anywhere from F1=0.989 down to F1=0.686 depending purely on how
> much wall-clock time had passed since the dataset was generated.
> That's fixed: tokens now carry relative `(issued_at, ttl_seconds)`,
> and `eval/harness.py` evaluates every case against the fixed clock
> in `eval/eval_manifest.json`, not `time.time()`. The numbers below
> are the result of that fixed evaluation and are checked for
> run-to-run stability by `harness.check_reproducibility()` — see
> that file for the mechanism, and `tests/test_security.py` for the
> related delegation/replay/step-up regression tests.
>
> **Signing secret (dataset version 3):** delegation tokens in this
> dataset are signed using an explicit test-only `KYA_SIGNING_SECRET`
> supplied through the environment. No secret value is stored in any
> tracked file. To reproduce the evaluation, set `KYA_SIGNING_SECRET`
> in your environment before running the harness:
> ```
> cd eval/
> KYA_SIGNING_SECRET=<your-test-secret> python harness.py
> ```
> The same secret must be used for both dataset generation and
> evaluation — see `eval_manifest.json` for the required variable name.

> **Fix applied:** `backend/intent_match.py`'s "unknown category" branch used
> to return `mismatch_severity: "medium"` for *any* stated intent it
> couldn't classify -- including plainly legitimate, just informally
> phrased, requests ("pick up some essentials for home", "handle the
> usual weekly errand"). That penalty alone was often enough to push the
> composite risk score past the STEP_UP threshold, wrongly challenging
> a real human for a purchase their agent was correctly authorized to
> make. The fix: "unclassifiable" is now treated as *absence of
> evidence*, not *evidence of mismatch* -- it downgrades to
> `mismatch_severity: "low"` (a small penalty, still visible in the
> audit trail) instead of `"medium"`. Confident, contradictory
> classifications (e.g. "buy electronics" against a grocery cart) are
> untouched and still escalate to `"high"` -- that detection logic was
> already correct and is what keeps `intent_hijack` recall at 1.0 below.
>
> This run scores **0.979 / 1.000 / 0.989** (precision/recall/F1). The
> original, unfixed behavior — preserved at
> `eval/intent_match_pre_fix_reference.py` for reproducibility — scored
> **0.862 / 1.000 / 0.926**. Both numbers below and the reconstructed
> "before" numbers in this note are reproducible by running:
> ```
> cd eval/
> python harness.py                              # fixed (current backend/intent_match.py)
> python harness.py intent_match_pre_fix_reference  # original, for comparison
> ```
> `harness.py` calls the pipeline modules (`registry`, `intent_match`,
> `risk_scorer`, `decision_engine`) directly rather than through the live
> API, since this was run in an environment with no network access for
> `uvicorn`/`requests`. The logic exercised is identical to `main.py`'s
> `/verify` handler -- see `harness.py`'s `run_case()` for the
> line-by-line correspondence. `run_evaluation.py` (the HTTP-based
> variant, for testing against a live server) reads the same
> `synthetic_dataset.json` and agrees with `harness.py` when pointed at
> the same `intent_match` module. Latency figures were not re-measured
> under the fix (unchanged O(1) cost, no new dependency) and are carried
> over from the original run.

## Overall intervention detection (should-block-or-step-up vs did-intervene)

- True Positives: 94
- False Positives: 2
- False Negatives: 0
- True Negatives: 84
- **Precision: 0.979**
- **Recall: 1.000**
- **F1: 0.989**

## Per-detector recall (isolated by failure mode)

These are computed against a synthetic dataset built from the *same* category taxonomy and threshold bands as the detectors themselves -- so near-100% here is expected and should not be read as a real-world guarantee. See the adversarial section below for the more honest signal.

- identity_spoof_detection_recall: 1.0
- delegation_fraud_detection_recall: 1.0
- scope_violation_detection_recall: 1.0
- intent_hijack_detection_recall: 1.0
- legit_traffic_false_positive_rate: 0.0
- moderate_drift_detection_recall: 1.0
- extreme_drift_detection_recall: 1.0

## Adversarial stress tests (the honest part)

These cases are deliberately designed to break the weak points -- not to confirm the system works.

- **Ambiguous-phrasing false positive rate: 0.133** (2/15) -- legitimate purchases described in everyday language the keyword matcher can't classify (e.g. "pick up some essentials for home") no longer get penalized just for being unclassifiable. The residual 2 failures are both "take care of the recurring order" carts where a genuinely elevated purchase amount (behavioral drift) combines with the small residual "low" mismatch penalty to just clear the STEP_UP threshold -- i.e. the remaining misses are a drift-threshold interaction, not the keyword matcher forcing a false positive on its own. Before the fix this rate was 1.0 (15/15): every ambiguously-phrased legitimate purchase was wrongly challenged.
- **Threshold-boundary exact-match rate: 0.867** (13/15) -- transactions placed deliberately at the edges of the STEP_UP/BLOCK bands. A rate below 1.0 here is expected and fine (thresholds are discrete lines through continuous risk); the 2 misses land in the *adjacent* band (STEP_UP expected, BLOCK returned) rather than far off. This is unrelated to the intent-match fix and unchanged by it.
- **Remaining known limitation:** the matcher is still keyword + severity-band based, not a real semantic/embedding model. It cannot yet distinguish "buy some snacks" (paraphrase, should match groceries) from "get some new tech gear" against a grocery cart (should probably still raise an eyebrow) when *both* fail the keyword list -- both currently land in the same lenient "low severity, unclassifiable" bucket. The safe fix under time pressure was to stop punishing the unclassifiable case by default; the more complete fix is a real embedding-similarity or LLM-based classifier scored against cart *item names*, not just a fixed category list. That's the next step, not a solved problem.

## Per-case-type breakdown

### drift_moderate (n=18)
- Exact expected-decision match rate: 1.0
- Decisions seen: {'STEP_UP': 18}

### legit_normal (n=67)
- Exact expected-decision match rate: 1.0
- Decisions seen: {'APPROVE': 67}

### scope_violation (n=8)
- Exact expected-decision match rate: 1.0
- Decisions seen: {'BLOCK': 8}

### delegation_expired (n=8)
- Exact expected-decision match rate: 1.0
- Decisions seen: {'BLOCK': 8}

### spoofed_identity (n=15)
- Exact expected-decision match rate: 1.0
- Decisions seen: {'BLOCK': 15}

### delegation_replay (n=9)
- Exact expected-decision match rate: 1.0
- Decisions seen: {'BLOCK': 9}

### drift_extreme (n=11)
- Exact expected-decision match rate: 1.0
- Decisions seen: {'BLOCK': 11}

### intent_hijack (n=14)
- Exact expected-decision match rate: 1.0
- Decisions seen: {'BLOCK': 14}

### ambiguous_intent_legit (n=15)
- Exact expected-decision match rate: 0.867 (13/15) -- up from 0.0 (0/15) before the fix
- Decisions seen: {'APPROVE': 13, 'STEP_UP': 2}

### boundary_drift (n=15)
- Exact expected-decision match rate: 0.867 (13/15) -- unchanged by the intent-match fix
- Decisions seen: {'STEP_UP': 8, 'APPROVE': 4, 'BLOCK': 3}

## Latency

- Mean: 6.8 ms
- p50: 6.7 ms
- p95: 10.1 ms
