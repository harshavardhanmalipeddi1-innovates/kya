"""
Offline evaluation harness.

Calls the shared pipeline module (backend/pipeline.py) directly, in
the same order and with the same functions as backend/main.py's
/verify handler -- so it exercises the identical logic without
needing a running FastAPI server, uvicorn, or network access. Useful
for CI, for judges re-running the numbers offline, and for the
before/after comparison referenced in eval_report.md.

Determinism: every delegation token's expiry is evaluated against
eval_manifest.json's fixed `eval_time`, never real wall-clock time.
This harness refuses to run without that manifest, rather than
silently falling back to time.time() -- falling back quietly is
exactly what produced a "reproducible" 0.989 F1 that was actually
only reproducible inside a ~1-hour window after dataset generation,
scoring 0.52 F1 an hour later and something else again before that.
See eval_manifest.json's `note` field for why.

Usage:
    cd eval/
    python harness.py                              # uses backend/intent_match.py
    python harness.py intent_match_pre_fix_reference  # reproduces the pre-fix numbers

If you'd rather test against the live API (closer to production, but
needs the server running and needs `requests`), use run_evaluation.py
instead -- both read the same synthetic_dataset.json and should agree
when backend/intent_match.py is the module under test, because both
now call the same pipeline.run_pipeline().
"""

import sys
import os
import json
import importlib
from collections import defaultdict

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
EVAL_DIR = os.path.dirname(__file__)
sys.path.insert(0, BACKEND_DIR)
sys.path.insert(0, EVAL_DIR)

from pipeline import run_pipeline  # noqa: E402


class NonDeterministicFixtureError(RuntimeError):
    pass


def load_eval_time() -> int:
    manifest_path = os.path.join(EVAL_DIR, "eval_manifest.json")
    if not os.path.exists(manifest_path):
        raise NonDeterministicFixtureError(
            "ERROR: NON-DETERMINISTIC EVALUATION FIXTURE\n"
            "eval_manifest.json is missing. This dataset's delegation "
            "tokens have relative (issued_at, ttl_seconds) expiry, "
            "which only means anything relative to a fixed evaluation "
            "clock. Without a manifest, results are NOT VALID for "
            "comparison -- regenerate the dataset with generate_dataset.py "
            "(it writes the manifest alongside the dataset) or pass "
            "--evaluation-time explicitly."
        )
    with open(manifest_path) as f:
        manifest = json.load(f)
    return manifest["eval_time"]


def run_case(req, intent_module, eval_time):
    outcome = run_pipeline(
        agent_id=req["agent_id"],
        delegation_token=req["delegation_token"],
        stated_intent=req["stated_intent"],
        cart=req["cart"],
        now=eval_time,
        intent_check_fn=intent_module.check_intent_match,
        use_rolling_baseline=False,
    )
    return outcome, outcome["intent_result"]


def confusion(tp, fp, fn, tn):
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) and precision == precision and recall == recall and (precision + recall) > 0
        else float("nan")
    )
    return precision, recall, f1


def run(intent_module_name="intent_match", verbose=True, eval_time=None):
    intent_module = importlib.import_module(intent_module_name)
    with open(os.path.join(EVAL_DIR, "synthetic_dataset.json")) as f:
        dataset = json.load(f)

    if eval_time is None:
        eval_time = load_eval_time()

    results = []
    for req in dataset:
        outcome, intent_result = run_case(req, intent_module, eval_time)
        results.append(
            {
                "id": req["id"],
                "case_type": req["case_type"],
                "expected": req["expected_decision"],
                "actual": outcome["decision"],
                "stated_intent": req["stated_intent"],
            }
        )

    # Positive class = "not APPROVE" -- i.e. correctly flagging a risky
    # transaction for STEP_UP or BLOCK. Matches the framing in eval_report.md.
    tp = fp = fn = tn = 0
    for r in results:
        exp_flag = r["expected"] != "APPROVE"
        act_flag = r["actual"] != "APPROVE"
        if exp_flag and act_flag:
            tp += 1
        elif act_flag and not exp_flag:
            fp += 1
        elif exp_flag and not act_flag:
            fn += 1
        else:
            tn += 1

    precision, recall, f1 = confusion(tp, fp, fn, tn)

    by_type = defaultdict(lambda: [0, 0])
    for r in results:
        by_type[r["case_type"]][1] += 1
        if r["expected"] == r["actual"]:
            by_type[r["case_type"]][0] += 1

    mismatches = [r for r in results if r["expected"] != r["actual"]]

    summary = {
        "intent_module": intent_module_name,
        "eval_time": eval_time,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "by_case_type": {k: {"correct": c, "total": t} for k, (c, t) in by_type.items()},
        "mismatches": mismatches,
    }

    if verbose:
        print(f"Module: {intent_module_name}  |  eval_time: {eval_time}")
        print(f"  TP={tp} FP={fp} FN={fn} TN={tn}")
        print(f"  Precision={precision:.3f} Recall={recall:.3f} F1={f1:.3f}")
        print("  Accuracy by case_type:")
        for ct, (c, t) in sorted(by_type.items()):
            print(f"    {ct:24s} {c}/{t}")
        print(f"  Total mismatches: {len(mismatches)}")
        for r in mismatches:
            print(f"    [{r['case_type']}] intent='{r['stated_intent']}' expected={r['expected']} actual={r['actual']}")

    return summary


def check_reproducibility(intent_module_name="intent_match", runs=3):
    """The missing test from the original review: prove that running
    the same code against the same fixture under the same clock gives
    the same answer every time, instead of asserting it."""
    eval_time = load_eval_time()
    summaries = [run(intent_module_name, verbose=False, eval_time=eval_time) for _ in range(runs)]
    key = lambda s: (s["tp"], s["fp"], s["fn"], s["tn"])
    baseline = key(summaries[0])
    all_identical = all(key(s) == baseline for s in summaries)
    print(f"Reproducibility check ({runs} runs, eval_time={eval_time} fixed): "
          f"{'IDENTICAL' if all_identical else 'DIVERGED'} -> {baseline}")
    return all_identical


if __name__ == "__main__":
    module = sys.argv[1] if len(sys.argv) > 1 else "intent_match"
    run(module)
    print()
    check_reproducibility(module)
