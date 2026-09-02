"""
Tests for Phase 1H: Baseline poisoning protection.

Validates that the rolling baseline cannot be manipulated by an attacker
who floods the system with tiny transactions to lower the baseline, then
makes a large transaction that passes risk scoring.
"""

import os
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import baseline
import registry


class TestBaselinePoisoningProtection(unittest.TestCase):
    """Test baseline poisoning detection and fallback behavior."""

    def setUp(self):
        """Use a temporary DB for each test to prevent cross-contamination."""
        self._tmpdir = tempfile.mkdtemp()
        self._db_path = os.path.join(self._tmpdir, "baselines.db")
        baseline.BASELINE_DB_PATH = self._db_path

    def tearDown(self):
        baseline.clear_history()
        baseline.BASELINE_DB_PATH = os.path.join(
            os.path.dirname(__file__), "..", "backend", "data", "baselines.db"
        )
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    # --- Poisoning detection ---

    def test_no_poisoning_when_few_samples(self):
        """Fewer than MIN_SAMPLES transactions should not trigger poisoning."""
        agent_id = "agent_procure_bot_042"
        static_mean = 1200.0
        static_std = 350.0

        # Record only 3 transactions (below MIN_SAMPLES=5)
        for _ in range(3):
            baseline.record_transaction(agent_id, 100.0)

        result = baseline.detect_poisoning(agent_id, static_mean, static_std)
        self.assertIsNone(result, "Should not detect poisoning with < MIN_SAMPLES")

    def test_no_poisoning_normal_transactions(self):
        """Normal transactions near the static baseline should not trigger poisoning."""
        agent_id = "agent_procure_bot_042"
        static_mean = 1200.0
        static_std = 350.0

        # Record 10 transactions near the static mean
        for amount in [1100, 1150, 1200, 1250, 1300, 1100, 1150, 1200, 1250, 1300]:
            baseline.record_transaction(agent_id, amount)

        result = baseline.detect_poisoning(agent_id, static_mean, static_std)
        self.assertIsNone(result, "Normal transactions should not trigger poisoning")

    def test_poisoning_detected_below(self):
        """Very small transactions should trigger poisoning detection."""
        agent_id = "agent_procure_bot_042"
        static_mean = 1200.0
        static_std = 350.0

        # Record 10 transactions at ₹10 (far below static mean of ₹1200)
        for _ in range(10):
            baseline.record_transaction(agent_id, 10.0)

        result = baseline.detect_poisoning(agent_id, static_mean, static_std)
        self.assertIsNotNone(result, "Poisoning should be detected for ₹10 transactions")
        self.assertTrue(result["detected"])
        self.assertEqual(result["direction"], "below")
        self.assertLess(result["ratio"], baseline.POISONING_MIN_RATIO)

    def test_poisoning_detected_above(self):
        """Very large transactions should trigger poisoning detection."""
        agent_id = "agent_procure_bot_042"
        static_mean = 1200.0
        static_std = 350.0

        # Record 10 transactions at ₹10,000 (far above static mean of ₹1200)
        for _ in range(10):
            baseline.record_transaction(agent_id, 10000.0)

        result = baseline.detect_poisoning(agent_id, static_mean, static_std)
        self.assertIsNotNone(result, "Poisoning should be detected for ₹10,000 transactions")
        self.assertTrue(result["detected"])
        self.assertEqual(result["direction"], "above")
        self.assertGreater(result["ratio"], baseline.POISONING_MAX_RATIO)

    def test_poisoning_ratio_within_bounds(self):
        """Transactions within the deviation factor should not trigger poisoning."""
        agent_id = "agent_procure_bot_042"
        static_mean = 1200.0
        static_std = 350.0

        # Record 10 transactions at ₹2000 (within 3x of static mean = ₹3600)
        for _ in range(10):
            baseline.record_transaction(agent_id, 2000.0)

        result = baseline.detect_poisoning(agent_id, static_mean, static_std)
        self.assertIsNone(result, "₹2000 is within 3x of ₹1200, should not trigger")

    def test_poisoning_exact_boundary(self):
        """Transactions exactly at the deviation boundary should not trigger poisoning."""
        agent_id = "agent_procure_bot_042"
        static_mean = 1200.0
        static_std = 350.0

        # At exactly 3x = ₹3600, should not trigger (uses <= or >= checks)
        for _ in range(10):
            baseline.record_transaction(agent_id, 3600.0)

        result = baseline.detect_poisoning(agent_id, static_mean, static_std)
        # At exactly the boundary, it depends on the check (>, not >=)
        # Our implementation uses > POISONING_MAX_RATIO, so 3.0 exactly should NOT trigger
        self.assertIsNone(result, "Exact boundary should not trigger poisoning")

    def test_poisoning_with_zero_static_mean(self):
        """Zero static mean should not cause division by zero."""
        agent_id = "agent_procure_bot_042"
        static_mean = 0.0
        static_std = 350.0

        for _ in range(10):
            baseline.record_transaction(agent_id, 10.0)

        result = baseline.detect_poisoning(agent_id, static_mean, static_std)
        self.assertIsNone(result, "Zero static mean should not trigger poisoning")

    def test_poisoning_info_structure(self):
        """Poisoning detection returns expected structure."""
        agent_id = "agent_procure_bot_042"
        static_mean = 1200.0
        static_std = 350.0

        for _ in range(10):
            baseline.record_transaction(agent_id, 10.0)

        result = baseline.detect_poisoning(agent_id, static_mean, static_std)
        self.assertIn("detected", result)
        self.assertIn("direction", result)
        self.assertIn("rolling_mean", result)
        self.assertIn("static_mean", result)
        self.assertIn("ratio", result)
        self.assertIn("deviation_pct", result)
        self.assertIn("threshold_factor", result)
        self.assertIn("rolling_count", result)
        self.assertIn("message", result)

    # --- get_effective_baseline unchanged ---

    def test_effective_baseline_still_uses_static_when_few_samples(self):
        """get_effective_baseline should still return static when < MIN_SAMPLES."""
        agent_id = "agent_procure_bot_042"
        static_mean = 1200.0
        static_std = 350.0

        for _ in range(3):
            baseline.record_transaction(agent_id, 10.0)

        mean, std, source = baseline.get_effective_baseline(agent_id, static_mean, static_std)
        self.assertEqual(source, "static")
        self.assertEqual(mean, static_mean)

    def test_effective_baseline_uses_rolling_when_enough_samples(self):
        """get_effective_baseline should use rolling stats when >= MIN_SAMPLES."""
        agent_id = "agent_procure_bot_042"
        static_mean = 1200.0
        static_std = 350.0

        # Record 10 well-spread transactions so std > MIN_STD_FRACTION * static_mean
        amounts = [600.0, 800.0, 1000.0, 1200.0, 1400.0, 1600.0, 1800.0, 2000.0, 2200.0, 2400.0]
        for amt in amounts:
            baseline.record_transaction(agent_id, amt)

        mean, std, source = baseline.get_effective_baseline(agent_id, static_mean, static_std)
        self.assertIn(source, ("rolling", "clamped"))
        self.assertGreater(mean, static_mean)


class TestPoisoningImpactOnPipeline(unittest.TestCase):
    """Test that poisoning detection is included in pipeline output."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._db_path = os.path.join(self._tmpdir, "baselines.db")
        baseline.BASELINE_DB_PATH = self._db_path

    def tearDown(self):
        baseline.clear_history()
        baseline.BASELINE_DB_PATH = os.path.join(
            os.path.dirname(__file__), "..", "backend", "data", "baselines.db"
        )
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_pipeline_includes_poisoning_info(self):
        """Pipeline output should include baseline_poisoning field."""
        from pipeline import run_pipeline
        from registry import issue_delegation_token

        agent = registry.get_agent("agent_procure_bot_042")
        token = issue_delegation_token(
            agent_id="agent_procure_bot_042",
            human_id=agent["human_owner"],
            allowed_categories=agent["category_scope"],
            max_amount=5000.0,
            ttl_seconds=3600,
            issued_at=1500,
        )

        result = run_pipeline(
            agent_id="agent_procure_bot_042",
            delegation_token=token,
            stated_intent="buy groceries",
            cart=[{"name": "milk", "amount": 50.0, "category": "groceries"}],
            now=1500,
        )

        self.assertIn("baseline_poisoning", result)
        # With no history, should be None (no poisoning detected)
        self.assertIsNone(result["baseline_poisoning"])

    def test_pipeline_detects_poisoning(self):
        """Pipeline should detect poisoning when rolling baseline deviates."""
        from pipeline import run_pipeline
        from registry import issue_delegation_token

        agent_id = "agent_procure_bot_042"
        agent = registry.get_agent(agent_id)

        # Flood the baseline with tiny transactions
        for _ in range(10):
            baseline.record_transaction(agent_id, 10.0)

        token = issue_delegation_token(
            agent_id=agent_id,
            human_id=agent["human_owner"],
            allowed_categories=agent["category_scope"],
            max_amount=5000.0,
            ttl_seconds=3600,
            issued_at=1500,
        )

        result = run_pipeline(
            agent_id=agent_id,
            delegation_token=token,
            stated_intent="buy groceries",
            cart=[{"name": "milk", "amount": 50.0, "category": "groceries"}],
            now=1500,
        )

        self.assertIn("baseline_poisoning", result)
        self.assertIsNotNone(result["baseline_poisoning"])
        self.assertTrue(result["baseline_poisoning"]["detected"])
        self.assertEqual(result["baseline_poisoning"]["direction"], "below")


if __name__ == "__main__":
    unittest.main()
