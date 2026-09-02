"""
Tests for the rolling behavioral baseline module.

Validates that:
  - Transaction recording works correctly
  - Rolling stats are computed accurately
  - Cold-start falls back to static baselines
  - Rolling baselines take over after MIN_SAMPLES
  - Window pruning keeps memory bounded
  - Clear/reset operations work
"""

import os
import sys
import shutil
import tempfile
import unittest

# Add backend to path
BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, BACKEND_DIR)

# Must set required env vars before importing backend modules
os.environ.setdefault("KYA_SIGNING_SECRET", "test-signing-secret-for-baseline-tests")
os.environ.setdefault("KYA_DEMO_ISSUER_KEY", "test-key")

import baseline


class TestBaselineRecording(unittest.TestCase):
    """Test transaction recording and retrieval."""

    def setUp(self):
        """Redirect baseline DB to temp dir."""
        self._tmpdir = tempfile.mkdtemp()
        self._original_path = baseline.BASELINE_DB_PATH
        baseline.BASELINE_DB_PATH = os.path.join(self._tmpdir, "baselines.db")

    def tearDown(self):
        """Restore original path and clean up."""
        baseline.BASELINE_DB_PATH = self._original_path
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_record_and_count(self):
        """Recording a transaction increments the count."""
        self.assertEqual(baseline.get_transaction_count("agent_test"), 0)
        baseline.record_transaction("agent_test", 100.0)
        self.assertEqual(baseline.get_transaction_count("agent_test"), 1)
        baseline.record_transaction("agent_test", 200.0)
        self.assertEqual(baseline.get_transaction_count("agent_test"), 2)

    def test_rolling_stats_empty(self):
        """No history returns None."""
        self.assertIsNone(baseline.get_rolling_stats("agent_empty"))

    def test_rolling_stats_single(self):
        """Single transaction gives mean=std=amount."""
        baseline.record_transaction("agent_one", 500.0)
        stats = baseline.get_rolling_stats("agent_one")
        self.assertIsNotNone(stats)
        self.assertEqual(stats["count"], 1)
        self.assertAlmostEqual(stats["mean"], 500.0)
        # std with n=1 is 0 (variance with ddof=1 is 0/0 -> 0)
        self.assertEqual(stats["std"], 0.0)

    def test_rolling_stats_multiple(self):
        """Multiple transactions compute correct mean and std."""
        amounts = [100.0, 200.0, 300.0, 400.0, 500.0]
        for a in amounts:
            baseline.record_transaction("agent_multi", a)
        stats = baseline.get_rolling_stats("agent_multi")
        self.assertIsNotNone(stats)
        self.assertEqual(stats["count"], 5)
        self.assertAlmostEqual(stats["mean"], 300.0)
        # std with ddof=1
        import math
        expected_std = math.sqrt(sum((a - 300.0) ** 2 for a in amounts) / 4)
        self.assertAlmostEqual(stats["std"], round(expected_std, 2))

    def test_rolling_stats_min_max(self):
        """Stats include min and max."""
        amounts = [50.0, 150.0, 100.0]
        for a in amounts:
            baseline.record_transaction("agent_minmax", a)
        stats = baseline.get_rolling_stats("agent_minmax")
        self.assertEqual(stats["min"], 50.0)
        self.assertEqual(stats["max"], 150.0)

    def test_agents_are_independent(self):
        """Different agents have independent histories."""
        baseline.record_transaction("agent_a", 100.0)
        baseline.record_transaction("agent_a", 200.0)
        baseline.record_transaction("agent_b", 500.0)
        self.assertEqual(baseline.get_transaction_count("agent_a"), 2)
        self.assertEqual(baseline.get_transaction_count("agent_b"), 1)
        stats_a = baseline.get_rolling_stats("agent_a")
        self.assertAlmostEqual(stats_a["mean"], 150.0)
        stats_b = baseline.get_rolling_stats("agent_b")
        self.assertAlmostEqual(stats_b["mean"], 500.0)


class TestBaselineFallback(unittest.TestCase):
    """Test static vs rolling baseline selection."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._original_path = baseline.BASELINE_DB_PATH
        baseline.BASELINE_DB_PATH = os.path.join(self._tmpdir, "baselines.db")

    def tearDown(self):
        baseline.BASELINE_DB_PATH = self._original_path
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_cold_start_uses_static(self):
        """With fewer than MIN_SAMPLES transactions, returns static baseline."""
        # Add fewer than MIN_SAMPLES (5) transactions
        for i in range(baseline.MIN_SAMPLES - 1):
            baseline.record_transaction("agent_cold", 1000.0 + i)
        mean, std, source = baseline.get_effective_baseline("agent_cold", 800.0, 200.0)
        self.assertEqual(source, "static")
        self.assertEqual(mean, 800.0)
        self.assertEqual(std, 200.0)

    def test_enough_samples_uses_rolling(self):
        """With >= MIN_SAMPLES well-spread transactions, returns rolling baseline."""
        # Use amounts with enough variance so std > MIN_STD_FRACTION * static_mean
        amounts = [500.0, 800.0, 1100.0, 1400.0, 1700.0]
        for amt in amounts:
            baseline.record_transaction("agent_warm", amt)
        mean, std, source = baseline.get_effective_baseline("agent_warm", 800.0, 200.0)
        self.assertIn(source, ("rolling", "clamped"))
        # Rolling mean should be close to the recorded values, not the static 800
        self.assertGreater(mean, 800.0)

    def test_clamped_when_low_variance(self):
        """Low-variance rolling stats get clamped to safe std floor."""
        for i in range(baseline.MIN_SAMPLES):
            baseline.record_transaction("agent_lowvar", 1000.0)
        mean, std, source = baseline.get_effective_baseline("agent_lowvar", 800.0, 200.0)
        self.assertEqual(source, "clamped")
        # Std should be floored at MIN_STD_FRACTION * static_mean
        self.assertGreaterEqual(std, 800.0 * baseline.MIN_STD_FRACTION)

    def test_no_history_uses_static(self):
        """No history at all returns static baseline."""
        mean, std, source = baseline.get_effective_baseline("agent_none", 500.0, 100.0)
        self.assertEqual(source, "static")
        self.assertEqual(mean, 500.0)


class TestBaselinePruning(unittest.TestCase):
    """Test that old transactions are pruned beyond MAX_WINDOW."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._original_path = baseline.BASELINE_DB_PATH
        baseline.BASELINE_DB_PATH = os.path.join(self._tmpdir, "baselines.db")

    def tearDown(self):
        baseline.BASELINE_DB_PATH = self._original_path
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_window_pruning(self):
        """Inserting more than MAX_WINDOW transactions prunes old ones."""
        for i in range(baseline.MAX_WINDOW + 20):
            baseline.record_transaction("agent_prune", 100.0 + i)
        count = baseline.get_transaction_count("agent_prune")
        self.assertLessEqual(count, baseline.MAX_WINDOW)


class TestBaselineClear(unittest.TestCase):
    """Test clear/reset operations."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._original_path = baseline.BASELINE_DB_PATH
        baseline.BASELINE_DB_PATH = os.path.join(self._tmpdir, "baselines.db")

    def tearDown(self):
        baseline.BASELINE_DB_PATH = self._original_path
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_clear_single_agent(self):
        """Clearing one agent's history doesn't affect others."""
        baseline.record_transaction("agent_x", 100.0)
        baseline.record_transaction("agent_y", 200.0)
        deleted = baseline.clear_history("agent_x")
        self.assertEqual(deleted, 1)
        self.assertEqual(baseline.get_transaction_count("agent_x"), 0)
        self.assertEqual(baseline.get_transaction_count("agent_y"), 1)

    def test_clear_all(self):
        """Clearing all history removes everything."""
        baseline.record_transaction("agent_a", 100.0)
        baseline.record_transaction("agent_b", 200.0)
        deleted = baseline.clear_history()
        self.assertEqual(deleted, 2)
        self.assertEqual(baseline.get_transaction_count("agent_a"), 0)
        self.assertEqual(baseline.get_transaction_count("agent_b"), 0)

    def test_get_all_baselines(self):
        """get_all_baselines returns stats for all agents."""
        baseline.record_transaction("agent_1", 100.0)
        baseline.record_transaction("agent_1", 200.0)
        baseline.record_transaction("agent_2", 300.0)
        all_stats = baseline.get_all_baselines()
        self.assertIn("agent_1", all_stats)
        self.assertIn("agent_2", all_stats)


if __name__ == "__main__":
    unittest.main()
