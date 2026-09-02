"""
Phase 1I: End-to-end tracing tests.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))


class TestTraceContext(unittest.TestCase):
    def setUp(self):
        import trace
        self._orig_db = trace.TRACE_DB_PATH
        self._tmpdir = tempfile.mkdtemp()
        trace.TRACE_DB_PATH = os.path.join(self._tmpdir, "traces.db")

    def tearDown(self):
        import trace
        trace.TRACE_DB_PATH = self._orig_db
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_create_and_finalize(self):
        from trace import TraceContext
        ctx = TraceContext(request_id="req_test_001")
        ctx.set_agent_id("agent_test")
        ctx.set_audit_id("audit_test_001")
        ctx.set_execution_id("exec_test_001")
        ctx.log_event("test_event", {"key": "value"})
        summary = ctx.finalize()
        self.assertEqual(summary["request_id"], "req_test_001")
        self.assertEqual(summary["audit_id"], "audit_test_001")
        self.assertEqual(summary["execution_id"], "exec_test_001")
        self.assertEqual(summary["agent_id"], "agent_test")
        self.assertEqual(summary["event_count"], 3)

    def test_lookup_by_request_id(self):
        from trace import TraceContext, lookup_by_request_id
        ctx = TraceContext(request_id="req_lookup_001")
        ctx.set_audit_id("audit_lookup_001")
        ctx.finalize()
        result = lookup_by_request_id("req_lookup_001")
        self.assertIsNotNone(result)
        self.assertEqual(result["audit_id"], "audit_lookup_001")

    def test_lookup_by_audit_id(self):
        from trace import TraceContext, lookup_by_audit_id
        ctx = TraceContext(request_id="req_audit_001")
        ctx.set_audit_id("audit_findme_001")
        ctx.finalize()
        result = lookup_by_audit_id("audit_findme_001")
        self.assertIsNotNone(result)
        self.assertEqual(result["request_id"], "req_audit_001")

    def test_lookup_by_execution_id(self):
        from trace import TraceContext, lookup_by_execution_id
        ctx = TraceContext(request_id="req_exec_001")
        ctx.set_execution_id("exec_findme_001")
        ctx.finalize()
        result = lookup_by_execution_id("exec_findme_001")
        self.assertIsNotNone(result)
        self.assertEqual(result["request_id"], "req_exec_001")

    def test_nonexistent_lookup_returns_none(self):
        from trace import lookup_by_request_id, lookup_by_audit_id
        self.assertIsNone(lookup_by_request_id("nonexistent"))
        self.assertIsNone(lookup_by_audit_id("nonexistent"))

    def test_to_dict(self):
        from trace import TraceContext
        ctx = TraceContext(request_id="req_dict_001")
        ctx.set_agent_id("agent_dict")
        d = ctx.to_dict()
        self.assertEqual(d["request_id"], "req_dict_001")
        self.assertEqual(d["agent_id"], "agent_dict")

    def test_get_trace_stats(self):
        from trace import TraceContext, get_trace_stats
        ctx = TraceContext(request_id="req_stats_001")
        ctx.finalize()
        stats = get_trace_stats()
        self.assertGreaterEqual(stats["total_traces"], 1)
        self.assertGreaterEqual(stats["finalized"], 1)


if __name__ == "__main__":
    unittest.main()
