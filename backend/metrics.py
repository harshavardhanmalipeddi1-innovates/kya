"""
Observability & Operations — Phase 7.

Provides structured metrics collection for KYA operations:
1. Request counters (per endpoint, per decision)
2. Latency histograms (per endpoint)
3. Error rates
4. Business metrics (APPROVE/STEP_UP/BLOCK ratios)
5. Security event counters
6. Health status aggregation

Metrics are collected in-memory and exported via:
- GET /metrics endpoint (Prometheus-compatible text format)
- Structured JSON logging
- Health endpoint enrichment

No external dependencies — uses only stdlib.
"""

import time
import threading
from typing import Dict, Any, Optional
from collections import defaultdict


class Counter:
    """Thread-safe counter."""

    def __init__(self, name: str, help_text: str = ""):
        self.name = name
        self.help = help_text
        self._value = 0
        self._lock = threading.Lock()

    def inc(self, value: float = 1.0) -> None:
        with self._lock:
            self._value += value

    def get(self) -> float:
        with self._lock:
            return self._value

    def reset(self) -> None:
        with self._lock:
            self._value = 0


class Histogram:
    """Thread-safe histogram for latency tracking."""

    def __init__(self, name: str, help_text: str = "", buckets: Optional[list] = None):
        self.name = name
        self.help = help_text
        self._buckets = buckets or [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        self._counts = [0] * (len(self._buckets) + 1)  # +1 for +Inf
        self._sum = 0.0
        self._count = 0
        self._lock = threading.Lock()

    def observe(self, value: float) -> None:
        with self._lock:
            self._sum += value
            self._count += 1
            for i, bucket in enumerate(self._buckets):
                if value <= bucket:
                    self._counts[i] += 1
                    return
            self._counts[-1] += 1  # +Inf bucket

    def get_percentile(self, p: float) -> float:
        """Estimate percentile from bucket counts."""
        with self._lock:
            if self._count == 0:
                return 0.0
            target = int(self._count * p)
            cumulative = 0
            for i, count in enumerate(self._counts):
                cumulative += count
                if cumulative >= target:
                    return self._buckets[i] if i < len(self._buckets) else float("inf")
            return float("inf")


class MetricsCollector:
    """Central metrics collection for KYA."""

    def __init__(self):
        # Request counters
        self.requests_total = Counter("kya_requests_total", "Total HTTP requests")
        self.requests_by_endpoint = defaultdict(lambda: Counter("kya_requests_by_endpoint"))
        self.requests_by_decision = defaultdict(lambda: Counter("kya_requests_by_decision"))

        # Security counters
        self.auth_failures = Counter("kya_auth_failures_total", "Total authentication failures")
        self.rate_limits = Counter("kya_rate_limits_total", "Total rate limit violations")
        self.replay_attempts = Counter("kya_replay_attempts_total", "Total replay attempts detected")
        self.baseline_poisoning = Counter("kya_baseline_poisoning_total", "Total poisoning detections")

        # Latency histograms
        self.request_latency = Histogram("kya_request_duration_seconds", "Request duration in seconds")
        self.pipeline_latency = Histogram("kya_pipeline_duration_seconds", "Pipeline execution duration")
        self.payment_latency = Histogram("kya_payment_duration_seconds", "Payment call duration")

        # Business metrics
        self.tokens_issued = Counter("kya_tokens_issued_total", "Total delegation tokens issued")
        self.tokens_executed = Counter("kya_tokens_executed_total", "Total tokens executed")
        self.tokens_released = Counter("kya_tokens_released_total", "Total tokens released")

        # System metrics
        self.start_time = time.time()
        self._custom_metrics: Dict[str, Any] = {}

    def record_request(
        self,
        endpoint: str,
        decision: str,
        duration_ms: float,
        status_code: int = 200,
    ) -> None:
        """Record a completed request."""
        self.requests_total.inc()
        self.requests_by_endpoint[endpoint].inc()
        self.requests_by_decision[decision].inc()
        self.request_latency.observe(duration_ms / 1000.0)

    def record_auth_failure(self) -> None:
        self.auth_failures.inc()

    def record_rate_limit(self) -> None:
        self.rate_limits.inc()

    def record_replay_attempt(self) -> None:
        self.replay_attempts.inc()

    def record_baseline_poisoning(self) -> None:
        self.baseline_poisoning.inc()

    def set_custom_metric(self, name: str, value: Any) -> None:
        self._custom_metrics[name] = value

    def export_prometheus(self) -> str:
        """Export metrics in Prometheus text format."""
        lines = []

        # Counters
        for name, counter in [
            ("kya_requests_total", self.requests_total),
            ("kya_auth_failures_total", self.auth_failures),
            ("kya_rate_limits_total", self.rate_limits),
            ("kya_replay_attempts_total", self.replay_attempts),
            ("kya_baseline_poisoning_total", self.baseline_poisoning),
            ("kya_tokens_issued_total", self.tokens_issued),
            ("kya_tokens_executed_total", self.tokens_executed),
            ("kya_tokens_released_total", self.tokens_released),
        ]:
            lines.append(f"# HELP {name} {counter.help}")
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name} {counter.get()}")

        # Histograms
        for name, hist in [
            ("kya_request_duration_seconds", self.request_latency),
            ("kya_pipeline_duration_seconds", self.pipeline_latency),
            ("kya_payment_duration_seconds", self.payment_latency),
        ]:
            lines.append(f"# HELP {name} {hist.help}")
            lines.append(f"# TYPE {name} histogram")
            cumulative = 0
            for i, bucket in enumerate(hist._buckets):
                with hist._lock:
                    cumulative += hist._counts[i]
                lines.append(f'{name}_bucket{{le="{bucket}"}} {cumulative}')
            with hist._lock:
                lines.append(f'{name}_bucket{{le="+Inf"}} {hist._count}')
                lines.append(f'{name}_sum {hist._sum:.6f}')
                lines.append(f'{name}_count {hist._count}')

        # Uptime
        uptime = time.time() - self.start_time
        lines.append("# TYPE kya_uptime_seconds gauge")
        lines.append(f"kya_uptime_seconds {uptime:.1f}")

        return "\n".join(lines) + "\n"

    def export_json(self) -> Dict[str, Any]:
        """Export metrics as JSON (for health endpoint enrichment)."""
        uptime = time.time() - self.start_time
        return {
            "uptime_seconds": round(uptime, 1),
            "requests_total": self.requests_total.get(),
            "auth_failures": self.auth_failures.get(),
            "rate_limits": self.rate_limits.get(),
            "replay_attempts": self.replay_attempts.get(),
            "baseline_poisoning": self.baseline_poisoning.get(),
            "tokens_issued": self.tokens_issued.get(),
            "tokens_executed": self.tokens_executed.get(),
            "tokens_released": self.tokens_released.get(),
            "request_p50_ms": round(self.request_latency.get_percentile(0.5) * 1000, 1),
            "request_p95_ms": round(self.request_latency.get_percentile(0.95) * 1000, 1),
            "request_p99_ms": round(self.request_latency.get_percentile(0.99) * 1000, 1),
        }


# Module-level singleton
_metrics = MetricsCollector()


def get_metrics() -> MetricsCollector:
    return _metrics
