"""
Distributed Reliability — Phase 6.

Enhances the outbox pattern with:
1. Exponential backoff retry for failed operations
2. Dead-letter queue for permanently failed items
3. Circuit breaker for external service calls
4. Health monitoring with detailed status
5. Transaction reconciliation helpers

This builds on the existing outbox in registry.py and provides
utilities that can be used by the payment executor and reconciliation worker.
"""

import time
import logging
from typing import Any, Callable, Dict, Optional
from enum import Enum

logger = logging.getLogger("kya")


# ── Circuit Breaker ──────────────────────────────────────────────

class CircuitState(Enum):
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing — reject calls
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreaker:
    """Circuit breaker for external service calls.

    Protects against cascading failures by breaking the circuit
    after repeated failures, then attempting recovery.

    Usage:
        breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=30)

        if breaker.allow_request():
            try:
                result = call_external_service()
                breaker.record_success()
            except Exception as e:
                breaker.record_failure()
                raise
        else:
            # Circuit is open — use fallback
    """

    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_timeout: float = 30.0,
        success_threshold: int = 2,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.success_threshold = success_threshold

        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = 0.0

    def allow_request(self) -> bool:
        """Check if a request should be allowed through."""
        if self.state == CircuitState.CLOSED:
            return True
        elif self.state == CircuitState.OPEN:
            # Check if recovery timeout has elapsed
            if time.time() - self.last_failure_time >= self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0
                logger.info("Circuit breaker: OPEN -> HALF_OPEN (testing recovery)")
                return True
            return False
        else:  # HALF_OPEN
            return True

    def record_success(self) -> None:
        """Record a successful call."""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.success_threshold:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                logger.info("Circuit breaker: HALF_OPEN -> CLOSED (recovered)")
        elif self.state == CircuitState.CLOSED:
            self.failure_count = 0

    def record_failure(self) -> None:
        """Record a failed call."""
        self.failure_count += 1
        self.last_failure_time = time.time()

        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
            logger.warning("Circuit breaker: HALF_OPEN -> OPEN (still failing)")
        elif self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            logger.warning(
                f"Circuit breaker: CLOSED -> OPEN "
                f"(failures={self.failure_count}, threshold={self.failure_threshold})"
            )

    @property
    def is_available(self) -> bool:
        return self.state != CircuitState.OPEN

    def get_status(self) -> Dict[str, Any]:
        return {
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "is_available": self.is_available,
        }


# ── Retry with Exponential Backoff ──────────────────────────────

class RetryConfig:
    """Configuration for retry behavior."""

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        exponential_base: float = 2.0,
        jitter: bool = True,
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter


def retry_with_backoff(
    fn: Callable,
    config: Optional[RetryConfig] = None,
    on_retry: Optional[Callable] = None,
) -> Any:
    """Execute a function with exponential backoff retry.

    Args:
        fn: The function to execute (no arguments — use lambda/closure)
        config: Retry configuration
        on_retry: Optional callback(attempt, delay, exception) called before each retry

    Returns:
        The result of fn() if successful

    Raises:
        The last exception if all retries fail
    """
    import random

    if config is None:
        config = RetryConfig()

    last_exception = None

    for attempt in range(config.max_retries + 1):
        try:
            return fn()
        except Exception as e:
            last_exception = e

            if attempt >= config.max_retries:
                break

            # Calculate delay with exponential backoff
            delay = min(
                config.base_delay * (config.exponential_base ** attempt),
                config.max_delay,
            )

            # Add jitter
            if config.jitter:
                delay *= (0.5 + random.random() * 0.5)

            if on_retry:
                on_retry(attempt + 1, delay, e)

            logger.warning(
                f"Retry {attempt + 1}/{config.max_retries} after {delay:.1f}s: {e}"
            )
            time.sleep(delay)

    raise last_exception


# ── Dead Letter Queue ────────────────────────────────────────────

class DeadLetterEntry:
    """Represents a permanently failed operation."""

    def __init__(
        self,
        operation: str,
        payload: Dict[str, Any],
        error: str,
        timestamp: float,
        retry_count: int,
    ):
        self.operation = operation
        self.payload = payload
        self.error = error
        self.timestamp = timestamp
        self.retry_count = retry_count

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation": self.operation,
            "payload": self.payload,
            "error": self.error,
            "timestamp": self.timestamp,
            "retry_count": self.retry_count,
        }


class DeadLetterQueue:
    """In-memory dead-letter queue for permanently failed operations.

    In production, this would be backed by a database or message queue.
    For the current architecture, entries are stored in memory and
    logged for administrative review.
    """

    def __init__(self, max_size: int = 1000):
        self._entries: list = []
        self._max_size = max_size

    def add(self, entry: DeadLetterEntry) -> None:
        """Add a failed operation to the dead-letter queue."""
        if len(self._entries) >= self._max_size:
            # Remove oldest
            self._entries.pop(0)

        self._entries.append(entry)
        logger.error(
            f"Dead letter: operation={entry.operation} error={entry.error} "
            f"retries={entry.retry_count}"
        )

    def get_all(self) -> list:
        return list(self._entries)

    def count(self) -> int:
        return len(self._entries)

    def clear(self) -> int:
        count = len(self._entries)
        self._entries.clear()
        return count


# ── Health Monitor ───────────────────────────────────────────────

class HealthMonitor:
    """Tracks system health across all components."""

    def __init__(self):
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._dead_letter_queue = DeadLetterQueue()
        self._component_status: Dict[str, Dict[str, Any]] = {}

    def register_circuit_breaker(self, name: str, breaker: CircuitBreaker) -> None:
        self._circuit_breakers[name] = breaker

    def update_component(self, name: str, status: Dict[str, Any]) -> None:
        self._component_status[name] = status

    def get_health(self) -> Dict[str, Any]:
        """Get overall system health status."""
        circuit_status = {
            name: breaker.get_status()
            for name, breaker in self._circuit_breakers.items()
        }

        all_healthy = all(
            cb.get_status()["is_available"]
            for cb in self._circuit_breakers.values()
        )

        return {
            "status": "healthy" if all_healthy else "degraded",
            "circuit_breakers": circuit_status,
            "dead_letters": self._dead_letter_queue.count(),
            "components": self._component_status,
        }

    @property
    def dead_letter_queue(self) -> DeadLetterQueue:
        return self._dead_letter_queue


# Module-level singletons
_circuit_breakers: Dict[str, CircuitBreaker] = {}
_health_monitor = HealthMonitor()


def get_payment_circuit_breaker() -> CircuitBreaker:
    """Get or create the circuit breaker for payment operations."""
    if "payment" not in _circuit_breakers:
        _circuit_breakers["payment"] = CircuitBreaker(
            failure_threshold=3, recovery_timeout=60.0
        )
        _health_monitor.register_circuit_breaker("payment", _circuit_breakers["payment"])
    return _circuit_breakers["payment"]


def get_reconciliation_circuit_breaker() -> CircuitBreaker:
    """Get or create the circuit breaker for reconciliation operations."""
    if "reconciliation" not in _circuit_breakers:
        _circuit_breakers["reconciliation"] = CircuitBreaker(
            failure_threshold=5, recovery_timeout=120.0
        )
        _health_monitor.register_circuit_breaker(
            "reconciliation", _circuit_breakers["reconciliation"]
        )
    return _circuit_breakers["reconciliation"]


def get_health_monitor() -> HealthMonitor:
    return _health_monitor
