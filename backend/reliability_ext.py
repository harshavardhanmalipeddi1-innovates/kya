# Distributed reliability layer
import os
import time
import logging
from typing import Dict, Any, Callable

MAX_RETRIES = int(os.environ.get("KYA_MAX_RETRIES", "3"))
BASE_BACKOFF = float(os.environ.get("KYA_BASE_BACKOFF", "1.0"))
MAX_BACKOFF = float(os.environ.get("KYA_MAX_BACKOFF", "30.0"))

def retry_with_backoff(fn, max_retries=MAX_RETRIES, base_backoff=BASE_BACKOFF, max_backoff=MAX_BACKOFF, retryable_exceptions=(Exception,)):
    attempts = 0
    last_error = None
    while attempts <= max_retries:
        try:
            return {"success": True, "result": fn(), "attempts": attempts + 1, "last_error": None}
        except retryable_exceptions as e:
            last_error = str(e)
            attempts += 1
            if attempts <= max_retries:
                time.sleep(min(base_backoff * (2 ** (attempts - 1)), max_backoff))
    return {"success": False, "result": None, "attempts": attempts, "last_error": last_error}

def classify_provider_error(error: Exception) -> Dict[str, Any]:
    e = str(error).lower()
    if "timeout" in e: return {"retryable": True, "category": "timeout"}
    if "auth" in e or "401" in e: return {"retryable": False, "category": "auth"}
    if "429" in e: return {"retryable": True, "category": "rate_limit"}
    if any(x in e for x in ["500", "502", "503"]): return {"retryable": True, "category": "server_error"}
    return {"retryable": True, "category": "unknown"}
