"""
Razorpay Webhook Handler — Phase 3I-3K.

Handles incoming Razorpay webhook events with:
  - HMAC-SHA256 signature verification
  - Event idempotency (deduplication)
  - Execution-state mapping
  - Audit trail

Webhook pipeline:
  HTTP body + X-Razorpay-Signature
      -> signature verification
      -> event parsing
      -> idempotency check
      -> execution-state update
      -> audit record

Invalid signature: 401, NO state change.
Duplicate event: 200, NO repeated effects.
"""

import hashlib
import hmac
import json
import logging
import os
import time
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger("kya")

# Webhook secret for signature verification
RAZORPAY_WEBHOOK_SECRET = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")

# In-memory dedup store (in production: use DB)
_processed_events: Dict[str, float] = {}
_DEDUP_TTL_SECONDS = 86400  # 24 hours


def verify_signature(raw_body: bytes, signature: str) -> bool:
    """Verify Razorpay webhook signature using HMAC-SHA256.

    Razorpay signs webhooks with:
      HMAC-SHA256(webhook_secret, raw_request_body)

    The signature is sent in the X-Razorpay-Signature header.
    """
    if not RAZORPAY_WEBHOOK_SECRET:
        logger.error("RAZORPAY_WEBHOOK_SECRET not configured — rejecting webhook")
        return False

    expected = hmac.new(
        RAZORPAY_WEBHOOK_SECRET.encode(),
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


def is_duplicate_event(event_id: str) -> bool:
    """Check if a webhook event has already been processed.

    Uses in-memory dedup with TTL. In production, use a durable store.
    """
    now = time.time()

    # Prune expired entries
    expired = [k for k, v in _processed_events.items() if now - v > _DEDUP_TTL_SECONDS]
    for k in expired:
        del _processed_events[k]

    if event_id in _processed_events:
        return True

    _processed_events[event_id] = now
    return False


def clear_dedup_store():
    """Clear the dedup store. For testing only."""
    _processed_events.clear()


def parse_event(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Parse a Razorpay webhook payload into a normalized event.

    Returns:
        Normalized event dict or None if unparseable.

    Razorpay webhook payload structure:
    {
        "event": "payment.authorized",
        "payload": {
            "payment": { "entity": { ... } },
            "order": { "entity": { ... } }
        }
    }
    """
    event_type = payload.get("event")
    if not event_type:
        logger.warning("Webhook payload missing 'event' field")
        return None

    payload_data = payload.get("payload", {})

    # Extract payment and order entities
    payment_entity = None
    order_entity = None

    if "payment" in payload_data:
        payment_entity = payload_data["payment"].get("entity")
    if "order" in payload_data:
        order_entity = payload_data["order"].get("entity")

    # Generate event ID for deduplication
    event_id = payload.get("id") or f"{event_type}_{payload.get('created_at', int(time.time()))}"

    return {
        "event_id": event_id,
        "event_type": event_type,
        "payment": payment_entity,
        "order": order_entity,
        "created_at": payload.get("created_at", int(time.time())),
    }


# Razorpay event -> KYA execution state mapping
EVENT_STATE_MAP = {
    # Order events
    "order.created": "PAYMENT_CREATED",
    "order.paid": "EXECUTED",
    # Payment events
    "payment.authorized": "PAYMENT_CREATED",
    "payment.captured": "EXECUTED",
    "payment.failed": "PAYMENT_FAILED",
    "payment.refunded": "PAYMENT_FAILED",
}


def map_event_to_state(event_type: str) -> Optional[str]:
    """Map a Razorpay event type to a KYA execution state.

    Returns None for unrecognized events (should be logged but not acted on).
    """
    return EVENT_STATE_MAP.get(event_type)


def clear_dedup_store():
    """Reset dedup state. For testing only."""
    _processed_events.clear()
