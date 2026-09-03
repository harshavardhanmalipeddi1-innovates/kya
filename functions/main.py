"""
KYA — Know Your Agent
Firebase Cloud Function entry point.

Wraps the FastAPI app from backend/main.py as a Google Cloud Function.
Firebase Hosting rewrites /api/** to this function, so we strip the
/api/ prefix at the ASGI level before FastAPI routes the request.
"""
import os
import sys

# Add functions/backend to Python path so all imports resolve
_dir = os.path.dirname(os.path.abspath(__file__))
_backend = os.path.join(_dir, "backend")
if _backend not in sys.path:
    sys.path.insert(0, _backend)
if _dir not in sys.path:
    sys.path.insert(0, _dir)

# Set defaults for Cloud Functions environment
os.environ.setdefault("KYA_PAYMENT_PROVIDER", "razorpay")
os.environ.setdefault("KYA_SIGNING_SECRET", os.environ.get("KYA_SIGNING_SECRET", "kya_prod_secret_2026_abc123def"))
os.environ.setdefault("KYA_DEMO_ISSUER_KEY", os.environ.get("KYA_DEMO_ISSUER_KEY", "kya_demo_key_2026_xyz789ghi"))
os.environ.setdefault("KYA_IDENTITY_MODE", "hmac")
os.environ.setdefault("KYA_INTENT_CLASSIFIER", "keyword")
os.environ.setdefault("KYA_RISK_MODEL", "basic")

from main import app as _fastapi_app  # noqa: E402


class StripApiPrefix:
    """ASGI middleware that strips /api/ prefix from the request path.

    Firebase Hosting rewrites /api/** to this Cloud Function.
    The function receives the full path (e.g. /api/verify).
    FastAPI routes are defined without /api/, so we strip it here.
    """

    def __init__(self, asgi_app):
        self.app = asgi_app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            path = scope.get("path", "")
            if path.startswith("/api/"):
                scope["path"] = path[4:]  # remove "/api"
            elif path == "/api":
                scope["path"] = "/"
        return await self.app(scope, receive, send)


# Wrap the FastAPI app with the prefix-stripping middleware
app = StripApiPrefix(_fastapi_app)
