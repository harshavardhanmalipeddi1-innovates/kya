"""
Production Identity & Delegation — Phase 3.

Replaces HMAC shared-key token signing with Ed25519 asymmetric
cryptography for delegation tokens. This enables:
  - Per-issuer key pairs (no shared secret)
  - Verifiable delegation chains
  - Key rotation without token invalidation
  - Cryptographic proof of issuer identity

Design:
  - Issuer holds Ed25519 private key (signing)
  - Verifier holds Ed25519 public key (verification)
  - Tokens are JWS-signed JSON payloads
  - Key IDs enable key rotation

This module provides the crypto layer. The existing registry.py
continues to handle token structure and verification — identity.py
provides the signing/verification primitives.

For backward compatibility, the HMAC mode remains available via
KYA_IDENTITY_MODE=hmac (default). Set KYA_IDENTITY_MODE=ed25519
to enable asymmetric crypto.
"""

import json
import os
import time
import hashlib
import hmac
import base64
from typing import Dict, Any, Optional, Tuple
from pathlib import Path

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
KEYS_DIR = os.path.join(DATA_DIR, "keys")

# Identity mode: "hmac" (default, backward-compatible) or "ed25519"
IDENTITY_MODE = os.environ.get("KYA_IDENTITY_MODE", "hmac").lower()


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding (JWT standard)."""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


# ── HMAC mode (backward-compatible) ──────────────────────────────

def _hmac_sign(payload: str, secret: bytes) -> str:
    """Sign payload with HMAC-SHA256."""
    return hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()


def _hmac_verify(payload: str, signature: str, secret: bytes) -> bool:
    """Verify HMAC-SHA256 signature (constant-time)."""
    expected = _hmac_sign(payload, secret)
    return hmac.compare_digest(expected, signature)


# ── Ed25519 mode (production) ───────────────────────────────────

class Ed25519KeyPair:
    """Ed25519 key pair for delegation token signing/verification.

    Wraps the cryptography library's Ed25519 implementation.
    """

    def __init__(self, private_key=None, public_key=None):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
        self._private_key = private_key
        self._public_key = public_key

    @classmethod
    def generate(cls) -> "Ed25519KeyPair":
        """Generate a new Ed25519 key pair."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return cls(private_key=private_key, public_key=public_key)

    @classmethod
    def from_private_key_bytes(cls, private_bytes: bytes) -> "Ed25519KeyPair":
        """Load from raw private key bytes."""
        from cryptography.hazmat.primitives.serialization import (
            load_der_private_key,
        )
        private_key = load_der_private_key(private_bytes, password=None)
        public_key = private_key.public_key()
        return cls(private_key=private_key, public_key=public_key)

    @classmethod
    def from_public_key_bytes(cls, public_bytes: bytes) -> "Ed25519KeyPair":
        """Load from raw public key bytes (verification only)."""
        from cryptography.hazmat.primitives.serialization import (
            load_der_public_key,
        )
        public_key = load_der_public_key(public_bytes)
        return cls(public_key=public_key)

    def sign(self, payload: str) -> str:
        """Sign a payload and return base64url-encoded signature."""
        if self._private_key is None:
            raise ValueError("No private key available for signing")
        signature = self._private_key.sign(payload.encode())
        return _b64url_encode(signature)

    def verify(self, payload: str, signature: str) -> bool:
        """Verify a signature. Returns True if valid."""
        if self._public_key is None:
            return False
        try:
            sig_bytes = _b64url_decode(signature)
            self._public_key.verify(sig_bytes, payload.encode())
            return True
        except Exception:
            return False

    @property
    def key_id(self) -> str:
        """Generate a key ID from the public key (first 8 bytes of SHA-256)."""
        if self._public_key is None:
            return "unknown"
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )
        pub_bytes = self._public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        digest = hashlib.sha256(pub_bytes).digest()[:8]
        return _b64url_encode(digest)

    def save_private_key(self, path: str) -> None:
        """Save private key to file (PEM format)."""
        if self._private_key is None:
            raise ValueError("No private key to save")
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PrivateFormat,
            NoEncryption,
        )
        pem = self._private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            f.write(pem)
        os.chmod(path, 0o600)

    def save_public_key(self, path: str) -> None:
        """Save public key to file (PEM format)."""
        if self._public_key is None:
            raise ValueError("No public key to save")
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )
        pem = self._public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            f.write(pem)

    @classmethod
    def load_private_key(cls, path: str) -> "Ed25519KeyPair":
        """Load private key from PEM file."""
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key,
        )
        with open(path, "rb") as f:
            private_key = load_pem_private_key(f.read(), password=None)
        public_key = private_key.public_key()
        return cls(private_key=private_key, public_key=public_key)

    @classmethod
    def load_public_key(cls, path: str) -> "Ed25519KeyPair":
        """Load public key from PEM file."""
        from cryptography.hazmat.primitives.serialization import (
            load_pem_public_key,
        )
        with open(path, "rb") as f:
            public_key = load_pem_public_key(f.read())
        return cls(public_key=public_key)


# ── Token signing/verification ───────────────────────────────────

class IdentityProvider:
    """Provides token signing and verification based on configured mode.

    In HMAC mode: uses the existing KYA_SIGNING_SECRET.
    In Ed25519 mode: uses per-issuer key pairs.
    """

    def __init__(self):
        self.mode = IDENTITY_MODE
        self._hmac_secret = None
        self._issuer_keys: Dict[str, Ed25519KeyPair] = {}

        if self.mode == "hmac":
            secret_raw = os.environ.get("KYA_SIGNING_SECRET")
            if not secret_raw:
                raise RuntimeError("KYA_SIGNING_SECRET required for HMAC identity mode")
            self._hmac_secret = secret_raw.encode()
        elif self.mode == "ed25519":
            self._load_or_generate_keys()
        else:
            raise RuntimeError(f"Unknown identity mode: {self.mode}")

    def _load_or_generate_keys(self) -> None:
        """Load existing keys or generate a new default issuer key pair."""
        os.makedirs(KEYS_DIR, exist_ok=True)
        default_key_path = os.path.join(KEYS_DIR, "default")
        private_path = f"{default_key_path}.pem"
        public_path = f"{default_key_path}.pub.pem"

        if os.path.exists(private_path) and os.path.exists(public_path):
            self._issuer_keys["default"] = Ed25519KeyPair.load_private_key(private_path)
        else:
            keypair = Ed25519KeyPair.generate()
            keypair.save_private_key(private_path)
            keypair.save_public_key(public_path)
            self._issuer_keys["default"] = keypair

    def sign_token(self, payload: str, issuer_id: str = "default") -> str:
        """Sign a token payload and return a signature string."""
        if self.mode == "hmac":
            return _hmac_sign(payload, self._hmac_secret)
        else:
            keypair = self._issuer_keys.get(issuer_id)
            if not keypair:
                raise ValueError(f"No key pair for issuer: {issuer_id}")
            return keypair.sign(payload)

    def verify_token(self, payload: str, signature: str, issuer_id: str = "default") -> bool:
        """Verify a token signature."""
        if self.mode == "hmac":
            return _hmac_verify(payload, signature, self._hmac_secret)
        else:
            keypair = self._issuer_keys.get(issuer_id)
            if not keypair:
                return False
            return keypair.verify(payload, signature)

    @property
    def key_id(self) -> str:
        """Return the current key ID (for token metadata)."""
        if self.mode == "hmac":
            return "hmac"
        else:
            return self._issuer_keys.get("default", Ed25519KeyPair()).key_id


# Module-level instance
_identity_provider = None


def get_identity_provider() -> IdentityProvider:
    """Get the singleton identity provider."""
    global _identity_provider
    if _identity_provider is None:
        _identity_provider = IdentityProvider()
    return _identity_provider
