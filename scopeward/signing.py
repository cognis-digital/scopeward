"""Detached HMAC signing for engagement scopes.

A scope is signed with an engagement key held by the authorizing party (the
client or the lead tester). Tools verify the signature before acting, so a
tampered scope — one where a target app or device was quietly added — fails
verification and the engagement halts.

HMAC-SHA256 is used rather than a bare hash so that knowledge of the key is
required to mint a valid scope. The key is never written into the scope
document; it is provisioned out of band.
"""

from __future__ import annotations

import hashlib
import hmac

from .scope import Scope


class SignatureError(Exception):
    """Raised when a scope signature is missing or does not verify."""


def _normalize_key(key: str | bytes) -> bytes:
    if isinstance(key, str):
        return key.encode("utf-8")
    if isinstance(key, (bytes, bytearray)):
        return bytes(key)
    raise SignatureError("signing key must be str or bytes")


def compute_signature(scope: Scope, key: str | bytes) -> str:
    """Return the hex HMAC-SHA256 of the scope's canonical bytes."""
    mac = hmac.new(_normalize_key(key), scope.canonical_bytes(), hashlib.sha256)
    return mac.hexdigest()


def sign_scope(scope: Scope, key: str | bytes) -> Scope:
    """Attach a fresh signature to ``scope`` (mutates and returns it)."""
    scope.signature = compute_signature(scope, key)
    return scope


def verify_scope(scope: Scope, key: str | bytes) -> bool:
    """Verify the scope's signature with a constant-time comparison.

    Raises :class:`SignatureError` if no signature is present; returns
    ``False`` on mismatch so callers can branch without catching.
    """
    if not scope.signature:
        raise SignatureError("scope is not signed")
    expected = compute_signature(scope, key)
    return hmac.compare_digest(expected, scope.signature)
