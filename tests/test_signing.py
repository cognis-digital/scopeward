import pytest

from scopeward.signing import sign_scope, verify_scope, compute_signature, SignatureError
from .conftest import KEY


def test_sign_then_verify(scope):
    sign_scope(scope, KEY)
    assert scope.signature
    assert verify_scope(scope, KEY) is True


def test_wrong_key_fails(scope):
    sign_scope(scope, KEY)
    assert verify_scope(scope, "other-key") is False


def test_tamper_breaks_signature(signed_scope):
    # adding an unauthorized target after signing must invalidate it
    from scopeward.scope import Target
    signed_scope.targets.append(Target("android", "com.attacker.evil"))
    assert verify_scope(signed_scope, KEY) is False


def test_verify_unsigned_raises(scope):
    with pytest.raises(SignatureError):
        verify_scope(scope, KEY)


def test_bytes_key_supported(scope):
    sign_scope(scope, b"raw-bytes-key")
    assert verify_scope(scope, b"raw-bytes-key") is True


def test_signature_is_hex_sha256(scope):
    sig = compute_signature(scope, KEY)
    assert len(sig) == 64
    int(sig, 16)  # parses as hex
