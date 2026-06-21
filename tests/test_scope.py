from datetime import datetime, timedelta, timezone

import pytest

from scopeward.scope import Scope, Target, Device, ScopeError


def test_target_validation():
    with pytest.raises(ScopeError):
        Target("windows", "com.x")
    with pytest.raises(ScopeError):
        Target("android", "")
    assert Target("android", "com.x").key == "android:com.x"


def test_device_validation():
    with pytest.raises(ScopeError):
        Device("")
    assert Device("S1", "lab").device_id == "S1"


def test_scope_requires_target_and_module(now):
    base = dict(
        engagement_id="E", client="C", authorized_by="A", roe="R",
        not_before=now - timedelta(days=1), not_after=now + timedelta(days=1),
    )
    with pytest.raises(ScopeError):
        Scope(**base, targets=[], allowed_modules=["m"])
    with pytest.raises(ScopeError):
        Scope(**base, targets=[Target("android", "com.x")], allowed_modules=[])


def test_window_must_be_ordered(now):
    with pytest.raises(ScopeError):
        Scope(
            engagement_id="E", client="C", authorized_by="A", roe="R",
            not_before=now, not_after=now,
            targets=[Target("android", "com.x")], allowed_modules=["m"],
        )


def test_from_dict_roundtrip(signed_scope):
    data = signed_scope.to_dict()
    again = Scope.from_dict(data)
    assert again.canonical_bytes() == signed_scope.canonical_bytes()
    assert again.target_keys() == {"android:com.acme.app", "ios:com.acme.AcmeApp"}


def test_canonical_bytes_excludes_signature(scope):
    before = scope.canonical_bytes()
    scope.signature = "deadbeef"
    assert scope.canonical_bytes() == before


def test_canonical_bytes_key_order_invariant(now):
    a = Scope.from_dict({
        "engagement_id": "E", "client": "C", "authorized_by": "A", "roe": "R",
        "not_before": (now - timedelta(days=1)).isoformat(),
        "not_after": (now + timedelta(days=1)).isoformat(),
        "targets": [{"platform": "android", "app_id": "com.x"}],
        "allowed_modules": ["m"],
    })
    b = Scope.from_dict({
        "roe": "R", "client": "C", "authorized_by": "A", "engagement_id": "E",
        "allowed_modules": ["m"],
        "targets": [{"app_id": "com.x", "platform": "android"}],
        "not_after": (now + timedelta(days=1)).isoformat(),
        "not_before": (now - timedelta(days=1)).isoformat(),
    })
    assert a.canonical_bytes() == b.canonical_bytes()


def test_z_suffix_timestamp_parsed(now):
    s = Scope.from_dict({
        "engagement_id": "E", "client": "C", "authorized_by": "A", "roe": "R",
        "not_before": "2026-06-19T00:00:00Z", "not_after": "2026-06-27T00:00:00Z",
        "targets": [{"platform": "android", "app_id": "com.x"}], "allowed_modules": ["m"],
    })
    assert s.not_before.tzinfo is not None


def test_is_active(scope, now):
    assert scope.is_active(now)
    assert not scope.is_active(now + timedelta(days=30))
    assert not scope.is_active(now - timedelta(days=30))
