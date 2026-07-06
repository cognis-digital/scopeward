from datetime import timedelta

import pytest

from scopeward.grants import Capability, Grant, expand_capabilities
from scopeward.scope import ScopeError


def test_ladder_order():
    assert Capability.READ.rank < Capability.INSTRUMENT.rank
    assert Capability.INSTRUMENT.rank < Capability.MODIFY.rank
    assert Capability.MODIFY.rank < Capability.DESTRUCTIVE.rank


def test_implies_downward_only():
    assert Capability.MODIFY.implies(Capability.READ)
    assert Capability.MODIFY.implies(Capability.INSTRUMENT)
    assert Capability.MODIFY.implies(Capability.MODIFY)
    assert not Capability.MODIFY.implies(Capability.DESTRUCTIVE)
    assert not Capability.READ.implies(Capability.INSTRUMENT)


def test_parse_capability():
    assert Capability.parse("READ") == Capability.READ
    assert Capability.parse(" modify ") == Capability.MODIFY
    assert Capability.parse(Capability.INSTRUMENT) == Capability.INSTRUMENT
    with pytest.raises(ScopeError):
        Capability.parse("root")


def test_expand_capabilities_ladder():
    assert expand_capabilities(["modify"]) == {
        Capability.READ,
        Capability.INSTRUMENT,
        Capability.MODIFY,
    }
    assert expand_capabilities(["read"]) == {Capability.READ}
    assert expand_capabilities(["destructive"]) == set(Capability)


def test_expand_is_idempotent_and_orderfree():
    a = expand_capabilities(["read", "modify"])
    b = expand_capabilities(["modify", "read"])
    assert a == b == {Capability.READ, Capability.INSTRUMENT, Capability.MODIFY}


def test_grant_requires_fields():
    with pytest.raises(ScopeError):
        Grant("", "android:com.x", ["read"])
    with pytest.raises(ScopeError):
        Grant("G", "", ["read"])
    with pytest.raises(ScopeError):
        Grant("G", "android:com.x", [])


def test_grant_normalizes_capabilities():
    g = Grant("G", "android:com.x", ["INSTRUMENT"])
    assert g.capabilities == ["instrument"]


def test_grant_grants_via_ladder():
    g = Grant("G", "android:com.x", ["modify"])
    assert g.grants("read")
    assert g.grants(Capability.INSTRUMENT)
    assert g.grants("modify")
    assert not g.grants("destructive")


def test_grant_effective_capabilities():
    g = Grant("G", "android:com.x", ["instrument"])
    assert g.effective_capabilities() == {Capability.READ, Capability.INSTRUMENT}


def test_grant_matches_wildcards():
    g = Grant("G", "android:com.x", ["read"])  # module/device wildcards
    assert g.matches(target="android:com.x", module="apkprobe", device_id="D1")
    assert not g.matches(target="ios:com.y", module="apkprobe", device_id=None)


def test_grant_matches_narrowed_module():
    g = Grant("G", "android:com.x", ["read"], module="hookbench")
    assert g.matches(target="android:com.x", module="hookbench", device_id=None)
    assert not g.matches(target="android:com.x", module="apkprobe", device_id=None)


def test_grant_matches_narrowed_device():
    g = Grant("G", "android:com.x", ["read"], device_id="D1")
    assert g.matches(target="android:com.x", module="m", device_id="D1")
    assert not g.matches(target="android:com.x", module="m", device_id="D2")
    assert not g.matches(target="android:com.x", module="m", device_id=None)


def test_grant_expiry(now):
    live = Grant("G", "android:com.x", ["read"], expires=(now + timedelta(days=1)).isoformat())
    dead = Grant("H", "android:com.x", ["read"], expires=(now - timedelta(days=1)).isoformat())
    assert not live.is_expired(now)
    assert dead.is_expired(now)
    assert Grant("N", "android:com.x", ["read"]).is_expired(now) is False


def test_grant_bad_expiry_rejected_at_construction():
    with pytest.raises(ScopeError):
        Grant("G", "android:com.x", ["read"], expires="not-a-timestamp")


def test_grant_roundtrip():
    g = Grant("G", "android:com.x", ["modify"], module="hookbench", expires="2026-06-30T00:00:00Z", note="n")
    again = Grant.from_dict(g.to_dict())
    assert again.to_dict() == g.to_dict()
    assert again.effective_capabilities() == g.effective_capabilities()


def test_grant_to_dict_omits_none_fields():
    g = Grant("G", "android:com.x", ["read"])
    d = g.to_dict()
    assert "module" not in d and "device_id" not in d and "expires" not in d
