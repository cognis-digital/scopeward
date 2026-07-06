import pytest

from scopeward.revocation import Revocation, RevocationList, RevocationKind
from scopeward.scope import ScopeError


def test_kind_parse():
    assert RevocationKind.parse("grant") == RevocationKind.GRANT
    assert RevocationKind.parse(RevocationKind.TARGET) == RevocationKind.TARGET
    with pytest.raises(ScopeError):
        RevocationKind.parse("nonsense")


def test_revocation_requires_value():
    with pytest.raises(ScopeError):
        Revocation(kind="target", value="")


def test_revocation_normalizes_kind():
    r = Revocation(kind="module", value="apkprobe")
    assert r.kind == RevocationKind.MODULE


def test_list_queries():
    rl = RevocationList()
    rl.add(Revocation("grant", "G1", reason="pulled"))
    rl.add(Revocation("target", "android:com.x"))
    rl.add(Revocation("module", "hookbench"))
    rl.add(Revocation("device", "D1"))
    assert rl.is_grant_revoked("G1")
    assert not rl.is_grant_revoked("G2")
    assert rl.is_target_revoked("android:com.x")
    assert rl.is_module_revoked("hookbench")
    assert rl.is_device_revoked("D1")
    assert len(rl) == 4


def test_find_returns_matching():
    rl = RevocationList()
    rl.add(Revocation("grant", "G1", reason="client pulled scope"))
    found = rl.find(RevocationKind.GRANT, "G1")
    assert found is not None and found.reason == "client pulled scope"
    assert rl.find(RevocationKind.GRANT, "G2") is None


def test_roundtrip():
    rl = RevocationList()
    rl.add(Revocation("target", "ios:com.y", reason="out of scope", at="2026-06-20T00:00:00Z"))
    again = RevocationList.from_list(rl.to_list())
    assert again.to_list() == rl.to_list()


def test_from_list_none_is_empty():
    assert len(RevocationList.from_list(None)) == 0


def test_from_list_rejects_non_array():
    with pytest.raises(ScopeError):
        RevocationList.from_list({"kind": "grant"})


def test_to_dict_omits_empty_optional_fields():
    d = Revocation("grant", "G1").to_dict()
    assert "reason" not in d and "at" not in d
