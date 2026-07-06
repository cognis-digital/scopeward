"""Reason-code, capability-ladder and revocation behaviour of the gate."""

from datetime import timedelta

import pytest

from scopeward.scope import Target
from scopeward.authz import Authorizer, ScopeViolation
from scopeward.reasons import ReasonCode, Decision
from scopeward.revocation import Revocation
from scopeward.evidence import EvidenceLog
from .conftest import KEY

ANDROID = Target("android", "com.acme.app")
IOS = Target("ios", "com.acme.AcmeApp")


# ----- reason codes on every deny path ---------------------------------
def test_code_allowed(signed_scope, now):
    d = Authorizer(signed_scope, KEY).authorize("apkprobe", target=ANDROID, now=now)
    assert isinstance(d, Decision)
    assert d.allowed and d.code == ReasonCode.ALLOWED


def test_code_not_signed(scope):
    with pytest.raises(ScopeViolation) as ei:
        Authorizer(scope, KEY)
    assert ei.value.code == ReasonCode.NOT_SIGNED


def test_code_signature_invalid(signed_scope):
    with pytest.raises(ScopeViolation) as ei:
        Authorizer(signed_scope, "wrong-key")
    assert ei.value.code == ReasonCode.SIGNATURE_INVALID


def test_code_window_inactive(signed_scope, now):
    authz = Authorizer(signed_scope, KEY)
    with pytest.raises(ScopeViolation) as ei:
        authz.authorize("apkprobe", target=ANDROID, now=now + timedelta(days=365))
    assert ei.value.code == ReasonCode.WINDOW_INACTIVE
    assert ei.value.decision.detail["not_after"]


def test_code_module_not_allowed(signed_scope, now):
    with pytest.raises(ScopeViolation) as ei:
        Authorizer(signed_scope, KEY).authorize("exfiltrate", target=ANDROID, now=now)
    assert ei.value.code == ReasonCode.MODULE_NOT_ALLOWED


def test_code_target_unauthorized(signed_scope, now):
    with pytest.raises(ScopeViolation) as ei:
        Authorizer(signed_scope, KEY).authorize("apkprobe", target=Target("android", "com.evil.app"), now=now)
    assert ei.value.code == ReasonCode.TARGET_UNAUTHORIZED


def test_code_device_unauthorized(signed_scope, now):
    with pytest.raises(ScopeViolation) as ei:
        Authorizer(signed_scope, KEY).authorize("hookbench", device_id="NOPE", now=now)
    assert ei.value.code == ReasonCode.DEVICE_UNAUTHORIZED


def test_code_destructive_forbidden(signed_scope, now):
    with pytest.raises(ScopeViolation) as ei:
        Authorizer(signed_scope, KEY).authorize("apkprobe", target=ANDROID, destructive=True, now=now)
    assert ei.value.code == ReasonCode.DESTRUCTIVE_FORBIDDEN


# ----- capability ladder ----------------------------------------------
def test_capability_granted_directly(signed_cap_scope, now):
    d = Authorizer(signed_cap_scope, KEY).authorize(
        "apkprobe", target=ANDROID, capability="instrument", now=now
    )
    assert d.allowed and d.code == ReasonCode.ALLOWED


def test_capability_implied_by_ladder(signed_cap_scope, now):
    # G1 grants instrument -> implies read
    d = Authorizer(signed_cap_scope, KEY).authorize(
        "apkprobe", target=ANDROID, capability="read", now=now
    )
    assert d.allowed


def test_capability_above_ladder_denied(signed_cap_scope, now):
    # G1 grants only up to instrument on android; modify is not conferred by any
    # *live* grant (G3 would confer modify but is expired). Deny either way.
    with pytest.raises(ScopeViolation) as ei:
        Authorizer(signed_cap_scope, KEY).authorize(
            "apkprobe", target=ANDROID, capability="modify", now=now
        )
    assert ei.value.code in (ReasonCode.CAP_NOT_GRANTED, ReasonCode.EXPIRED)


def test_capability_truly_ungranted(signed_cap_scope, now):
    # ios modify grant (G2) is narrowed to hookbench; apkprobe on ios has no
    # applicable grant at all -> CAP_NOT_GRANTED (no expired candidate either).
    with pytest.raises(ScopeViolation) as ei:
        Authorizer(signed_cap_scope, KEY).authorize(
            "apkprobe", target=IOS, capability="read", now=now
        )
    assert ei.value.code == ReasonCode.CAP_NOT_GRANTED


def test_capability_modify_implies_instrument(signed_cap_scope, now):
    # G2 grants modify on ios via hookbench -> implies instrument
    d = Authorizer(signed_cap_scope, KEY).authorize(
        "hookbench", target=IOS, capability="instrument", now=now
    )
    assert d.allowed


def test_capability_module_narrowing(signed_cap_scope, now):
    # G2 is narrowed to hookbench; apkprobe must not inherit it
    with pytest.raises(ScopeViolation) as ei:
        Authorizer(signed_cap_scope, KEY).authorize(
            "apkprobe", target=IOS, capability="modify", now=now
        )
    # apkprobe isn't even allowed on this scope? it is allowed_modules -> falls to CAP_NOT_GRANTED
    assert ei.value.code == ReasonCode.CAP_NOT_GRANTED


def test_capability_requires_target(signed_cap_scope, now):
    with pytest.raises(ScopeViolation) as ei:
        Authorizer(signed_cap_scope, KEY).authorize(
            "apkprobe", capability="read", now=now
        )
    assert ei.value.code == ReasonCode.CAP_NOT_GRANTED


def test_capability_destructive_sets_destructive_flag(signed_cap_scope, now):
    # cap_scope allows destructive at engagement level; G3 grants destructive
    # but it is expired -> EXPIRED, proving the destructive->flag path + expiry
    with pytest.raises(ScopeViolation) as ei:
        Authorizer(signed_cap_scope, KEY).authorize(
            "apkprobe", target=ANDROID, capability="destructive", now=now
        )
    assert ei.value.code == ReasonCode.EXPIRED


def test_expired_grant_denied(signed_cap_scope, now):
    with pytest.raises(ScopeViolation) as ei:
        Authorizer(signed_cap_scope, KEY).authorize(
            "apkprobe", target=ANDROID, capability="destructive", now=now
        )
    assert ei.value.code == ReasonCode.EXPIRED
    assert ei.value.decision.detail["grant_id"] == "G3"


# ----- revocation ------------------------------------------------------
def _sign(scope):
    from scopeward.signing import sign_scope
    return sign_scope(scope, KEY)


def test_revoked_module_denied(cap_scope, now):
    cap_scope.revocations.add(Revocation("module", "apkprobe", reason="client pulled"))
    authz = Authorizer(_sign(cap_scope), KEY)
    with pytest.raises(ScopeViolation) as ei:
        authz.authorize("apkprobe", target=ANDROID, now=now)
    assert ei.value.code == ReasonCode.REVOKED
    assert "client pulled" in str(ei.value)


def test_revoked_target_denied(cap_scope, now):
    cap_scope.revocations.add(Revocation("target", "android:com.acme.app"))
    authz = Authorizer(_sign(cap_scope), KEY)
    with pytest.raises(ScopeViolation) as ei:
        authz.authorize("apkprobe", target=ANDROID, now=now)
    assert ei.value.code == ReasonCode.REVOKED


def test_revoked_device_denied(cap_scope, now):
    cap_scope.revocations.add(Revocation("device", "PIXEL8-ABC123"))
    authz = Authorizer(_sign(cap_scope), KEY)
    with pytest.raises(ScopeViolation) as ei:
        authz.authorize("hookbench", device_id="PIXEL8-ABC123", now=now)
    assert ei.value.code == ReasonCode.REVOKED


def test_revoked_grant_denied(cap_scope, now):
    cap_scope.revocations.add(Revocation("grant", "G1"))
    authz = Authorizer(_sign(cap_scope), KEY)
    with pytest.raises(ScopeViolation) as ei:
        authz.authorize("apkprobe", target=ANDROID, capability="instrument", now=now)
    assert ei.value.code == ReasonCode.REVOKED


def test_revocation_beats_positive_authorization(cap_scope, now):
    # target is authorized AND has a grant, but revoked -> still denied
    cap_scope.revocations.add(Revocation("target", "android:com.acme.app"))
    authz = Authorizer(_sign(cap_scope), KEY)
    assert not authz.is_authorized("apkprobe", target=ANDROID, now=now)


def test_revocation_is_signed_in(cap_scope):
    # adding a revocation changes canonical bytes -> old signature must break
    signed = _sign(cap_scope)
    from scopeward.signing import verify_scope
    assert verify_scope(signed, KEY)
    signed.revocations.add(Revocation("module", "apkprobe"))
    assert verify_scope(signed, KEY) is False


# ----- evaluate() non-raising + auditing -------------------------------
def test_evaluate_does_not_log(signed_cap_scope, now, tmp_path):
    log = EvidenceLog(str(tmp_path / "e.jsonl"))
    authz = Authorizer(signed_cap_scope, KEY, evidence=log)
    authz.evaluate("apkprobe", target=ANDROID, now=now)
    assert list(log) == []  # evaluate() is pure


def test_authorize_logs_code(signed_cap_scope, now, tmp_path):
    log = EvidenceLog(str(tmp_path / "e.jsonl"), "ENG")
    authz = Authorizer(signed_cap_scope, KEY, evidence=log)
    authz.authorize("apkprobe", target=ANDROID, now=now)
    with pytest.raises(ScopeViolation):
        authz.authorize("apkprobe", target=IOS, capability="read", now=now)
    recs = list(log)
    assert recs[0]["data"]["code"] == "SW_ALLOWED"
    assert recs[1]["data"]["code"] == "SW_CAP_NOT_GRANTED"
    assert log.verify()


def test_decision_to_dict(signed_scope, now):
    d = Authorizer(signed_scope, KEY).evaluate("apkprobe", target=ANDROID, now=now)
    payload = d.to_dict()
    assert payload["code"] == "SW_ALLOWED"
    assert payload["allowed"] is True
    assert "detail" in payload
