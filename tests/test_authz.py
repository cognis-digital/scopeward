from datetime import timedelta

import pytest

from scopeward.scope import Target
from scopeward.authz import Authorizer, ScopeViolation
from scopeward.evidence import EvidenceLog
from .conftest import KEY


def test_unsigned_scope_refused(scope):
    with pytest.raises(ScopeViolation):
        Authorizer(scope, KEY)  # not signed -> refuse


def test_bad_signature_refused(signed_scope):
    with pytest.raises(ScopeViolation):
        Authorizer(signed_scope, "wrong-key")


def test_authorized_target_passes(signed_scope, now):
    authz = Authorizer(signed_scope, KEY)
    authz.authorize("apkprobe", target=Target("android", "com.acme.app"), now=now)


def test_unauthorized_target_refused(signed_scope, now):
    authz = Authorizer(signed_scope, KEY)
    with pytest.raises(ScopeViolation, match="not an authorized target"):
        authz.authorize("apkprobe", target=Target("android", "com.evil.app"), now=now)


def test_unauthorized_module_refused(signed_scope, now):
    authz = Authorizer(signed_scope, KEY)
    with pytest.raises(ScopeViolation, match="not in allowed_modules"):
        authz.authorize("exfiltrate", target=Target("android", "com.acme.app"), now=now)


def test_unauthorized_device_refused(signed_scope, now):
    authz = Authorizer(signed_scope, KEY)
    with pytest.raises(ScopeViolation, match="not an authorized device"):
        authz.authorize("hookbench", device_id="UNKNOWN-DEV", now=now)


def test_expired_window_refused(signed_scope, now):
    authz = Authorizer(signed_scope, KEY)
    with pytest.raises(ScopeViolation, match="window not active"):
        authz.authorize("apkprobe", target=Target("android", "com.acme.app"), now=now + timedelta(days=30))


def test_destructive_blocked_by_default(signed_scope, now):
    authz = Authorizer(signed_scope, KEY)
    with pytest.raises(ScopeViolation, match="destructive"):
        authz.authorize("apkprobe", target=Target("android", "com.acme.app"), destructive=True, now=now)


def test_is_authorized_nonraising(signed_scope, now):
    authz = Authorizer(signed_scope, KEY)
    assert authz.is_authorized("apkprobe", target=Target("android", "com.acme.app"), now=now)
    assert not authz.is_authorized("apkprobe", target=Target("android", "com.evil.app"), now=now)


def test_decisions_logged(signed_scope, now, tmp_path):
    log = EvidenceLog(str(tmp_path / "ev.jsonl"), signed_scope.engagement_id)
    authz = Authorizer(signed_scope, KEY, evidence=log)
    authz.authorize("apkprobe", target=Target("android", "com.acme.app"), now=now)
    with pytest.raises(ScopeViolation):
        authz.authorize("apkprobe", target=Target("android", "com.evil.app"), now=now)
    kinds = [r["kind"] for r in log]
    assert kinds == ["authorized", "denied"]
    assert log.verify()
