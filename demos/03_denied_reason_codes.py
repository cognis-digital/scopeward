"""Demo: every denial path, each with its stable machine-parseable reason code."""

from __future__ import annotations

from datetime import timedelta

from _common import ANDROID, KEY, hr, now, signed_scope
from scopeward.authz import Authorizer, ScopeViolation
from scopeward.reasons import ReasonCode
from scopeward.scope import Target


def _expect(authz, code, **kwargs):
    try:
        authz.authorize(**kwargs)
    except ScopeViolation as exc:
        got = exc.code
        mark = "OK" if got == code else "MISMATCH"
        print(f"  [{mark}] {got.value:<24} {exc}")
        return got == code
    print(f"  [FAIL] expected denial {code.value} but action was allowed")
    return False


def main() -> int:
    hr("3. Denials & reason codes")
    scope = signed_scope()
    authz = Authorizer(scope, KEY)
    checks = [
        _expect(authz, ReasonCode.MODULE_NOT_ALLOWED,
                module="exfiltrate", target=ANDROID),
        _expect(authz, ReasonCode.TARGET_UNAUTHORIZED,
                module="apkprobe", target=Target("android", "com.evil.app")),
        _expect(authz, ReasonCode.DEVICE_UNAUTHORIZED,
                module="hookbench", device_id="ROGUE-DEVICE"),
        _expect(authz, ReasonCode.DESTRUCTIVE_FORBIDDEN,
                module="apkprobe", target=ANDROID, destructive=True),
        _expect(authz, ReasonCode.WINDOW_INACTIVE,
                module="apkprobe", target=ANDROID, now=now() + timedelta(days=365)),
    ]
    # signature failures happen at Authorizer construction
    try:
        Authorizer(scope, "wrong-key")
    except ScopeViolation as exc:
        ok = exc.code == ReasonCode.SIGNATURE_INVALID
        print(f"  [{'OK' if ok else 'MISMATCH'}] {exc.code.value:<24} {exc}")
        checks.append(ok)

    assert all(checks), "a reason code did not match"
    print("\nOK: each refusal carried the expected SW_* code.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
