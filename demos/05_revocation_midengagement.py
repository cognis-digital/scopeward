"""Demo: revoke a target mid-engagement; it is denied even though in scope."""

from __future__ import annotations

from _common import ANDROID, KEY, build_scope, hr
from scopeward.authz import Authorizer, ScopeViolation
from scopeward.reasons import ReasonCode
from scopeward.revocation import Revocation
from scopeward.signing import sign_scope, verify_scope


def main() -> int:
    hr("5. Mid-engagement revocation")
    scope = build_scope()
    sign_scope(scope, KEY)
    authz = Authorizer(scope, KEY)

    print(f"before revocation: apkprobe on {ANDROID.key} ...")
    d = authz.authorize("apkprobe", target=ANDROID)
    print(f"  -> {d.code.value}")
    assert d.allowed

    print("\nclient pulls the Android app out of scope; the authorizer re-signs")
    print("the scope with a revocation (a deleted revocation breaks the signature):")
    scope.revocations.add(Revocation("target", ANDROID.key, reason="client withdrew consent"))
    sign_scope(scope, KEY)  # re-sign: revocations are part of the signed document
    assert verify_scope(scope, KEY)

    authz2 = Authorizer(scope, KEY)
    try:
        authz2.authorize("apkprobe", target=ANDROID)
        print("  -> ALLOWED (unexpected!)")
        return 1
    except ScopeViolation as exc:
        print(f"  -> {exc.code.value}: {exc}")
        assert exc.code == ReasonCode.REVOKED

    print("\nOK: a revoked target is denied even though it is otherwise in scope.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
