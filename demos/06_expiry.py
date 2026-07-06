"""Demo: a per-grant expiry stricter than the engagement window."""

from __future__ import annotations

from datetime import timedelta

from _common import ANDROID, KEY, build_scope, hr, now
from scopeward.authz import Authorizer, ScopeViolation
from scopeward.grants import Grant
from scopeward.reasons import ReasonCode
from scopeward.signing import sign_scope


def main() -> int:
    hr("6. Per-grant expiry")
    scope = build_scope(with_grants=False)
    # A grant that already expired an hour ago, even though the engagement
    # window (7 days) is still wide open.
    scope.grants.append(
        Grant("G-SHORT", ANDROID.key, ["instrument"],
              expires=(now() - timedelta(hours=1)).isoformat(),
              note="short-lived instrumentation grant")
    )
    sign_scope(scope, KEY)
    authz = Authorizer(scope, KEY)

    print(f"engagement window active: {scope.is_active()}")
    print(f"grant G-SHORT expired at: {scope.grants[0].expires}")
    print("\nrequesting instrument on the Android app:")
    try:
        authz.authorize("apkprobe", target=ANDROID, capability="instrument")
        print("  -> ALLOWED (unexpected!)")
        return 1
    except ScopeViolation as exc:
        print(f"  -> {exc.code.value}: {exc}")
        assert exc.code == ReasonCode.EXPIRED

    print("\nOK: an expired grant is denied even inside the engagement window.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
