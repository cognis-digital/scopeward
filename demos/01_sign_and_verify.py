"""Demo: sign an engagement scope, verify it, then show tampering breaks it."""

from __future__ import annotations

from _common import KEY, build_scope, hr
from scopeward.signing import sign_scope, verify_scope
from scopeward.scope import Target


def main() -> int:
    hr("1. Sign & verify an engagement scope")
    scope = build_scope()
    print(f"engagement:  {scope.engagement_id}  ({scope.client})")
    print(f"authorized:  {scope.authorized_by}")
    print(f"targets:     {sorted(scope.target_keys())}")

    sign_scope(scope, KEY)
    print(f"\nsignature:   {scope.signature[:32]}…  (HMAC-SHA256, detached)")
    print(f"verify:      {verify_scope(scope, KEY)}")
    assert verify_scope(scope, KEY) is True

    print("\nNow an attacker quietly adds an unauthorized target after signing:")
    scope.targets.append(Target("android", "com.attacker.evil"))
    ok = verify_scope(scope, KEY)
    print(f"verify:      {ok}   <- signature no longer matches; engagement halts")
    assert ok is False

    print("\nOK: a scope cannot be widened after it is signed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
