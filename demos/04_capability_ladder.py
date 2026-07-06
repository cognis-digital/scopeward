"""Demo: the read < instrument < modify < destructive capability ladder."""

from __future__ import annotations

from _common import ANDROID, IOS, KEY, hr, signed_scope
from scopeward.authz import Authorizer, ScopeViolation


def _try(authz, label, **kwargs):
    try:
        d = authz.authorize(**kwargs)
        print(f"  ALLOW  {label:<44} {d.code.value}")
        return True, None
    except ScopeViolation as exc:
        print(f"  DENY   {label:<44} {exc.code.value}")
        return False, exc.code


def main() -> int:
    hr("4. Capability ladder")
    scope = signed_scope()
    authz = Authorizer(scope, KEY)

    print("G-ANDROID grants 'instrument' on the Android app; a higher rung")
    print("(modify) is refused, but a lower rung (read) is implied:\n")
    allow_read, _ = _try(authz, "apkprobe read android", module="apkprobe", target=ANDROID, capability="read")
    allow_instr, _ = _try(authz, "apkprobe instrument android", module="apkprobe", target=ANDROID, capability="instrument")
    deny_modify, _ = _try(authz, "apkprobe modify android", module="apkprobe", target=ANDROID, capability="modify")

    print("\nG-IOS grants 'modify' to hookbench on the iOS app; modify implies")
    print("instrument, and the grant is narrowed to the hookbench module:\n")
    allow_ios, _ = _try(authz, "hookbench instrument ios", module="hookbench", target=IOS, capability="instrument")
    deny_wrong_module, _ = _try(authz, "apkprobe modify ios (wrong module)", module="apkprobe", target=IOS, capability="modify")

    assert allow_read and allow_instr and allow_ios
    assert not deny_modify and not deny_wrong_module
    print("\nOK: higher rungs imply lower rungs; grants do not leak across targets/modules.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
