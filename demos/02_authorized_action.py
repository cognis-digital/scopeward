"""Demo: an authorized action passes the gate and is written to the audit log."""

from __future__ import annotations

import tempfile
from pathlib import Path

from _common import ANDROID, KEY, hr, signed_scope
from scopeward.authz import Authorizer
from scopeward.evidence import EvidenceLog


def main() -> int:
    hr("2. An authorized action")
    scope = signed_scope()
    tmp = Path(tempfile.mkdtemp()) / "evidence.jsonl"
    log = EvidenceLog(str(tmp), scope.engagement_id)
    authz = Authorizer(scope, KEY, evidence=log)

    decision = authz.authorize("apkprobe", target=ANDROID)
    print(f"module=apkprobe target={ANDROID.key}")
    print(f"  -> {decision.code.value}: {decision.message}")
    assert decision.allowed

    print(f"\nan audit record was appended to {tmp.name}:")
    for rec in log:
        print(f"  [{rec['kind']}] {rec['data'].get('code')} module={rec['data'].get('module')}")
    assert log.verify()
    print("\nOK: authorized, audited, chain intact.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
