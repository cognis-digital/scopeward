"""Demo: emit findings, then export a valid SARIF 2.1.0 document."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from _common import KEY, hr, signed_scope
from scopeward.authz import Authorizer
from scopeward.evidence import EvidenceLog
from scopeward.findings import Finding
from scopeward.sarif import findings_to_sarif


def main() -> int:
    hr("8. SARIF 2.1.0 export")
    scope = signed_scope()
    path = Path(tempfile.mkdtemp()) / "evidence.jsonl"
    log = EvidenceLog(str(path), scope.engagement_id)
    Authorizer(scope, KEY, evidence=log)  # verifies signature

    for f in [
        Finding("Cleartext traffic permitted", "high", "android:com.acme.app",
                module="apkprobe", masvs="MASVS-NETWORK-1", mastg_test="MASTG-TEST-0019"),
        Finding("Hardcoded API key", "critical", "android:com.acme.app",
                module="apkprobe", masvs="MASVS-CRYPTO-1"),
        Finding("Debuggable flag set", "medium", "android:com.acme.app",
                module="apkprobe", masvs="MASVS-RESILIENCE-2"),
    ]:
        log.record("finding", f.to_dict())

    findings = [Finding.from_dict(d) for d in log.findings()]
    doc = findings_to_sarif(findings)

    print(f"findings recorded: {len(findings)}")
    print(f"SARIF version:     {doc['version']}")
    driver = doc["runs"][0]["tool"]["driver"]
    print(f"tool:              {driver['name']} v{driver['version']}")
    print(f"rules:             {[r['id'] for r in driver['rules']]}")
    print("results:")
    for r in doc["runs"][0]["results"]:
        print(f"  {r['level']:<8} {r['ruleId']:<20} sev={r['properties']['security-severity']}")

    out = Path(tempfile.mkdtemp()) / "scopeward.sarif"
    out.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    # sanity: reload and re-check the essentials
    reloaded = json.loads(out.read_text(encoding="utf-8"))
    assert reloaded["version"] == "2.1.0"
    assert len(reloaded["runs"][0]["results"]) == 3
    print(f"\nwrote SARIF to {out}")
    print("OK: valid SARIF 2.1.0 with MASVS-tagged rules.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
