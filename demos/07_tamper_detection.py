"""Demo: mutating a record in the evidence log is caught by chain verification."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from _common import hr
from scopeward.evidence import EvidenceLog, EvidenceError


def main() -> int:
    hr("7. Audit-log tamper detection")
    path = Path(tempfile.mkdtemp()) / "evidence.jsonl"
    log = EvidenceLog(str(path), "ENG-DEMO-001")
    log.record("authorized", {"module": "apkprobe", "code": "SW_ALLOWED"})
    log.record("finding", {"title": "Cleartext traffic", "severity": "HIGH"})
    log.record("authorized", {"module": "hookbench", "code": "SW_ALLOWED"})

    print(f"wrote {sum(1 for _ in log)} records; chain verifies: {log.verify()}")

    print("\nan attacker edits the first record to hide what was run:")
    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["data"]["module"] = "nothing-to-see-here"
    lines[0] = json.dumps(rec, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    try:
        log.verify()
        print("  -> chain verified (unexpected!)")
        return 1
    except EvidenceError as exc:
        print(f"  -> TAMPERED: {exc}")

    print("\nOK: the SHA-256 hash chain caught the mutation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
