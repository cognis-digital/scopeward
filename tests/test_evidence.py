import json

import pytest

from scopeward.evidence import EvidenceLog, EvidenceError, GENESIS


def test_empty_log_verifies(tmp_path):
    log = EvidenceLog(str(tmp_path / "ev.jsonl"))
    assert log.verify()
    assert list(log) == []


def test_records_chain(tmp_path):
    log = EvidenceLog(str(tmp_path / "ev.jsonl"), "ENG-1")
    r1 = log.record("authorized", {"module": "apkprobe"})
    r2 = log.record("finding", {"title": "cleartext traffic"})
    assert r1["prev"] == GENESIS
    assert r2["prev"] == r1["hash"]
    assert log.verify()
    assert sum(1 for _ in log) == 2


def test_tamper_detected(tmp_path):
    path = tmp_path / "ev.jsonl"
    log = EvidenceLog(str(path), "ENG-1")
    log.record("authorized", {"module": "apkprobe"})
    log.record("finding", {"title": "secret in strings.xml"})

    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["data"]["module"] = "tampered"
    lines[0] = json.dumps(rec, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(EvidenceError):
        log.verify()


def test_deleted_record_detected(tmp_path):
    path = tmp_path / "ev.jsonl"
    log = EvidenceLog(str(path), "ENG-1")
    log.record("a", {"n": 1})
    log.record("b", {"n": 2})
    log.record("c", {"n": 3})
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]  # drop the middle record
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(EvidenceError):
        log.verify()
