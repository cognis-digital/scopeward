import json

from scopeward.evidence import EvidenceLog


def _populate(path):
    log = EvidenceLog(str(path), "ENG-1")
    log.record("authorized", {"module": "apkprobe", "code": "SW_ALLOWED"})
    log.record("denied", {"module": "evil", "code": "SW_MODULE_NOT_ALLOWED"})
    log.record("denied", {"module": "x", "code": "SW_MODULE_NOT_ALLOWED"})
    log.record("finding", {"title": "Cleartext", "severity": "HIGH",
                           "target": "android:com.acme.app", "masvs": "MASVS-NETWORK-1"})
    return log


def test_summary_counts(tmp_path):
    log = _populate(tmp_path / "e.jsonl")
    s = log.summary()
    assert s["total"] == 4
    assert s["by_kind"] == {"authorized": 1, "denied": 2, "finding": 1}
    assert s["by_code"]["SW_MODULE_NOT_ALLOWED"] == 2
    assert s["by_code"]["SW_ALLOWED"] == 1
    assert s["engagement_ids"] == ["ENG-1"]
    assert s["first_ts"] and s["last_ts"]


def test_findings_extraction(tmp_path):
    log = _populate(tmp_path / "e.jsonl")
    fs = log.findings()
    assert len(fs) == 1
    assert fs[0]["title"] == "Cleartext"


def test_export_roundtrip(tmp_path):
    log = _populate(tmp_path / "e.jsonl")
    out = tmp_path / "trail.json"
    n = log.export(str(out))
    assert n == 4
    data = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(data, list) and len(data) == 4
    assert data[0]["kind"] == "authorized"


def test_summary_empty_log(tmp_path):
    log = EvidenceLog(str(tmp_path / "e.jsonl"))
    s = log.summary()
    assert s["total"] == 0
    assert s["by_kind"] == {}
    assert s["first_ts"] is None


def test_export_creates_parent_dir(tmp_path):
    log = _populate(tmp_path / "e.jsonl")
    out = tmp_path / "sub" / "dir" / "trail.json"
    n = log.export(str(out))
    assert n == 4 and out.exists()
