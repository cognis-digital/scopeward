import json
from pathlib import Path

import pytest

from datetime import datetime, timezone

from scopeward.cli import main
from scopeward.scope import Scope, Target, Device
from scopeward.signing import sign_scope
from scopeward.evidence import EvidenceLog
from scopeward.grants import Grant
from .conftest import KEY

KEY_ENV = "SCOPEWARD_TEST_KEY"


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv(KEY_ENV, KEY)


def _wide_scope() -> Scope:
    """A scope whose window spans the real current time (the CLI uses now())."""
    return Scope(
        engagement_id="ENG-CLI",
        client="Acme",
        authorized_by="jane@acme.example",
        roe="CLI test scope.",
        not_before=datetime(2000, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2999, 1, 1, tzinfo=timezone.utc),
        targets=[Target("android", "com.acme.app"), Target("ios", "com.acme.AcmeApp")],
        devices=[Device("PIXEL8-ABC123", "lab")],
        allowed_modules=["apkprobe", "hookbench"],
        allow_destructive=False,
        grants=[Grant("G1", "android:com.acme.app", ["instrument"])],
    )


@pytest.fixture
def scope_file(tmp_path):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(_wide_scope().to_dict()), encoding="utf-8")
    return p


@pytest.fixture
def signed_file(tmp_path):
    scope = _wide_scope()
    sign_scope(scope, KEY)
    p = tmp_path / "signed.json"
    p.write_text(json.dumps(scope.to_dict()), encoding="utf-8")
    return p


def _k(extra):
    # subcommand must come first; --key-env is a subcommand-level flag.
    return [extra[0]] + ["--key-env", KEY_ENV] + extra[1:]


def test_version(capsys):
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip()


def test_no_command_prints_help(capsys):
    assert main([]) == 1


def test_sign_and_verify(scope_file, tmp_path, capsys):
    out = tmp_path / "signed.json"
    assert main(_k(["sign", "--scope", str(scope_file), "--out", str(out)])) == 0
    assert out.exists()
    assert main(_k(["verify", "--scope", str(out)])) == 0
    assert "VALID" in capsys.readouterr().out


def test_verify_bad_signature(signed_file, capsys, monkeypatch):
    monkeypatch.setenv(KEY_ENV, "wrong-key")
    assert main(_k(["verify", "--scope", str(signed_file)])) == 1
    assert "INVALID" in capsys.readouterr().out


def test_validate_good(scope_file, capsys):
    assert main(["validate", "--scope", str(scope_file)]) == 0
    assert "VALID" in capsys.readouterr().out


def test_validate_bad(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"engagement_id": "E"}), encoding="utf-8")
    assert main(["validate", "--scope", str(bad)]) == 1
    assert "INVALID" in capsys.readouterr().out


def test_validate_not_json(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert main(["validate", "--scope", str(bad)]) == 1


def test_check_authorized(signed_file, tmp_path, capsys):
    log = tmp_path / "ev.jsonl"
    rc = main(_k(["check", "--scope", str(signed_file), "--module", "apkprobe",
                  "--target", "android:com.acme.app", "--log", str(log)]))
    assert rc == 0
    out = capsys.readouterr().out
    assert "AUTHORIZED" in out and "SW_ALLOWED" in out
    assert log.exists()


def test_check_denied_reason_code(signed_file, capsys):
    rc = main(_k(["check", "--scope", str(signed_file), "--module", "nope",
                  "--target", "android:com.acme.app"]))
    assert rc == 1
    assert "SW_MODULE_NOT_ALLOWED" in capsys.readouterr().out


def test_check_capability(signed_file, capsys):
    rc = main(_k(["check", "--scope", str(signed_file), "--module", "apkprobe",
                  "--target", "android:com.acme.app", "--capability", "instrument"]))
    assert rc == 0


def test_check_capability_denied(signed_file, capsys):
    rc = main(_k(["check", "--scope", str(signed_file), "--module", "apkprobe",
                  "--target", "ios:com.acme.AcmeApp", "--capability", "read"]))
    assert rc == 1
    assert "SW_CAP_NOT_GRANTED" in capsys.readouterr().out


def test_check_json_output(signed_file, capsys):
    rc = main(_k(["check", "--scope", str(signed_file), "--module", "apkprobe",
                  "--target", "android:com.acme.app", "--json"]))
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["code"] == "SW_ALLOWED"


def test_check_bad_target_format(signed_file, capsys):
    with pytest.raises(SystemExit):
        main(_k(["check", "--scope", str(signed_file), "--module", "apkprobe",
                 "--target", "no-colon"]))


def test_audit_intact(signed_file, tmp_path, capsys):
    log = EvidenceLog(str(tmp_path / "ev.jsonl"), "ENG")
    log.record("authorized", {"module": "apkprobe", "code": "SW_ALLOWED"})
    rc = main(["audit", "--log", str(tmp_path / "ev.jsonl"), "--summary"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "INTACT" in out and "SW_ALLOWED" in out


def test_audit_tampered(tmp_path, capsys):
    path = tmp_path / "ev.jsonl"
    log = EvidenceLog(str(path), "ENG")
    log.record("authorized", {"module": "apkprobe"})
    log.record("finding", {"title": "x"})
    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["data"]["module"] = "tampered"
    lines[0] = json.dumps(rec, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert main(["audit", "--log", str(path)]) == 1
    assert "TAMPERED" in capsys.readouterr().out


def test_audit_export(tmp_path):
    path = tmp_path / "ev.jsonl"
    log = EvidenceLog(str(path), "ENG")
    log.record("finding", {"title": "x"})
    out = tmp_path / "trail.json"
    assert main(["audit", "--log", str(path), "--export", str(out)]) == 0
    assert out.exists()


def test_report_sarif(tmp_path, capsys):
    path = tmp_path / "ev.jsonl"
    log = EvidenceLog(str(path), "ENG")
    log.record("finding", {"title": "Cleartext", "severity": "HIGH",
                           "target": "android:com.acme.app", "masvs": "MASVS-NETWORK-1"})
    out = tmp_path / "out.sarif"
    assert main(["report", "--log", str(path), "--format", "sarif", "--out", str(out)]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"][0]["results"]) == 1


def test_report_sarif_stdout(tmp_path, capsys):
    path = tmp_path / "ev.jsonl"
    log = EvidenceLog(str(path), "ENG")
    log.record("finding", {"title": "X", "severity": "LOW", "target": "android:com.x"})
    assert main(["report", "--log", str(path), "--format", "sarif"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"


def test_report_table(tmp_path, capsys):
    path = tmp_path / "ev.jsonl"
    log = EvidenceLog(str(path), "ENG")
    log.record("finding", {"title": "Cleartext", "severity": "HIGH",
                           "target": "android:com.acme.app", "masvs": "MASVS-NETWORK-1"})
    assert main(["report", "--log", str(path), "--format", "table"]) == 0
    out = capsys.readouterr().out
    assert "SEVERITY" in out and "Cleartext" in out


def test_report_table_empty(tmp_path, capsys):
    path = tmp_path / "ev.jsonl"
    EvidenceLog(str(path), "ENG").record("authorized", {"module": "m"})
    assert main(["report", "--log", str(path), "--format", "table"]) == 0
    assert "no findings" in capsys.readouterr().out


def test_reasons_table(capsys):
    assert main(["reasons"]) == 0
    out = capsys.readouterr().out
    assert "SW_ALLOWED" in out and "SW_REVOKED" in out


def test_reasons_json(capsys):
    assert main(["reasons", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "SW_ALLOWED" in payload


def test_missing_key_env(scope_file, capsys, monkeypatch):
    monkeypatch.delenv(KEY_ENV, raising=False)
    with pytest.raises(SystemExit):
        main(_k(["verify", "--scope", str(scope_file)]))


def test_missing_scope_file(capsys):
    rc = main(["validate", "--scope", "does-not-exist.json"])
    assert rc == 2
