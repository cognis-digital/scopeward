import pytest

from scopeward.findings import Finding, Severity


def test_severity_parse():
    assert Severity.parse("high") == Severity.HIGH
    assert Severity.parse("CRITICAL") == Severity.CRITICAL
    assert Severity.parse(2) == Severity.MEDIUM
    assert Severity.parse(Severity.LOW) == Severity.LOW
    with pytest.raises(ValueError):
        Severity.parse("apocalyptic")


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO


def test_finding_requires_title():
    with pytest.raises(ValueError):
        Finding(title="", severity="low", target="android:com.x")


def test_finding_roundtrip():
    f = Finding(
        title="Cleartext traffic permitted",
        severity="high",
        target="android:com.acme.app",
        masvs="MASVS-NETWORK-1",
        mastg_test="MASTG-TEST-0019",
        evidence="usesCleartextTraffic=true",
    )
    d = f.to_dict()
    assert d["severity"] == "HIGH"
    assert d["fingerprint"] == f.fingerprint
    again = Finding.from_dict(d)
    assert again.fingerprint == f.fingerprint


def test_fingerprint_stable_and_distinct():
    a = Finding(title="X", severity="low", target="android:com.a", evidence="e1")
    b = Finding(title="X", severity="low", target="android:com.a", evidence="e1")
    c = Finding(title="X", severity="low", target="android:com.b", evidence="e1")
    assert a.fingerprint == b.fingerprint
    assert a.fingerprint != c.fingerprint
