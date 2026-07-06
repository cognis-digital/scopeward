from scopeward.findings import Finding, Severity
from scopeward.sarif import findings_to_sarif, SARIF_VERSION


def _findings():
    return [
        Finding(
            title="Cleartext traffic permitted",
            severity="high",
            target="android:com.acme.app",
            description="usesCleartextTraffic is true",
            module="apkprobe",
            masvs="MASVS-NETWORK-1",
            mastg_test="MASTG-TEST-0019",
            evidence="android:usesCleartextTraffic=true",
        ),
        Finding(
            title="Hardcoded secret",
            severity="critical",
            target="android:com.acme.app",
            module="apkprobe",
            masvs="MASVS-CRYPTO-1",
        ),
        Finding(
            title="Another cleartext finding",
            severity="medium",
            target="ios:com.acme.AcmeApp",
            module="ipaprobe",
            masvs="MASVS-NETWORK-1",  # same rule as first -> dedup
        ),
        Finding(title="No MASVS finding", severity="low", target="android:com.acme.app", module="hookbench"),
    ]


def test_sarif_top_level_shape():
    doc = findings_to_sarif(_findings())
    assert doc["version"] == SARIF_VERSION
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    assert len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "scopeward"
    assert driver["version"]


def test_rules_are_deduplicated():
    doc = findings_to_sarif(_findings())
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    # MASVS-NETWORK-1 used twice -> one rule; unique ids
    assert len(ids) == len(set(ids))
    assert "MASVS-NETWORK-1" in ids
    assert "MASVS-CRYPTO-1" in ids


def test_results_reference_valid_rule_index():
    doc = findings_to_sarif(_findings())
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    for res in run["results"]:
        assert 0 <= res["ruleIndex"] < len(rules)
        assert res["ruleId"] == rules[res["ruleIndex"]]["id"]


def test_severity_maps_to_level():
    doc = findings_to_sarif(_findings())
    results = doc["runs"][0]["results"]
    levels = {r["ruleId"]: r["level"] for r in results}
    assert levels["MASVS-NETWORK-1"] in ("error", "warning")
    # critical -> error
    crit = [r for r in results if r["properties"]["severity"] == "CRITICAL"][0]
    assert crit["level"] == "error"


def test_security_severity_present():
    doc = findings_to_sarif(_findings())
    for r in doc["runs"][0]["results"]:
        assert "security-severity" in r["properties"]
        float(r["properties"]["security-severity"])  # numeric


def test_partial_fingerprints_present():
    doc = findings_to_sarif(_findings())
    for r in doc["runs"][0]["results"]:
        assert r["partialFingerprints"]["scopewardFingerprint/v1"]


def test_masvs_tags_on_rule():
    doc = findings_to_sarif(_findings())
    rules = {r["id"]: r for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    net = rules["MASVS-NETWORK-1"]
    assert "MASVS-NETWORK-1" in net["properties"]["tags"]
    assert "helpUri" in net


def test_finding_without_masvs_gets_module_rule():
    doc = findings_to_sarif(_findings())
    ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
    assert "scopeward/hookbench" in ids


def test_empty_findings_valid():
    doc = findings_to_sarif([])
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_locations_are_logical():
    doc = findings_to_sarif(_findings())
    r = doc["runs"][0]["results"][0]
    loc = r["locations"][0]["logicalLocations"][0]
    assert loc["fullyQualifiedName"].startswith(("android:", "ios:"))
