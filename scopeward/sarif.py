"""SARIF 2.1.0 export of findings.

SARIF (Static Analysis Results Interchange Format, OASIS 2.1.0) is the lingua
franca for security results — GitHub code scanning, Azure DevOps and most
review tooling ingest it. This module turns a stream of
:class:`~scopeward.findings.Finding` objects (typically read back out of an
evidence log) into a valid SARIF 2.1.0 document.

Each distinct MASVS control becomes a SARIF *rule* (deduplicated), tagged with
its MASVS category and linked to the MASVS/MASTG docs. Severities map to SARIF
``level`` (error/warning/note) plus a numeric ``security-severity`` property so
GitHub sorts them. Everything is stdlib ``json``-serializable.

Reference: SARIF v2.1.0, OASIS Standard.
"""

from __future__ import annotations

from typing import Any, Iterable

from .findings import Finding, Severity
from . import masvs

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "scopeward"

# Severity → SARIF level. SARIF has three result levels.
_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

# Severity → GitHub security-severity (CVSS-like 0-10 buckets).
_SECURITY_SEVERITY = {
    Severity.INFO: "0.0",
    Severity.LOW: "2.0",
    Severity.MEDIUM: "5.5",
    Severity.HIGH: "8.0",
    Severity.CRITICAL: "9.5",
}


def _rule_id(finding: Finding) -> str:
    """Stable rule id: the MASVS control if present, else module-derived."""
    if finding.masvs:
        return finding.masvs
    if finding.module:
        return f"scopeward/{finding.module}"
    return "scopeward/finding"


def _build_rule(finding: Finding) -> dict[str, Any]:
    rule_id = _rule_id(finding)
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": rule_id.replace("-", "").replace("/", "_"),
        "shortDescription": {"text": finding.title},
    }
    tags: list[str] = ["security", "mobile"]
    if finding.masvs:
        rule["helpUri"] = masvs.masvs_help_uri(finding.masvs)
        cat = masvs.category_name(finding.masvs)
        if cat:
            tags.append(finding.masvs)
            rule["fullDescription"] = {"text": f"OWASP MASVS category: {cat}"}
    if finding.mastg_test:
        uri = masvs.mastg_help_uri(finding.mastg_test)
        if uri and "helpUri" not in rule:
            rule["helpUri"] = uri
        tags.append(finding.mastg_test)
    rule["properties"] = {"tags": tags}
    return rule


def _build_result(finding: Finding, rule_index: int) -> dict[str, Any]:
    sev = finding.severity
    result: dict[str, Any] = {
        "ruleId": _rule_id(finding),
        "ruleIndex": rule_index,
        "level": _LEVEL[sev],
        "message": {"text": finding.description or finding.title},
        "properties": {
            "security-severity": _SECURITY_SEVERITY[sev],
            "severity": sev.name,
            "target": finding.target,
            "fingerprint": finding.fingerprint,
        },
    }
    if finding.module:
        result["properties"]["module"] = finding.module
    # Represent the target app as a logical location; SARIF requires locations
    # to be physical or logical — logical fits a mobile app id well.
    result["locations"] = [
        {
            "logicalLocations": [
                {"fullyQualifiedName": finding.target, "kind": "namespace"}
            ]
        }
    ]
    # Stable partial fingerprint for result matching across runs.
    result["partialFingerprints"] = {"scopewardFingerprint/v1": finding.fingerprint}
    return result


def findings_to_sarif(
    findings: Iterable[Finding],
    *,
    tool_version: str | None = None,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from an iterable of findings."""
    from . import __version__

    findings = list(findings)
    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        rid = _rule_id(finding)
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            rules.append(_build_rule(finding))
        results.append(_build_result(finding, rule_index[rid]))

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": "https://github.com/cognis-digital/scopeward",
                        "version": tool_version or __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
