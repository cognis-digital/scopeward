# SARIF export

scopeward exports findings as **SARIF 2.1.0** (OASIS Standard) — the format
GitHub code scanning, Azure DevOps and most review tooling ingest. Findings are
read back out of the evidence log, so the SARIF you publish is exactly what was
recorded during the engagement.

```console
$ scopeward report --log evidence.jsonl --format sarif --out scopeward.sarif
wrote SARIF (3 finding(s)) to scopeward.sarif
```

A human-readable table is also available:

```console
$ scopeward report --log evidence.jsonl --format table
SEVERITY  TARGET               MASVS            TITLE
--------  -------------------  ---------------  -----------------------
CRITICAL  android:com.acme.app  MASVS-CRYPTO-1   Hardcoded API key
HIGH      android:com.acme.app  MASVS-NETWORK-1  Cleartext traffic permitted
MEDIUM    android:com.acme.app  MASVS-RESILIENCE-2  Debuggable flag set
```

## Mapping

| scopeward | SARIF |
|-----------|-------|
| Distinct MASVS control (e.g. `MASVS-NETWORK-1`) | one **rule** (deduplicated), tagged with the MASVS category and linked to the MASVS/MASTG docs via `helpUri`. |
| A finding with no MASVS id | a rule `scopeward/<module>`. |
| `Finding.target` (`android:com.acme.app`) | a **logical location** (`fullyQualifiedName`). |
| `Finding.fingerprint` | `partialFingerprints["scopewardFingerprint/v1"]` for result matching across runs. |

## Severity → level

| Severity | SARIF `level` | `security-severity` |
|----------|---------------|---------------------|
| `CRITICAL` | `error` | 9.5 |
| `HIGH` | `error` | 8.0 |
| `MEDIUM` | `warning` | 5.5 |
| `LOW` | `note` | 2.0 |
| `INFO` | `note` | 0.0 |

The numeric `security-severity` property is what GitHub uses to sort and
threshold results.

## Publishing to GitHub code scanning

```yaml
- run: scopeward report --log evidence.jsonl --format sarif --out scopeward.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: scopeward.sarif
```
