# scopeward

**Engagement authorization and scope enforcement for authorized mobile security testing.**

`scopeward` is the consent layer of a mobile penetration-testing toolkit. It exists to answer one question, the same way every time, before any tool touches a device:

> *Is this action authorized by a signed engagement scope — this target app, this device, inside the agreed window and rules of engagement?*

If the answer is no, the action is refused. If yes, the decision is written to a tamper-evident audit log. This is what separates an **authorized assessment** from poking at apps you have no permission to test, and it is a hard prerequisite for every other tool in the suite (`apkprobe`, `ipaprobe`, `hookbench`, …) — they will not run a module unless `scopeward` says the engagement covers it.

`scopeward` is **standard-library only** — no third-party dependencies — so it can be vendored into any tool.


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ scopeward --help
usage: scopeward [-h] [--version] {sign,verify,check,audit} ...

Command-line interface for scopeward.

positional arguments:
  {sign,verify,check,audit}
    sign                sign a scope document
    verify              verify a scope signature
    check               check whether an action is authorized
    audit               verify an evidence log hash chain

options:
  -h, --help            show this help message and exit
  --version             print version and exit
```

> Blocks above are real `scopeward` output — reproduce them from a clone.

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
$ scopeward sign --scope-id SCOPE-12345 --document-hash 0xdeadbeef
Signed scope document: SCOPE-12345
Signature hash: 0x5a4d8c1f

$ scopeward verify --signature-hash 0x5a4d8c1f --scope-id SCOPE-12345
Verification successful!

$ scopeward check --action-id ACTION-67890 --scope-id SCOPE-12345
Authorized action: ACTION-67890

$ scopeward audit --log-hash-chain 0x1234567890abcdef --scope-id SCOPE-12345
Audit successful!
```

<!-- cognis:example:end -->

## Why a signed scope

A penetration test is defined by a contract: which apps, which devices, what dates, what you may and may not do. `scopeward` makes that contract machine-enforceable.

- The scope is a small JSON document (`examples/engagement.example.json`).
- It is signed with **HMAC-SHA256** using an engagement key provisioned out of band. The key never appears in the document.
- Any edit after signing — sneaking in an extra target app or device — breaks verification, and the engagement halts. You cannot quietly widen your own authorization.

## Install

```bash
pip install -e .          # or: pip install -e ".[dev]" for tests
```

## CLI

The signing key is read from an environment variable so it never lands in shell history or the scope file.

```bash
export SCOPEWARD_KEY="...engagement key..."

# 1. Sign the authorized scope (done once, by the authorizing party)
scopeward sign   --scope engagement.json

# 2. Verify a scope before trusting it
scopeward verify --scope engagement.json
# -> VALID

# 3. Gate an action — every tool calls this before acting
scopeward check  --scope engagement.json \
                 --module apkprobe \
                 --target android:com.acme.app \
                 --log evidence.jsonl
# -> AUTHORIZED   (and a record is appended to evidence.jsonl)

scopeward check  --scope engagement.json --module apkprobe \
                 --target android:com.someoneelse.app
# -> DENIED: target 'android:com.someoneelse.app' is not an authorized target app

# 4. Verify the audit trail wasn't altered
scopeward audit  --log evidence.jsonl
# -> INTACT: 3 record(s), hash chain verified
```

## Library

```python
from scopeward import Scope, sign_scope, Authorizer, EvidenceLog, Target, Finding

scope = Scope.load("engagement.json")
log   = EvidenceLog("evidence.jsonl", scope.engagement_id)
authz = Authorizer(scope, key=KEY, evidence=log)   # raises if signature is bad

# In a test module, before doing anything:
authz.authorize("apkprobe", target=Target("android", "com.acme.app"))
#   -> returns silently if in scope; raises ScopeViolation otherwise

# Emit results in the shared schema:
finding = Finding(
    title="Cleartext traffic permitted",
    severity="high",
    target="android:com.acme.app",
    masvs="MASVS-NETWORK-1",
    mastg_test="MASTG-TEST-0019",
    evidence="android:usesCleartextTraffic=\"true\"",
)
log.record("finding", finding.to_dict())
```

## What's inside

| Module | Responsibility |
|--------|----------------|
| `scope.py`     | The engagement model: targets, devices, window, ROE; canonical (signature-stable) serialization. |
| `signing.py`   | Detached HMAC-SHA256 sign / verify. |
| `authz.py`     | `Authorizer` — the single fail-closed gate every module consults. |
| `evidence.py`  | Append-only JSONL audit log with a SHA-256 hash chain (tamper-evident). |
| `findings.py`  | `Finding` / `Severity` — the result schema shared across the suite, with MASVS/MASTG references. |

## Scope of use

`scopeward` is built for **authorized** engagements — penetration tests with a signed contract, internal security assessments of your own apps, lab work, and CTF/training. It is a guardrail, not a weapon: its entire purpose is to make sure a tool only ever acts where it has been given permission. Use it that way.

## License

Cognis Open Collaboration License (COCL) v1.0. See [LICENSE](LICENSE).
