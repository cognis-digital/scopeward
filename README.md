# scopeward

**A signed-scope authorization keystone for authorized mobile security testing.**

`scopeward` is the consent layer of a mobile penetration-testing toolkit. It
exists to answer one question, the same way every time, before any tool touches
a device:

> *Is this action authorized by a signed engagement scope — this target app,
> this device, this module, this capability, inside the agreed window and rules
> of engagement — and can we prove afterward exactly what was run?*

If the answer is no, the action is refused **fail-closed** with a stable reason
code. If yes, the decision is written to a **tamper-evident audit log**. This is
what separates an *authorized assessment* from poking at apps you have no
permission to test, and it is a hard prerequisite for every other tool in the
suite (`apkprobe`, `ipaprobe`, `hookbench`, …) — they will not run a module
unless `scopeward` says the engagement covers it.

`scopeward` is **standard-library only** — no third-party runtime
dependencies — so it vendors cleanly into any tool.

- **Signed scope** — HMAC-SHA256 over canonical bytes; a scope cannot be widened after it is signed.
- **Capability ladder** — `read < instrument < modify < destructive`; higher rungs imply lower, never the reverse.
- **Scoped, expiring grants** — bind capabilities to a target/module/device with a per-grant expiry stricter than the window.
- **Mid-engagement revocation** — withdraw a grant/target/module/device; a revoked item is denied even if otherwise in scope.
- **Stable reason codes** — every decision carries a machine-parseable `SW_*` code (see [docs/REASON_CODES.md](docs/REASON_CODES.md)).
- **Tamper-evident audit** — append-only JSONL with a SHA-256 hash chain; any edit or deletion is caught.
- **JSON Schema** — a real draft-2020-12 schema plus a stdlib validator (`scopeward validate`).
- **SARIF 2.1.0 export** — publish findings to GitHub code scanning (`scopeward report --format sarif`), MASVS-tagged.

Measured, reproducible from a clone: **155 tests passing**, **9 runnable
demos**, runs fully offline, zero third-party runtime dependencies.

<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output — runs offline. Sign the example scope, verify it,
gate some actions, then audit the trail:

```console
$ scopeward validate --scope engagement.json
VALID: scope document conforms to schema/scope.schema.json

$ scopeward sign --scope engagement.json --out signed.json
signed scope written to signed.json

$ scopeward verify --scope signed.json
VALID

$ scopeward check --scope signed.json --module apkprobe --target android:com.acme.app --log evidence.jsonl
AUTHORIZED [SW_ALLOWED]

$ scopeward check --scope signed.json --module hookbench --target ios:com.acme.AcmeApp --capability modify --log evidence.jsonl
AUTHORIZED [SW_ALLOWED]

$ scopeward check --scope signed.json --module apkprobe --target android:com.someoneelse.app
DENIED [SW_TARGET_UNAUTHORIZED]: target 'android:com.someoneelse.app' is not an authorized target app

$ scopeward audit --log evidence.jsonl --summary
INTACT: 2 record(s), hash chain verified
{
  "total": 2,
  "by_kind": { "authorized": 2 },
  "by_code": { "SW_ALLOWED": 2 },
  "first_ts": "2026-...T...Z",
  "last_ts": "2026-...T...Z",
  "engagement_ids": ["ENG-2026-001"]
}
```

Or run the guided tour — nine standalone demos, offline, exits 0:

```console
$ python demos/run_all.py
...
ALL 9 DEMOS PASSED
```

<!-- cognis:example:end -->

## Why a signed scope

A penetration test is defined by a contract: which apps, which devices, what
dates, what you may and may not do. `scopeward` makes that contract
machine-enforceable.

- The scope is a small JSON document (`examples/engagement.example.json`),
  validated against a real JSON Schema ([docs/SCHEMA.md](docs/SCHEMA.md)).
- It is signed with **HMAC-SHA256** using an engagement key provisioned out of
  band. The key never appears in the document.
- Any edit after signing — sneaking in an extra target, flipping
  `allow_destructive`, or deleting a revocation — breaks verification, and the
  engagement halts. You cannot quietly widen your own authorization.

## Install

`scopeward` has no runtime dependencies. Python 3.10+.

**Linux / macOS**

```bash
./install.sh            # pip install -e . into the current environment
```

**Windows (PowerShell)**

```powershell
.\install.ps1
```

**Any platform (manual)**

```bash
pip install -e .          # or: pip install -e ".[dev]" for tests
# or, with make:
make install              # make dev  → editable + test deps
```

**Docker**

```bash
docker build -t scopeward .
docker run --rm scopeward --version
```

The `scopeward` console command is installed via `[project.scripts]`.

## CLI

The signing key is read from an environment variable so it never lands in shell
history or the scope file.

```bash
export SCOPEWARD_KEY="...engagement key..."

scopeward validate --scope engagement.json       # structural check vs JSON Schema
scopeward sign     --scope engagement.json --out signed.json
scopeward verify   --scope signed.json           # -> VALID

# Gate an action — every tool calls this before acting:
scopeward check    --scope signed.json --module apkprobe \
                   --target android:com.acme.app \
                   --capability instrument --log evidence.jsonl
# -> AUTHORIZED [SW_ALLOWED]   (and a record is appended)

# Verify the audit trail wasn't altered, with a summary:
scopeward audit    --log evidence.jsonl --summary

# Export findings for GitHub code scanning:
scopeward report   --log evidence.jsonl --format sarif --out scopeward.sarif

# The stable reason-code table:
scopeward reasons
```

Full subcommand list: `sign`, `verify`, `validate`, `check`, `audit`,
`report`, `reasons`.

## Library

```python
from scopeward import (
    Scope, sign_scope, Authorizer, ScopeViolation,
    EvidenceLog, Target, Finding, ReasonCode,
)

scope = Scope.load("signed.json")
log   = EvidenceLog("evidence.jsonl", scope.engagement_id)
authz = Authorizer(scope, key=KEY, evidence=log)   # raises if signature is bad

# Before doing anything, gate on module + target + capability:
try:
    decision = authz.authorize(
        "hookbench", target=Target("ios", "com.acme.AcmeApp"), capability="modify"
    )
    # decision.allowed is True; decision.code == ReasonCode.ALLOWED
except ScopeViolation as exc:
    if exc.code == ReasonCode.EXPIRED:
        ...  # the grant lapsed — renew it, don't proceed

# Emit results in the shared schema; they flow straight into SARIF:
log.record("finding", Finding(
    title="Cleartext traffic permitted",
    severity="high",
    target="android:com.acme.app",
    masvs="MASVS-NETWORK-1",
    mastg_test="MASTG-TEST-0019",
    evidence='android:usesCleartextTraffic="true"',
).to_dict())
```

## Capability ladder & grants

Grants bind capabilities to a target (and optionally a module/device) with an
optional expiry. The ladder is `read < instrument < modify < destructive`;
granting a rung implies every rung below it, and *never* a rung above.

```json
{
  "grants": [
    { "grant_id": "G-ANDROID", "target": "android:com.acme.app", "capabilities": ["instrument"] },
    { "grant_id": "G-IOS", "target": "ios:com.acme.AcmeApp", "capabilities": ["modify"],
      "module": "hookbench", "expires": "2026-07-01T00:00:00Z" }
  ],
  "revocations": [
    { "kind": "target", "value": "android:com.acme.app", "reason": "client withdrew consent" }
  ]
}
```

Because grants and revocations are part of the signed document, a tester cannot
delete a revocation or add a grant without breaking the signature.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — modules, data flow, evaluation order, threat model, why fail-closed.
- [docs/REASON_CODES.md](docs/REASON_CODES.md) — the stable `SW_*` code table and stability policy.
- [docs/SCHEMA.md](docs/SCHEMA.md) — the scope document schema and validator.
- [docs/SARIF.md](docs/SARIF.md) — SARIF 2.1.0 export and severity mapping.

## What's inside

| Module | Responsibility |
|--------|----------------|
| `scope.py`      | Engagement model: targets, devices, window, ROE, grants, revocations; canonical (signature-stable) serialization. |
| `signing.py`    | Detached HMAC-SHA256 sign / verify. |
| `grants.py`     | Capability ladder + scoped, expiring `Grant`. |
| `revocation.py` | `Revocation` / `RevocationList` — subtractive, fail-closed withdrawal. |
| `reasons.py`    | Stable `SW_*` reason codes and the `Decision` object. |
| `authz.py`      | `Authorizer` — the single fail-closed gate. |
| `evidence.py`   | Append-only JSONL audit log with a SHA-256 hash chain; verify / summary / export. |
| `findings.py`   | `Finding` / `Severity` — shared result schema with MASVS/MASTG references. |
| `masvs.py`      | OWASP MASVS v2 control-category helpers. |
| `schema.py`     | Stdlib JSON Schema (draft 2020-12) validator. |
| `sarif.py`      | SARIF 2.1.0 export of findings. |

## Standards

- **OWASP MASVS v2 / MASTG** — findings carry MASVS control ids and MASTG test
  ids; SARIF rules are tagged and linked to the MASVS/MASTG documentation.
- **SARIF 2.1.0** (OASIS) — findings export ingests directly into GitHub code
  scanning and other review tooling.
- **JSON Schema draft 2020-12** — the scope document format.

## Scope of use

`scopeward` is built for **authorized** engagements — penetration tests with a
signed contract, internal security assessments of your own apps, lab work, and
CTF/training. It is a guardrail, not a weapon: its entire purpose is to make
sure a tool only ever acts where it has been given permission. Use it that way.

## License

Cognis Open Collaboration License (COCL) v1.0. See [LICENSE](LICENSE).
