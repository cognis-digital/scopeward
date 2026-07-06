# scopeward architecture

scopeward answers one question, provably, before any mobile-security tool
touches a device:

> *Is this action authorized by a signed engagement scope — this target app,
> this device, this module, this capability, inside the agreed window and rules
> of engagement — and can we prove afterward exactly what was run?*

Everything in the package serves that sentence. It is standard-library only, so
it vendors cleanly into any tool in the suite (`apkprobe`, `ipaprobe`,
`hookbench`, …).

## Modules

| Module | Responsibility |
|--------|----------------|
| `scope.py` | The engagement model — client, ROE, window, targets, devices, allowed modules, capability **grants** and **revocations**. Canonical (signature-stable) serialization. |
| `signing.py` | Detached HMAC-SHA256 sign / verify over the scope's canonical bytes. |
| `grants.py` | The capability ladder (`read < instrument < modify < destructive`) and `Grant` — a scoped, optionally-expiring binding of capabilities to a target/module/device. |
| `revocation.py` | `Revocation` / `RevocationList` — subtractive, fail-closed withdrawal of a grant/target/module/device mid-engagement. |
| `reasons.py` | Stable machine-parseable `SW_*` reason codes and the structured `Decision` object every evaluation produces. |
| `authz.py` | `Authorizer` — the single fail-closed gate. Layered evaluation that returns a `Decision` and audits it. |
| `evidence.py` | Append-only JSONL audit log with a SHA-256 hash chain; verification, summary, findings extraction, export. |
| `findings.py` | `Finding` / `Severity` — the result schema shared across the suite, with MASVS/MASTG references. |
| `masvs.py` | OWASP MASVS v2 control-category lookups used to tag reports. |
| `schema.py` | A focused, stdlib-only JSON Schema (draft 2020-12) validator for the scope document. |
| `sarif.py` | SARIF 2.1.0 export of findings for GitHub code scanning and other tooling. |
| `cli.py` | `sign` / `verify` / `validate` / `check` / `audit` / `report` / `reasons`. |

## Data flow

```
  authorizing party                        test module / CI
  -----------------                        -----------------
  scope.json  ──sign(key)──►  signed scope  ──►  Authorizer(scope, key)
      │                            │                    │
      │                    verify_scope() ──────────────┤ (fail closed if bad)
      │                                                 │
      │                              authorize(module, target, device,
      │                                        capability, destructive)
      │                                                 │
      │                                          ┌──────▼───────┐
      │                                          │  evaluate()  │  Decision(code, …)
      │                                          └──────┬───────┘
      │                                                 │
      │                          EvidenceLog.record("authorized"|"denied", …)
      │                                                 │
      └────────────►  evidence.jsonl (hash-chained)  ◄──┘
                              │
                    audit / report (table | SARIF 2.1.0)
```

## Evaluation order (fail-closed, coarse → fine)

`Authorizer.evaluate` runs these gates in order and returns the **first**
failing `Decision`. The order is deliberate — cheap coarse checks first, and
revocation (subtractive) is checked before positive authorization so a
withdrawn item is denied even when otherwise in scope:

1. **Signature** (at construction) — `SW_NOT_SIGNED` / `SW_SIGNATURE_INVALID`.
2. **Window** — `SW_WINDOW_INACTIVE`.
3. **Module allow-list** — `SW_MODULE_NOT_ALLOWED`.
4. **Target allow-list** — `SW_TARGET_UNAUTHORIZED`.
5. **Device allow-list** — `SW_DEVICE_UNAUTHORIZED`.
6. **Revocation** — `SW_REVOKED`.
7. **Destructive gate** — `SW_DESTRUCTIVE_FORBIDDEN`.
8. **Capability ladder** (only if a capability was requested) — `SW_EXPIRED`,
   `SW_CAP_NOT_GRANTED`, or `SW_REVOKED` (revoked grant).

Success returns `SW_ALLOWED`. See [REASON_CODES.md](REASON_CODES.md).

## Threat model

scopeward is a guardrail for **authorized** work. The adversaries it defends
against are *scope creep* and *deniability*, not a remote attacker:

- **Silent scope widening.** A tester edits `scope.json` to add a target app or
  device, or to flip `allow_destructive`. → The scope is signed with a key held
  out of band by the authorizing party; any edit changes the canonical bytes and
  breaks verification, so the `Authorizer` refuses to construct. Grants and
  revocations are part of the signed document, so a revocation cannot be deleted
  to re-widen authorization.
- **Acting outside the window / after withdrawal.** → The window and the
  revocation list are enforced on every call, fail-closed.
- **Over-reach within an in-scope target.** A module authorized to `read`
  performs a `modify`. → Capability grants gate the *verb*, and higher rungs must
  be granted explicitly (the ladder only implies *downward*).
- **Tampering with the record of what was done.** Someone edits or deletes an
  audit line to hide an action. → The evidence log is an append-only SHA-256
  hash chain; mutating or removing any record breaks verification of every
  subsequent record.

Non-goals: scopeward is not a secrets manager (the key is provisioned out of
band), not a network control, and not a substitute for a written contract — it
makes the contract *machine-enforceable*.

## Why fail-closed

Every ambiguity refuses. An unsigned scope, an unparseable grant expiry, a
capability request without a target, a missing signature — all deny. The cost of
a false refusal in this domain (a blocked test) is trivially recoverable; the
cost of a false allow (an out-of-scope action against a system you were not
authorized to touch) is not. So the default is always "no".

## Backward compatibility

A v0.1.0 scope (no `grants`, no `revocations`) serializes byte-for-byte as
before: those keys are omitted from the canonical bytes when empty, so existing
signed scopes still verify under v0.2.0.
