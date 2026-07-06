# Reason codes

Every authorization decision carries a stable, machine-parseable `SW_*` reason
code alongside a human-readable message. **Codes are the contract**: downstream
tooling (CI gates, SIEM rules, dashboards) should branch on the code, never on
the English message. Messages may be reworded between releases; codes will not
change meaning. See the stability policy at the bottom.

Reproduce this table from a clone: `scopeward reasons` (or `scopeward reasons --json`).

| Code | Meaning |
|------|---------|
| `SW_ALLOWED` | Action is authorized by the signed scope. |
| `SW_SIGNATURE_INVALID` | Scope signature does not verify; the document may have been altered after authorization. |
| `SW_NOT_SIGNED` | Scope carries no signature and signatures are required. |
| `SW_WINDOW_INACTIVE` | Current time is outside the engagement window. |
| `SW_MODULE_NOT_ALLOWED` | Requested module is not in `allowed_modules`. |
| `SW_TARGET_UNAUTHORIZED` | Requested target app is not an authorized target. |
| `SW_DEVICE_UNAUTHORIZED` | Requested device is not an authorized device. |
| `SW_DESTRUCTIVE_FORBIDDEN` | A destructive action was requested but the engagement does not permit destructive operations. |
| `SW_REVOKED` | The grant, target, module or capability was revoked mid-engagement. |
| `SW_EXPIRED` | A per-grant or per-capability expiry has passed. |
| `SW_CAP_NOT_GRANTED` | The requested capability is not granted (directly or via a capability ladder) for this target. |

## Consuming codes

**Library** — the `Decision` on a raised `ScopeViolation`:

```python
from scopeward import Authorizer, ScopeViolation, ReasonCode

try:
    authz.authorize("apkprobe", target=t, capability="modify")
except ScopeViolation as exc:
    if exc.code == ReasonCode.EXPIRED:
        ...  # renew the grant
    log.warning("denied %s: %s", exc.code.value, exc)
```

`ReasonCode` subclasses `str`, so `exc.code == "SW_EXPIRED"` also works without
importing the enum.

**CLI** — codes appear in output and in the audit log:

```console
$ scopeward check --scope signed.json --module evil --target android:com.acme.app
DENIED [SW_MODULE_NOT_ALLOWED]: module 'evil' is not in allowed_modules for this engagement

$ scopeward check ... --json
{
  "allowed": false,
  "code": "SW_MODULE_NOT_ALLOWED",
  "message": "...",
  "detail": { "module": "evil", "allowed_modules": ["apkprobe", ...] }
}
```

Audit records for `authorized` / `denied` decisions carry the code under
`data.code`, so `scopeward audit --summary` tallies decisions by code.

## Stability policy

- A code's **string value never changes** once released.
- A code's **meaning never changes**. If a distinction is needed, a *new* code is
  added rather than repurposing an old one.
- New codes may be **added** in a minor release; consumers must treat unknown
  codes as a denial (fail-closed) if `allowed` is false.
- The `allowed` boolean is authoritative for the allow/deny decision; the code
  explains *why*.
