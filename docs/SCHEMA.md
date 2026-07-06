# Scope document schema

A scope is a small JSON document. Its structure is defined by
[`schema/scope.schema.json`](../schema/scope.schema.json) — a real JSON Schema
(draft 2020-12). scopeward validates against it with a focused, **stdlib-only**
validator (`scopeward/schema.py`); there is no third-party runtime dependency.

Validate a document:

```console
$ scopeward validate --scope engagement.json
VALID: scope document conforms to schema/scope.schema.json
```

Invalid documents are rejected with a located reason:

```console
$ scopeward validate --scope broken.json
INVALID: 2 schema violation(s):
  - client: required property is missing
  - targets/0/platform: value 'windows' not in enum ['android', 'ios']
```

## Fields

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `engagement_id` | string | yes | Stable engagement identifier. |
| `client` | string | yes | Authorizing organization. |
| `authorized_by` | string | yes | Named individual who authorized the work. |
| `roe` | string | yes | Rules of engagement (human-readable). |
| `not_before` | date-time | yes | ISO-8601 start of the window. |
| `not_after` | date-time | yes | ISO-8601 end of the window. |
| `targets` | array (≥1) | yes | `{platform: android\|ios, app_id}`. |
| `devices` | array | no | `{device_id, label?}`. |
| `allowed_modules` | array (≥1) | yes | Module names permitted to run. |
| `allow_destructive` | boolean | no | Whether destructive ops are permitted at all. |
| `grants` | array | no | Capability grants — see [ARCHITECTURE.md](ARCHITECTURE.md). |
| `revocations` | array | no | Mid-engagement withdrawals. |
| `signature` | string | no | Hex HMAC-SHA256 (64 chars), added by `sign`. |

`additionalProperties` is `false` everywhere: an unrecognized key is a
validation error, so a typo (or a smuggled field) cannot silently pass.

## Grant object

```json
{
  "grant_id": "G-IOS",
  "target": "ios:com.acme.AcmeApp",
  "capabilities": ["modify"],
  "module": "hookbench",
  "device_id": "PIXEL8-ABC123",
  "expires": "2026-07-01T00:00:00Z",
  "note": "hookbench may modify the iOS app"
}
```

`capabilities` are drawn from the ladder `read | instrument | modify |
destructive`; a higher rung implies the lower ones. `module`/`device_id`
narrow the grant (omit for a wildcard). `expires` is stricter than the
engagement window.

## Revocation object

```json
{ "kind": "target", "value": "android:com.acme.app", "reason": "client withdrew consent", "at": "2026-06-25T14:00:00Z" }
```

`kind` is one of `grant | target | module | device`. Revocations are
subtractive and fail-closed, and are part of the signed document so they cannot
be deleted to re-widen authorization.

## Validator scope

`scopeward/schema.py` implements exactly the keywords this schema uses:
`type`, `required`, `properties`, `additionalProperties` (bool), `items`,
`enum`, `minItems`, `minLength`, `pattern`, and `format: date-time`. It is not a
general-purpose validator — unimplemented keywords are ignored — which is honest
and sufficient because scopeward controls the schema.
