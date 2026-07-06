"""Command-line interface for scopeward.

Subcommands::

    scopeward sign     --scope s.json --key-env SW_KEY [--out signed.json]
    scopeward verify   --scope s.json --key-env SW_KEY
    scopeward validate --scope s.json                 # JSON Schema structural check
    scopeward check    --scope s.json --key-env SW_KEY --module apkprobe \
                       --target android:com.example.app [--device D] \
                       [--capability instrument] [--destructive] [--json]
    scopeward audit    --log evidence.jsonl [--summary] [--export trail.json]
    scopeward report   --log evidence.jsonl --format sarif|table [--out out.sarif]
    scopeward reasons                                  # print the reason-code table

The signing key is read from an environment variable (``--key-env``, default
``SCOPEWARD_KEY``) so it never lands in shell history or the scope file.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional

from .scope import Scope, Target, ScopeError
from .signing import sign_scope, verify_scope, SignatureError
from .authz import Authorizer, ScopeViolation
from .evidence import EvidenceLog, EvidenceError
from .findings import Finding
from .reasons import ReasonCode, REASON_DESCRIPTIONS
from .schema import validate_document, load_schema
from .sarif import findings_to_sarif


def _read_key(key_env: str) -> str:
    key = os.environ.get(key_env)
    if not key:
        print(f"error: signing key not found in env var {key_env!r}", file=sys.stderr)
        raise SystemExit(2)
    return key


def _parse_target(value: Optional[str]) -> Optional[Target]:
    if not value:
        return None
    if ":" not in value:
        print(f"error: --target must be 'platform:app_id', got {value!r}", file=sys.stderr)
        raise SystemExit(2)
    platform, app_id = value.split(":", 1)
    return Target(platform=platform, app_id=app_id)


def cmd_sign(args: argparse.Namespace) -> int:
    scope = Scope.load(args.scope)
    sign_scope(scope, _read_key(args.key_env))
    out = args.out or args.scope
    Path(out).write_text(
        json.dumps(scope.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
    )
    print(f"signed scope written to {out}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    scope = Scope.load(args.scope)
    try:
        ok = verify_scope(scope, _read_key(args.key_env))
    except SignatureError as exc:
        print(f"INVALID: {exc}")
        return 1
    print("VALID" if ok else "INVALID: signature mismatch")
    return 0 if ok else 1


def cmd_validate(args: argparse.Namespace) -> int:
    schema = load_schema(args.schema) if args.schema else load_schema()
    try:
        data = json.loads(Path(args.scope).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"INVALID: not valid JSON: {exc}")
        return 1
    errors = validate_document(data, schema)
    if errors:
        print(f"INVALID: {len(errors)} schema violation(s):")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("VALID: scope document conforms to schema/scope.schema.json")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    scope = Scope.load(args.scope)
    evidence = EvidenceLog(args.log, scope.engagement_id) if args.log else None
    try:
        authz = Authorizer(scope, _read_key(args.key_env), evidence=evidence)
        decision = authz.authorize(
            args.module,
            target=_parse_target(args.target),
            device_id=args.device,
            destructive=args.destructive,
            capability=args.capability,
        )
    except ScopeViolation as exc:
        if args.json:
            print(json.dumps(exc.decision.to_dict(), indent=2))
        else:
            print(f"DENIED [{exc.code.value}]: {exc}")
        return 1
    if args.json:
        print(json.dumps(decision.to_dict(), indent=2))
    else:
        print(f"AUTHORIZED [{decision.code.value}]")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    log = EvidenceLog(args.log)
    try:
        log.verify()
    except EvidenceError as exc:
        print(f"TAMPERED: {exc}")
        return 1
    summary = log.summary()
    print(f"INTACT: {summary['total']} record(s), hash chain verified")
    if args.summary:
        print(json.dumps(summary, indent=2))
    if args.export:
        n = log.export(args.export)
        print(f"exported {n} record(s) to {args.export}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    log = EvidenceLog(args.log)
    findings = [Finding.from_dict(d) for d in log.findings()]
    if args.format == "sarif":
        doc = findings_to_sarif(findings)
        text = json.dumps(doc, indent=2)
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
            print(f"wrote SARIF ({len(findings)} finding(s)) to {args.out}")
        else:
            print(text)
        return 0
    # table
    if not findings:
        print("no findings in evidence log")
        return 0
    rows = [
        (f.severity.name, f.target, f.masvs or "-", f.title)
        for f in sorted(findings, key=lambda x: x.severity, reverse=True)
    ]
    widths = [max(len(str(r[i])) for r in rows + [("SEVERITY", "TARGET", "MASVS", "TITLE")]) for i in range(4)]
    header = ("SEVERITY", "TARGET", "MASVS", "TITLE")
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(header))
    print(line)
    print("  ".join("-" * widths[i] for i in range(4)))
    for r in rows:
        print("  ".join(str(r[i]).ljust(widths[i]) for i in range(4)))
    return 0


def cmd_reasons(args: argparse.Namespace) -> int:
    if args.json:
        print(json.dumps(REASON_DESCRIPTIONS, indent=2))
        return 0
    width = max(len(c) for c in REASON_DESCRIPTIONS)
    for code in ReasonCode:
        print(f"{code.value.ljust(width)}  {REASON_DESCRIPTIONS[code.value]}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scopeward", description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="store_true", help="print version and exit")
    sub = parser.add_subparsers(dest="command")

    def add_key(p: argparse.ArgumentParser) -> None:
        p.add_argument("--key-env", default="SCOPEWARD_KEY", help="env var holding the signing key")

    p_sign = sub.add_parser("sign", help="sign a scope document")
    p_sign.add_argument("--scope", required=True)
    p_sign.add_argument("--out")
    add_key(p_sign)
    p_sign.set_defaults(func=cmd_sign)

    p_verify = sub.add_parser("verify", help="verify a scope signature")
    p_verify.add_argument("--scope", required=True)
    add_key(p_verify)
    p_verify.set_defaults(func=cmd_verify)

    p_validate = sub.add_parser("validate", help="validate scope structure against the JSON Schema")
    p_validate.add_argument("--scope", required=True)
    p_validate.add_argument("--schema", help="override schema path (defaults to packaged schema)")
    p_validate.set_defaults(func=cmd_validate)

    p_check = sub.add_parser("check", help="check whether an action is authorized")
    p_check.add_argument("--scope", required=True)
    p_check.add_argument("--module", required=True)
    p_check.add_argument("--target")
    p_check.add_argument("--device")
    p_check.add_argument("--capability", help="requested capability: read|instrument|modify|destructive")
    p_check.add_argument("--destructive", action="store_true")
    p_check.add_argument("--log", help="evidence log path (records the decision)")
    p_check.add_argument("--json", action="store_true", help="emit the structured decision as JSON")
    add_key(p_check)
    p_check.set_defaults(func=cmd_check)

    p_audit = sub.add_parser("audit", help="verify an evidence log hash chain")
    p_audit.add_argument("--log", required=True)
    p_audit.add_argument("--summary", action="store_true", help="print a JSON summary of the trail")
    p_audit.add_argument("--export", help="export the full trail as a JSON array to this path")
    p_audit.set_defaults(func=cmd_audit)

    p_report = sub.add_parser("report", help="export findings from an evidence log")
    p_report.add_argument("--log", required=True)
    p_report.add_argument("--format", choices=["sarif", "table"], default="table")
    p_report.add_argument("--out", help="write output to a file instead of stdout")
    p_report.set_defaults(func=cmd_report)

    p_reasons = sub.add_parser("reasons", help="print the stable reason-code table")
    p_reasons.add_argument("--json", action="store_true")
    p_reasons.set_defaults(func=cmd_reasons)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "version", False):
        from . import __version__

        print(__version__)
        return 0
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    try:
        return args.func(args)
    except (ScopeError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
