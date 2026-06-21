"""Command-line interface for scopeward.

Subcommands::

    scopeward sign   --scope s.json --key-env SW_KEY [--out signed.json]
    scopeward verify --scope s.json --key-env SW_KEY
    scopeward check  --scope s.json --key-env SW_KEY --module apkprobe \
                     --target android:com.example.app [--device ABC123] [--destructive]
    scopeward audit  --log evidence.jsonl          # verify hash chain

The signing key is read from an environment variable (``--key-env``, default
``SCOPEWARD_KEY``) so it never lands in shell history or the scope file.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from .scope import Scope, Target, ScopeError
from .signing import sign_scope, verify_scope, SignatureError
from .authz import Authorizer, ScopeViolation
from .evidence import EvidenceLog, EvidenceError


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
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(scope.to_dict(), handle, indent=2, sort_keys=True)
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


def cmd_check(args: argparse.Namespace) -> int:
    scope = Scope.load(args.scope)
    evidence = EvidenceLog(args.log, scope.engagement_id) if args.log else None
    try:
        authz = Authorizer(scope, _read_key(args.key_env), evidence=evidence)
        authz.authorize(
            args.module,
            target=_parse_target(args.target),
            device_id=args.device,
            destructive=args.destructive,
        )
    except ScopeViolation as exc:
        print(f"DENIED: {exc}")
        return 1
    print("AUTHORIZED")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    log = EvidenceLog(args.log)
    try:
        log.verify()
    except EvidenceError as exc:
        print(f"TAMPERED: {exc}")
        return 1
    count = sum(1 for _ in log)
    print(f"INTACT: {count} record(s), hash chain verified")
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

    p_check = sub.add_parser("check", help="check whether an action is authorized")
    p_check.add_argument("--scope", required=True)
    p_check.add_argument("--module", required=True)
    p_check.add_argument("--target")
    p_check.add_argument("--device")
    p_check.add_argument("--destructive", action="store_true")
    p_check.add_argument("--log", help="evidence log path (records the decision)")
    add_key(p_check)
    p_check.set_defaults(func=cmd_check)

    p_audit = sub.add_parser("audit", help="verify an evidence log hash chain")
    p_audit.add_argument("--log", required=True)
    p_audit.set_defaults(func=cmd_audit)

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
