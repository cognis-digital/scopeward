"""Shared helpers for the scopeward demos.

Each demo is a standalone script that builds an in-memory engagement, exercises
one facet of scopeward, prints clear output, and exits 0 on success. Nothing
here touches the network or external services.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Make the repo importable when run as `python demos/xyz.py` from anywhere.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scopeward.scope import Scope, Target, Device  # noqa: E402
from scopeward.grants import Grant  # noqa: E402
from scopeward.signing import sign_scope  # noqa: E402

KEY = "demo-engagement-key"

ANDROID = Target("android", "com.acme.app")
IOS = Target("ios", "com.acme.AcmeApp")


def now() -> datetime:
    return datetime.now(timezone.utc)


def build_scope(*, with_grants: bool = True) -> Scope:
    """A realistic, currently-active engagement scope."""
    grants = []
    if with_grants:
        grants = [
            Grant("G-ANDROID", ANDROID.key, ["instrument"],
                  note="read + instrument the Android app"),
            Grant("G-IOS", IOS.key, ["modify"], module="hookbench",
                  note="hookbench may modify the iOS app"),
        ]
    return Scope(
        engagement_id="ENG-DEMO-001",
        client="Acme Corp",
        authorized_by="jane.security@acme.example",
        roe="Authorized assessment of Acme mobile apps. Lab devices only.",
        not_before=now() - timedelta(days=1),
        not_after=now() + timedelta(days=7),
        targets=[ANDROID, IOS],
        devices=[Device("PIXEL8-ABC123", "lab pixel 8")],
        allowed_modules=["apkprobe", "ipaprobe", "hookbench"],
        allow_destructive=False,
        grants=grants,
    )


def signed_scope(**kwargs) -> Scope:
    return sign_scope(build_scope(**kwargs), KEY)


def hr(title: str) -> None:
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)
