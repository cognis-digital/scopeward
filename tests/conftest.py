"""Shared fixtures: a known-good signed scope and a key."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from scopeward.scope import Scope, Target, Device
from scopeward.signing import sign_scope

KEY = "test-engagement-key-do-not-reuse"


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 6, 20, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def scope(now: datetime) -> Scope:
    return Scope(
        engagement_id="ENG-2026-001",
        client="Acme Corp",
        authorized_by="jane.security@acme.example",
        roe="No production data exfiltration; testing window 09:00-17:00 UTC.",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=7),
        targets=[Target("android", "com.acme.app"), Target("ios", "com.acme.AcmeApp")],
        devices=[Device("PIXEL8-ABC123", "lab pixel 8")],
        allowed_modules=["apkprobe", "ipaprobe", "hookbench"],
        allow_destructive=False,
    )


@pytest.fixture
def signed_scope(scope: Scope) -> Scope:
    return sign_scope(scope, KEY)
