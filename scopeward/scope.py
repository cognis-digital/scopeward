"""Engagement scope model and canonical serialization.

A :class:`Scope` is the machine-readable authorization for a single engagement.
It is loaded from JSON, validated, and (after signing) becomes the gate that
every test module consults before acting.

Canonicalization matters: the signature in :mod:`scopeward.signing` is computed
over :meth:`Scope.canonical_bytes`, so two scopes that are semantically equal
must serialize byte-for-byte identically regardless of key ordering in the
source file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Iterable


class ScopeError(ValueError):
    """Raised when a scope document is structurally invalid."""


def _parse_ts(value: str, fieldname: str) -> datetime:
    """Parse an ISO-8601 timestamp, normalizing to timezone-aware UTC."""
    if not isinstance(value, str):
        raise ScopeError(f"{fieldname} must be an ISO-8601 string")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:  # pragma: no cover - message passthrough
        raise ScopeError(f"{fieldname} is not a valid ISO-8601 timestamp: {value}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class Target:
    """An app authorized for testing.

    ``platform`` is ``android`` or ``ios``; ``app_id`` is the Android package
    name (``com.example.app``) or the iOS bundle identifier.
    """

    platform: str
    app_id: str

    def __post_init__(self) -> None:
        if self.platform not in ("android", "ios"):
            raise ScopeError(f"target platform must be 'android' or 'ios', got {self.platform!r}")
        if not self.app_id or not isinstance(self.app_id, str):
            raise ScopeError("target app_id must be a non-empty string")

    @property
    def key(self) -> str:
        return f"{self.platform}:{self.app_id}"


@dataclass(frozen=True)
class Device:
    """A device authorized for testing, identified by serial/UDID."""

    device_id: str
    label: str = ""

    def __post_init__(self) -> None:
        if not self.device_id or not isinstance(self.device_id, str):
            raise ScopeError("device_id must be a non-empty string")


@dataclass
class Scope:
    """A signed-or-unsigned engagement authorization.

    The ``signature`` field is excluded from canonical bytes so that the
    document can carry its own signature without invalidating it.
    """

    engagement_id: str
    client: str
    authorized_by: str
    roe: str
    not_before: datetime
    not_after: datetime
    targets: list[Target] = field(default_factory=list)
    devices: list[Device] = field(default_factory=list)
    allowed_modules: list[str] = field(default_factory=list)
    allow_destructive: bool = False
    grants: list[Any] = field(default_factory=list)          # list[grants.Grant]
    revocations: Any = None                                    # revocation.RevocationList | None
    signature: str | None = None

    # ----- construction -------------------------------------------------
    def __post_init__(self) -> None:
        for fld in ("engagement_id", "client", "authorized_by", "roe"):
            if not getattr(self, fld):
                raise ScopeError(f"scope field '{fld}' is required and must be non-empty")
        if self.not_after <= self.not_before:
            raise ScopeError("not_after must be later than not_before")
        if not self.targets:
            raise ScopeError("scope must authorize at least one target app")
        if not self.allowed_modules:
            raise ScopeError("scope must list at least one allowed module")
        # Normalize revocations so direct construction and from_dict agree.
        if self.revocations is None:
            from .revocation import RevocationList
            self.revocations = RevocationList()
        # Every grant must reference a target that this scope actually authorizes.
        known = self.target_keys()
        for grant in self.grants:
            if grant.target not in known:
                raise ScopeError(
                    f"grant {grant.grant_id!r} references target {grant.target!r} "
                    "which is not an authorized target of this scope"
                )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Scope":
        # Local imports avoid a circular dependency: grants/revocation import
        # helpers from this module.
        from .grants import Grant
        from .revocation import RevocationList

        if not isinstance(data, dict):
            raise ScopeError("scope document must be a JSON object")
        try:
            targets = [Target(**t) if isinstance(t, dict) else _bad_target(t) for t in data.get("targets", [])]
            devices = [Device(**d) if isinstance(d, dict) else _bad_device(d) for d in data.get("devices", [])]
        except TypeError as exc:
            raise ScopeError(f"malformed target/device entry: {exc}") from exc
        grants = [Grant.from_dict(g) for g in data.get("grants", [])]
        revocations = RevocationList.from_list(data.get("revocations"))
        return cls(
            engagement_id=data.get("engagement_id", ""),
            client=data.get("client", ""),
            authorized_by=data.get("authorized_by", ""),
            roe=data.get("roe", ""),
            not_before=_parse_ts(data.get("not_before", ""), "not_before"),
            not_after=_parse_ts(data.get("not_after", ""), "not_after"),
            targets=targets,
            devices=devices,
            allowed_modules=list(data.get("allowed_modules", [])),
            allow_destructive=bool(data.get("allow_destructive", False)),
            grants=grants,
            revocations=revocations,
            signature=data.get("signature"),
        )

    @classmethod
    def load(cls, path: str) -> "Scope":
        with open(path, "r", encoding="utf-8") as handle:
            return cls.from_dict(json.load(handle))

    # ----- serialization ------------------------------------------------
    def to_dict(self, include_signature: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "engagement_id": self.engagement_id,
            "client": self.client,
            "authorized_by": self.authorized_by,
            "roe": self.roe,
            "not_before": self.not_before.astimezone(timezone.utc).isoformat(),
            "not_after": self.not_after.astimezone(timezone.utc).isoformat(),
            "targets": [asdict(t) for t in self.targets],
            "devices": [asdict(d) for d in self.devices],
            "allowed_modules": list(self.allowed_modules),
            "allow_destructive": self.allow_destructive,
        }
        # Emit grants/revocations only when present so scopes that use neither
        # serialize (and therefore sign/verify) byte-identically to v0.1.0.
        if self.grants:
            data["grants"] = [g.to_dict() for g in self.grants]
        if self.revocations is not None and len(self.revocations) > 0:
            data["revocations"] = self.revocations.to_list()
        if include_signature and self.signature is not None:
            data["signature"] = self.signature
        return data

    def canonical_bytes(self) -> bytes:
        """Deterministic byte representation used for signing (excludes signature)."""
        payload = self.to_dict(include_signature=False)
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # ----- queries ------------------------------------------------------
    def target_keys(self) -> set[str]:
        return {t.key for t in self.targets}

    def device_ids(self) -> set[str]:
        return {d.device_id for d in self.devices}

    def is_active(self, now: datetime | None = None) -> bool:
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        return self.not_before <= now <= self.not_after

    def grants_for(
        self,
        *,
        target: str,
        module: str | None = None,
        device_id: str | None = None,
    ) -> list[Any]:
        """Grants that apply to the given (target, module, device) tuple."""
        return [
            g for g in self.grants
            if g.matches(target=target, module=module, device_id=device_id)
        ]

    def uses_capabilities(self) -> bool:
        """True if this scope declares any capability grants (ladder mode)."""
        return bool(self.grants)


def _bad_target(value: Any) -> Target:  # pragma: no cover - defensive
    raise ScopeError(f"target entry must be an object, got {type(value).__name__}")


def _bad_device(value: Any) -> Device:  # pragma: no cover - defensive
    raise ScopeError(f"device entry must be an object, got {type(value).__name__}")
