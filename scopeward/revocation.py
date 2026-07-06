"""Mid-engagement revocation.

Some authorizations must be withdrawn *before* the engagement window closes: a
client pulls a target app out of scope, a device is repurposed, a whole grant is
cancelled after a scare. A :class:`Revocation` names exactly what is withdrawn;
a :class:`RevocationList` is the set consulted by the gate.

Revocation is **subtractive and fail-closed**: a revoked item is denied even if
the signed scope otherwise permits it. Revocations are part of the signed scope
document (so they cannot be silently deleted to re-widen authorization) and are
also emitted to the evidence log when applied, making the withdrawal auditable.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Optional

from .scope import ScopeError


class RevocationKind(str, enum.Enum):
    """What a revocation targets."""

    GRANT = "grant"      # a specific grant_id
    TARGET = "target"    # a platform:app_id key
    MODULE = "module"    # a module name
    DEVICE = "device"    # a device_id

    @classmethod
    def parse(cls, value: "str | RevocationKind") -> "RevocationKind":
        if isinstance(value, RevocationKind):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:
            raise ScopeError(
                f"unknown revocation kind {value!r}; expected one of "
                f"{[k.value for k in cls]}"
            ) from exc


@dataclass(frozen=True)
class Revocation:
    """A single withdrawal of authorization."""

    kind: RevocationKind
    value: str
    reason: str = ""
    at: str = ""  # ISO-8601 instant the revocation was issued (informational)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", RevocationKind.parse(self.kind))
        if not self.value:
            raise ScopeError("revocation value is required and must be non-empty")

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"kind": self.kind.value, "value": self.value}
        if self.reason:
            data["reason"] = self.reason
        if self.at:
            data["at"] = self.at
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Revocation":
        if not isinstance(data, dict):
            raise ScopeError("revocation entry must be a JSON object")
        return cls(
            kind=data.get("kind", ""),
            value=data.get("value", ""),
            reason=data.get("reason", ""),
            at=data.get("at", ""),
        )


@dataclass
class RevocationList:
    """A queryable collection of revocations."""

    entries: list[Revocation] = field(default_factory=list)

    def add(self, revocation: Revocation) -> None:
        self.entries.append(revocation)

    def _values(self, kind: RevocationKind) -> set[str]:
        return {r.value for r in self.entries if r.kind == kind}

    def is_grant_revoked(self, grant_id: str) -> bool:
        return grant_id in self._values(RevocationKind.GRANT)

    def is_target_revoked(self, target_key: str) -> bool:
        return target_key in self._values(RevocationKind.TARGET)

    def is_module_revoked(self, module: str) -> bool:
        return module in self._values(RevocationKind.MODULE)

    def is_device_revoked(self, device_id: str) -> bool:
        return device_id in self._values(RevocationKind.DEVICE)

    def find(self, kind: RevocationKind, value: str) -> Optional[Revocation]:
        """Return the first matching revocation (for its reason/timestamp)."""
        for r in self.entries:
            if r.kind == kind and r.value == value:
                return r
        return None

    # ----- serialization ------------------------------------------------
    def to_list(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self.entries]

    @classmethod
    def from_list(cls, data: Any) -> "RevocationList":
        if data is None:
            return cls()
        if not isinstance(data, list):
            raise ScopeError("revocations must be a JSON array")
        return cls(entries=[Revocation.from_dict(d) for d in data])

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self.entries)

    def __iter__(self):  # pragma: no cover - trivial
        return iter(self.entries)
