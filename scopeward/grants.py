"""Capability ladders and scoped, expiring grants.

A *capability* is a verb of increasing power. scopeward ships a canonical
ladder — ``read < instrument < modify < destructive`` — where a grant of a
higher rung *implies* every lower rung. Granting ``modify`` on a target implies
``read`` and ``instrument`` on it; it does not imply ``destructive``.

A :class:`Grant` binds a set of capabilities to a specific target (and,
optionally, a module and device), with an optional per-grant expiry that is
*independent of and stricter than* the engagement window. This lets an
authorizing party say "you may ``instrument`` com.acme.app until Tuesday, but
``read`` only for the rest of the window" without reissuing the whole scope.

Everything here is a plain dataclass, stdlib-serializable, and folds into the
signed scope's canonical bytes so grants cannot be widened after signing.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .scope import ScopeError, _parse_ts


class Capability(str, enum.Enum):
    """The canonical capability ladder, ordered least → most powerful."""

    READ = "read"
    INSTRUMENT = "instrument"
    MODIFY = "modify"
    DESTRUCTIVE = "destructive"

    @property
    def rank(self) -> int:
        return _LADDER.index(self)

    def implies(self, other: "Capability") -> bool:
        """True if holding ``self`` grants ``other`` (equal or lower rung)."""
        return self.rank >= other.rank

    @classmethod
    def parse(cls, value: "str | Capability") -> "Capability":
        if isinstance(value, Capability):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:
            raise ScopeError(
                f"unknown capability {value!r}; expected one of "
                f"{[c.value for c in cls]}"
            ) from exc


#: Ordering used by :attr:`Capability.rank`. Index == rung.
_LADDER: list[Capability] = [
    Capability.READ,
    Capability.INSTRUMENT,
    Capability.MODIFY,
    Capability.DESTRUCTIVE,
]


def expand_capabilities(caps: "list[Capability | str]") -> set[Capability]:
    """Expand each capability down the ladder to the full implied set.

    ``[MODIFY]`` → ``{READ, INSTRUMENT, MODIFY}``. Idempotent; order-free.
    """
    out: set[Capability] = set()
    for raw in caps:
        cap = Capability.parse(raw)
        for lower in _LADDER[: cap.rank + 1]:
            out.add(lower)
    return out


@dataclass
class Grant:
    """A scoped, optionally-expiring capability grant.

    ``target`` is a ``platform:app_id`` key (the same string
    :attr:`scopeward.scope.Target.key` produces). ``capabilities`` lists the
    top rungs granted; lower rungs are implied via the ladder. ``module`` and
    ``device_id`` optionally narrow the grant. ``expires`` is an ISO-8601
    instant after which the grant is dead regardless of the engagement window.
    ``grant_id`` is a stable handle used by the revocation list.
    """

    grant_id: str
    target: str
    capabilities: list[str] = field(default_factory=list)
    module: Optional[str] = None
    device_id: Optional[str] = None
    expires: Optional[str] = None
    note: str = ""

    def __post_init__(self) -> None:
        if not self.grant_id:
            raise ScopeError("grant_id is required and must be non-empty")
        if not self.target:
            raise ScopeError("grant target is required and must be non-empty")
        if not self.capabilities:
            raise ScopeError(f"grant {self.grant_id!r} lists no capabilities")
        # Validate + normalize capability spellings eagerly (fail closed at load).
        self.capabilities = [Capability.parse(c).value for c in self.capabilities]
        if self.expires is not None:
            # Validate parseability now so a bad expiry is caught at load, not at gate time.
            _parse_ts(self.expires, f"grant[{self.grant_id}].expires")

    # ----- queries ------------------------------------------------------
    def effective_capabilities(self) -> set[Capability]:
        """The full implied capability set (ladder-expanded)."""
        return expand_capabilities(self.capabilities)

    def grants(self, cap: "Capability | str") -> bool:
        """True if this grant confers ``cap`` (directly or via the ladder)."""
        return Capability.parse(cap) in self.effective_capabilities()

    def expiry_dt(self) -> Optional[datetime]:
        if self.expires is None:
            return None
        return _parse_ts(self.expires, f"grant[{self.grant_id}].expires")

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        exp = self.expiry_dt()
        if exp is None:
            return False
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        return now > exp

    def matches(
        self,
        *,
        target: str,
        module: Optional[str],
        device_id: Optional[str],
    ) -> bool:
        """True if this grant applies to the given (target, module, device).

        A ``None`` narrowing field on the grant is a wildcard; a set field must
        match exactly. A ``None`` request field only matches a wildcard grant
        field.
        """
        if self.target != target:
            return False
        if self.module is not None and self.module != module:
            return False
        if self.device_id is not None and self.device_id != device_id:
            return False
        return True

    # ----- serialization ------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "grant_id": self.grant_id,
            "target": self.target,
            "capabilities": list(self.capabilities),
        }
        if self.module is not None:
            data["module"] = self.module
        if self.device_id is not None:
            data["device_id"] = self.device_id
        if self.expires is not None:
            data["expires"] = self.expires
        if self.note:
            data["note"] = self.note
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Grant":
        if not isinstance(data, dict):
            raise ScopeError("grant entry must be a JSON object")
        return cls(
            grant_id=data.get("grant_id", ""),
            target=data.get("target", ""),
            capabilities=list(data.get("capabilities", [])),
            module=data.get("module"),
            device_id=data.get("device_id"),
            expires=data.get("expires"),
            note=data.get("note", ""),
        )
