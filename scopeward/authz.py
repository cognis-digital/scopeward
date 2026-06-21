"""The authorization gate.

:class:`Authorizer` wraps a verified :class:`~scopeward.scope.Scope` and is the
single chokepoint every test module calls before touching a target. A call to
:meth:`Authorizer.authorize` either returns silently (action permitted, and an
audit record is written) or raises :class:`ScopeViolation` (action refused).

Design intent: it should be *impossible* to run a module against an app or
device that the signed scope does not name, or outside the engagement window.
Fail closed — any ambiguity refuses.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .scope import Scope, Target
from .signing import verify_scope, SignatureError
from .evidence import EvidenceLog


class ScopeViolation(Exception):
    """Raised when a requested action falls outside the authorized scope."""


class Authorizer:
    """Gate actions against a signed, time-bounded engagement scope."""

    def __init__(
        self,
        scope: Scope,
        key: str | bytes,
        evidence: Optional[EvidenceLog] = None,
        *,
        require_signature: bool = True,
    ) -> None:
        if require_signature:
            try:
                ok = verify_scope(scope, key)
            except SignatureError as exc:
                raise ScopeViolation(f"refusing to operate: {exc}") from exc
            if not ok:
                raise ScopeViolation(
                    "refusing to operate: scope signature does not verify "
                    "(scope may have been altered after authorization)"
                )
        self.scope = scope
        self.evidence = evidence

    # ----- the gate -----------------------------------------------------
    def authorize(
        self,
        module: str,
        *,
        target: Optional[Target] = None,
        device_id: Optional[str] = None,
        destructive: bool = False,
        now: Optional[datetime] = None,
    ) -> None:
        """Permit ``module`` to act, or raise :class:`ScopeViolation`.

        Every check is fail-closed. On success an ``authorized`` evidence
        record is written; on refusal a ``denied`` record is written before the
        exception propagates, so the audit log captures attempts too.
        """
        reason = self._evaluate(module, target, device_id, destructive, now)
        ctx = {
            "module": module,
            "target": target.key if target else None,
            "device_id": device_id,
            "destructive": destructive,
        }
        if reason is not None:
            if self.evidence is not None:
                self.evidence.record("denied", {**ctx, "reason": reason})
            raise ScopeViolation(reason)
        if self.evidence is not None:
            self.evidence.record("authorized", ctx)

    def is_authorized(self, module: str, **kwargs) -> bool:
        """Non-raising variant of :meth:`authorize`."""
        try:
            self.authorize(module, **kwargs)
            return True
        except ScopeViolation:
            return False

    # ----- evaluation ---------------------------------------------------
    def _evaluate(
        self,
        module: str,
        target: Optional[Target],
        device_id: Optional[str],
        destructive: bool,
        now: Optional[datetime],
    ) -> Optional[str]:
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if not self.scope.is_active(now):
            return (
                f"engagement window not active: now={now.isoformat()} "
                f"window=[{self.scope.not_before.isoformat()} .. {self.scope.not_after.isoformat()}]"
            )
        if module not in self.scope.allowed_modules:
            return f"module {module!r} is not in allowed_modules for this engagement"
        if target is not None and target.key not in self.scope.target_keys():
            return f"target {target.key!r} is not an authorized target app"
        if device_id is not None and device_id not in self.scope.device_ids():
            return f"device {device_id!r} is not an authorized device"
        if destructive and not self.scope.allow_destructive:
            return "destructive action requested but engagement does not permit destructive operations"
        return None
