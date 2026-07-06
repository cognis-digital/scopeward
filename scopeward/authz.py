"""The authorization gate.

:class:`Authorizer` wraps a verified :class:`~scopeward.scope.Scope` and is the
single chokepoint every test module calls before touching a target. A call to
:meth:`Authorizer.authorize` either returns silently (action permitted, and an
audit record is written) or raises :class:`ScopeViolation` (action refused).

Design intent: it should be *impossible* to run a module against an app or
device that the signed scope does not name, or outside the engagement window.
Fail closed — any ambiguity refuses.

Evaluation is layered and every layer produces a structured
:class:`~scopeward.reasons.Decision` carrying a stable ``SW_*`` reason code, so
callers can branch on codes and the audit log records exactly *why* an action
was allowed or denied. The order below is deliberate: cheaper, coarser gates
(window, module) run before finer ones (target, device, capability), and
revocation is checked before positive authorization so a withdrawn item is
denied even when otherwise in scope.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .scope import Scope, Target
from .signing import verify_scope, SignatureError
from .evidence import EvidenceLog
from .reasons import Decision, ReasonCode, describe
from .grants import Capability
from .revocation import RevocationKind


class ScopeViolation(Exception):
    """Raised when a requested action falls outside the authorized scope.

    Carries the structured :class:`~scopeward.reasons.Decision` on
    :attr:`decision` so ``except ScopeViolation as e: e.decision.code`` works.
    """

    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.message)
        self.decision = decision

    @property
    def code(self) -> ReasonCode:
        return self.decision.code


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
                raise ScopeViolation(
                    Decision(
                        allowed=False,
                        code=ReasonCode.NOT_SIGNED,
                        message=f"refusing to operate: {exc}",
                        detail={},
                    )
                ) from exc
            if not ok:
                raise ScopeViolation(
                    Decision(
                        allowed=False,
                        code=ReasonCode.SIGNATURE_INVALID,
                        message=(
                            "refusing to operate: scope signature does not verify "
                            "(scope may have been altered after authorization)"
                        ),
                        detail={"engagement_id": scope.engagement_id},
                    )
                )
        self.scope = scope
        self.evidence = evidence

    # ----- the gate -----------------------------------------------------
    def evaluate(
        self,
        module: str,
        *,
        target: Optional[Target] = None,
        device_id: Optional[str] = None,
        destructive: bool = False,
        capability: Optional["Capability | str"] = None,
        now: Optional[datetime] = None,
    ) -> Decision:
        """Return a :class:`Decision` without raising or logging.

        This is the pure evaluation core. :meth:`authorize` and
        :meth:`is_authorized` are thin wrappers that add raising and auditing.
        """
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        cap = Capability.parse(capability) if capability is not None else None
        # A capability request at or above DESTRUCTIVE implies a destructive action.
        if cap is not None and cap.implies(Capability.DESTRUCTIVE):
            destructive = True

        # 1. window
        if not self.scope.is_active(now):
            return self._deny(
                ReasonCode.WINDOW_INACTIVE,
                f"engagement window not active: now={now.isoformat()} "
                f"window=[{self.scope.not_before.isoformat()} .. "
                f"{self.scope.not_after.isoformat()}]",
                {
                    "now": now.isoformat(),
                    "not_before": self.scope.not_before.isoformat(),
                    "not_after": self.scope.not_after.isoformat(),
                },
            )

        # 2. module allow-list
        if module not in self.scope.allowed_modules:
            return self._deny(
                ReasonCode.MODULE_NOT_ALLOWED,
                f"module {module!r} is not in allowed_modules for this engagement",
                {"module": module, "allowed_modules": list(self.scope.allowed_modules)},
            )

        # 3. target allow-list
        if target is not None and target.key not in self.scope.target_keys():
            return self._deny(
                ReasonCode.TARGET_UNAUTHORIZED,
                f"target {target.key!r} is not an authorized target app",
                {"target": target.key},
            )

        # 4. device allow-list
        if device_id is not None and device_id not in self.scope.device_ids():
            return self._deny(
                ReasonCode.DEVICE_UNAUTHORIZED,
                f"device {device_id!r} is not an authorized device",
                {"device_id": device_id},
            )

        # 5. revocation (subtractive, fail-closed) — before positive checks
        revoked = self._check_revocations(module, target, device_id)
        if revoked is not None:
            return revoked

        # 6. destructive gate (engagement-level)
        if destructive and not self.scope.allow_destructive:
            return self._deny(
                ReasonCode.DESTRUCTIVE_FORBIDDEN,
                "destructive action requested but engagement does not permit "
                "destructive operations",
                {"module": module, "target": target.key if target else None},
            )

        # 7. capability ladder — only when a capability was requested
        if cap is not None:
            cap_decision = self._check_capability(cap, module, target, device_id, now)
            if cap_decision is not None:
                return cap_decision

        return Decision(
            allowed=True,
            code=ReasonCode.ALLOWED,
            message=describe(ReasonCode.ALLOWED),
            detail={
                "module": module,
                "target": target.key if target else None,
                "device_id": device_id,
                "capability": cap.value if cap else None,
                "destructive": destructive,
            },
        )

    def authorize(
        self,
        module: str,
        *,
        target: Optional[Target] = None,
        device_id: Optional[str] = None,
        destructive: bool = False,
        capability: Optional["Capability | str"] = None,
        now: Optional[datetime] = None,
    ) -> Decision:
        """Permit ``module`` to act, or raise :class:`ScopeViolation`.

        Every check is fail-closed. On success an ``authorized`` evidence
        record is written and the :class:`Decision` returned; on refusal a
        ``denied`` record is written before :class:`ScopeViolation` propagates,
        so the audit log captures attempts too.
        """
        decision = self.evaluate(
            module,
            target=target,
            device_id=device_id,
            destructive=destructive,
            capability=capability,
            now=now,
        )
        if self.evidence is not None:
            kind = "authorized" if decision.allowed else "denied"
            self.evidence.record(kind, {
                **decision.detail,
                "code": decision.code.value,
                "reason": decision.message,
            })
        if not decision.allowed:
            raise ScopeViolation(decision)
        return decision

    def is_authorized(self, module: str, **kwargs) -> bool:
        """Non-raising variant of :meth:`authorize` (still audits)."""
        try:
            self.authorize(module, **kwargs)
            return True
        except ScopeViolation:
            return False

    # ----- evaluation helpers ------------------------------------------
    @staticmethod
    def _deny(code: ReasonCode, message: str, detail: dict) -> Decision:
        return Decision(allowed=False, code=code, message=message, detail=detail)

    def _check_revocations(
        self,
        module: str,
        target: Optional[Target],
        device_id: Optional[str],
    ) -> Optional[Decision]:
        rl = self.scope.revocations
        if rl is None or len(rl) == 0:
            return None
        if rl.is_module_revoked(module):
            rev = rl.find(RevocationKind.MODULE, module)
            return self._revoked_decision(RevocationKind.MODULE, module, rev)
        if target is not None and rl.is_target_revoked(target.key):
            rev = rl.find(RevocationKind.TARGET, target.key)
            return self._revoked_decision(RevocationKind.TARGET, target.key, rev)
        if device_id is not None and rl.is_device_revoked(device_id):
            rev = rl.find(RevocationKind.DEVICE, device_id)
            return self._revoked_decision(RevocationKind.DEVICE, device_id, rev)
        return None

    def _revoked_decision(self, kind: RevocationKind, value: str, rev) -> Decision:
        reason = getattr(rev, "reason", "") if rev is not None else ""
        msg = f"{kind.value} {value!r} has been revoked for this engagement"
        if reason:
            msg += f" (reason: {reason})"
        return self._deny(
            ReasonCode.REVOKED,
            msg,
            {"revoked_kind": kind.value, "revoked_value": value, "reason": reason},
        )

    def _check_capability(
        self,
        cap: Capability,
        module: str,
        target: Optional[Target],
        device_id: Optional[str],
        now: datetime,
    ) -> Optional[Decision]:
        """Require a live, unrevoked grant that confers ``cap`` on the target."""
        if target is None:
            return self._deny(
                ReasonCode.CAP_NOT_GRANTED,
                f"capability {cap.value!r} requested without a target; "
                "capability grants are per-target",
                {"capability": cap.value},
            )
        applicable = self.scope.grants_for(
            target=target.key, module=module, device_id=device_id
        )
        rl = self.scope.revocations
        # A grant satisfies the request if it confers the capability, is live
        # (not expired), and is not itself revoked.
        satisfying = None
        expired_but_would_satisfy = None
        for g in applicable:
            if not g.grants(cap):
                continue
            if rl is not None and rl.is_grant_revoked(g.grant_id):
                return self._deny(
                    ReasonCode.REVOKED,
                    f"grant {g.grant_id!r} has been revoked",
                    {"revoked_kind": "grant", "revoked_value": g.grant_id},
                )
            if g.is_expired(now):
                expired_but_would_satisfy = g
                continue
            satisfying = g
            break
        if satisfying is not None:
            return None  # allowed
        if expired_but_would_satisfy is not None:
            g = expired_but_would_satisfy
            return self._deny(
                ReasonCode.EXPIRED,
                f"grant {g.grant_id!r} conferring {cap.value!r} expired at "
                f"{g.expires}",
                {"grant_id": g.grant_id, "capability": cap.value, "expires": g.expires},
            )
        return self._deny(
            ReasonCode.CAP_NOT_GRANTED,
            f"no live grant confers capability {cap.value!r} on target "
            f"{target.key!r} for module {module!r}",
            {"capability": cap.value, "target": target.key, "module": module},
        )
