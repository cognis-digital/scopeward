"""Machine-parseable reason codes for authorization decisions.

Every refusal (and every explicit allow) carries a stable ``SW_*`` reason code
alongside a human-readable message. Codes are the *contract*: downstream tooling
(CI gates, dashboards, SIEM rules) can branch on ``SW_MODULE_NOT_ALLOWED``
without parsing English. Messages may be reworded; codes are stable — see
``docs/REASON_CODES.md``.

The registry here is the single source of truth. :mod:`scopeward.authz`
produces :class:`Decision` objects that reference these codes, and the SARIF /
audit layers surface them verbatim.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any


class ReasonCode(str, enum.Enum):
    """Stable, machine-parseable outcome codes.

    Subclassing :class:`str` means a code serializes to its value in JSON and
    compares equal to the bare string, so ``decision.code == "SW_ALLOWED"``
    works without importing the enum.
    """

    # --- allow ---------------------------------------------------------
    ALLOWED = "SW_ALLOWED"

    # --- deny ----------------------------------------------------------
    SIGNATURE_INVALID = "SW_SIGNATURE_INVALID"
    NOT_SIGNED = "SW_NOT_SIGNED"
    WINDOW_INACTIVE = "SW_WINDOW_INACTIVE"
    MODULE_NOT_ALLOWED = "SW_MODULE_NOT_ALLOWED"
    TARGET_UNAUTHORIZED = "SW_TARGET_UNAUTHORIZED"
    DEVICE_UNAUTHORIZED = "SW_DEVICE_UNAUTHORIZED"
    DESTRUCTIVE_FORBIDDEN = "SW_DESTRUCTIVE_FORBIDDEN"
    REVOKED = "SW_REVOKED"
    EXPIRED = "SW_EXPIRED"
    CAP_NOT_GRANTED = "SW_CAP_NOT_GRANTED"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


#: One-line human descriptions, keyed by code value. Documented and stable.
REASON_DESCRIPTIONS: dict[str, str] = {
    ReasonCode.ALLOWED.value: "Action is authorized by the signed scope.",
    ReasonCode.SIGNATURE_INVALID.value: (
        "Scope signature does not verify; the document may have been altered "
        "after authorization."
    ),
    ReasonCode.NOT_SIGNED.value: "Scope carries no signature and signatures are required.",
    ReasonCode.WINDOW_INACTIVE.value: "Current time is outside the engagement window.",
    ReasonCode.MODULE_NOT_ALLOWED.value: "Requested module is not in allowed_modules.",
    ReasonCode.TARGET_UNAUTHORIZED.value: "Requested target app is not an authorized target.",
    ReasonCode.DEVICE_UNAUTHORIZED.value: "Requested device is not an authorized device.",
    ReasonCode.DESTRUCTIVE_FORBIDDEN.value: (
        "A destructive action was requested but the engagement does not permit "
        "destructive operations."
    ),
    ReasonCode.REVOKED.value: (
        "The grant, target, module or capability was revoked mid-engagement."
    ),
    ReasonCode.EXPIRED.value: "A per-grant or per-capability expiry has passed.",
    ReasonCode.CAP_NOT_GRANTED.value: (
        "The requested capability is not granted (directly or via a capability "
        "ladder) for this target."
    ),
}


def describe(code: "ReasonCode | str") -> str:
    """Return the documented human description for a reason code."""
    key = code.value if isinstance(code, ReasonCode) else str(code)
    return REASON_DESCRIPTIONS.get(key, "Unknown reason code.")


@dataclass(frozen=True)
class Decision:
    """The structured result of an authorization evaluation.

    ``allowed`` is the boolean gate; ``code`` is a stable :class:`ReasonCode`;
    ``message`` is a rich human-readable explanation (safe to log/show);
    ``detail`` carries structured context (offending target, window bounds, …)
    for machine consumers.
    """

    allowed: bool
    code: ReasonCode
    message: str
    detail: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "code": self.code.value,
            "message": self.message,
            "detail": dict(self.detail),
        }

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return self.allowed
