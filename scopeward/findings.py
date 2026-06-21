"""Finding model shared across the mobile suite.

A :class:`Finding` is the unit of output every analysis module emits. Keeping
one schema across ``apkprobe`` / ``ipaprobe`` / ``hookbench`` etc. means
results from different tools merge into a single engagement report and map to
external systems (the cognis-connect Finding contract, SARIF, MASVS coverage).

The schema is intentionally small and stdlib-serializable.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


class Severity(enum.IntEnum):
    """Ordered severities; integer values allow sorting/thresholding."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: "str | int | Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        try:
            return cls[str(value).strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {value!r}") from exc


@dataclass
class Finding:
    """A single security observation tied to a target and (optionally) MASTG."""

    title: str
    severity: Severity
    target: str  # e.g. "android:com.example.app"
    description: str = ""
    module: str = ""
    masvs: str = ""          # MASVS control id, e.g. "MASVS-NETWORK-1"
    mastg_test: str = ""     # MASTG test id, e.g. "MASTG-TEST-0019"
    evidence: str = ""       # free-form pointer/snippet
    metadata: dict[str, Any] = field(default_factory=dict)
    ts: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.title:
            raise ValueError("finding title is required")
        self.severity = Severity.parse(self.severity)
        if self.ts is None:
            self.ts = datetime.now(timezone.utc).isoformat()

    @property
    def fingerprint(self) -> str:
        """Stable id for dedup across reruns (title+target+masvs+evidence)."""
        basis = f"{self.title}|{self.target}|{self.masvs}|{self.evidence}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.name
        data["fingerprint"] = self.fingerprint
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        payload = {k: v for k, v in data.items() if k != "fingerprint"}
        return cls(**payload)
