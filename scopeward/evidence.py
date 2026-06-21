"""Tamper-evident, append-only evidence log.

Every authorization decision and finding is written as one JSON object per
line (JSONL). Each record carries the SHA-256 of the previous record, forming a
hash chain: altering or deleting any historical line breaks verification of all
subsequent lines. This gives a defensible audit trail of exactly what was run,
against what, and when — which is the point of an *authorized* engagement.

Standard library only; the chain is verifiable by anyone with the file.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

GENESIS = "0" * 64


class EvidenceError(Exception):
    """Raised when the evidence log is malformed or its chain is broken."""


def _hash_record(prev_hash: str, body: dict[str, Any]) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


class EvidenceLog:
    """Append-only JSONL log with a per-record hash chain."""

    def __init__(self, path: str, engagement_id: str = "") -> None:
        self.path = path
        self.engagement_id = engagement_id

    # ----- writing ------------------------------------------------------
    def _last_hash(self) -> str:
        if not os.path.exists(self.path):
            return GENESIS
        last = None
        with open(self.path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    last = line
        if last is None:
            return GENESIS
        try:
            return json.loads(last)["hash"]
        except (ValueError, KeyError) as exc:
            raise EvidenceError(f"cannot read previous record hash: {exc}") from exc

    def record(self, kind: str, data: dict[str, Any], *, ts: Optional[datetime] = None) -> dict[str, Any]:
        """Append a record of ``kind`` carrying ``data`` and return it."""
        prev = self._last_hash()
        body = {
            "ts": (ts or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(),
            "engagement_id": self.engagement_id,
            "kind": kind,
            "data": data,
            "prev": prev,
        }
        body["hash"] = _hash_record(prev, body_without_hash(body))
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(body, separators=(",", ":")) + "\n")
        return body

    # ----- reading / verifying -----------------------------------------
    def __iter__(self) -> Iterator[dict[str, Any]]:
        if not os.path.exists(self.path):
            return
        with open(self.path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def verify(self) -> bool:
        """Return ``True`` if the hash chain is intact end to end."""
        prev = GENESIS
        for rec in self:
            if rec.get("prev") != prev:
                raise EvidenceError(f"chain break: record prev={rec.get('prev')!r} expected {prev!r}")
            expected = _hash_record(prev, body_without_hash(rec))
            if rec.get("hash") != expected:
                raise EvidenceError(f"hash mismatch at record ts={rec.get('ts')}")
            prev = rec["hash"]
        return True


def body_without_hash(body: dict[str, Any]) -> dict[str, Any]:
    """The record content the hash is computed over (everything but ``hash``)."""
    return {k: v for k, v in body.items() if k != "hash"}
