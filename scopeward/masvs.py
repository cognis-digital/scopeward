"""OWASP MASVS control mapping helpers.

Findings carry a MASVS control id (e.g. ``MASVS-NETWORK-1``) and, optionally, a
MASTG test id. This module knows the MASVS v2 control *categories* so a report
can group findings by category and cross-link to the MASTG. It is a small,
honest lookup table — not a claim to implement any test — used to tag SARIF
rules and to render coverage summaries.

Reference: OWASP Mobile Application Security Verification Standard (MASVS) v2,
Mobile Application Security Testing Guide (MASTG).
"""

from __future__ import annotations

import re
from typing import Optional

#: MASVS v2 control category prefixes → human-readable category names.
MASVS_CATEGORIES: dict[str, str] = {
    "MASVS-STORAGE": "Data Storage",
    "MASVS-CRYPTO": "Cryptography",
    "MASVS-AUTH": "Authentication and Authorization",
    "MASVS-NETWORK": "Network Communication",
    "MASVS-PLATFORM": "Platform Interaction",
    "MASVS-CODE": "Code Quality",
    "MASVS-RESILIENCE": "Resilience",
    "MASVS-PRIVACY": "Privacy",
}

_MASVS_ID = re.compile(r"^(MASVS-[A-Z]+)-\d+$")
_MASTG_URL = "https://mas.owasp.org/MASTG/tests/"
_MASVS_URL = "https://mas.owasp.org/MASVS/"


def category_of(masvs_id: str) -> Optional[str]:
    """Return the MASVS category prefix for a control id, or ``None``.

    ``category_of("MASVS-NETWORK-1")`` → ``"MASVS-NETWORK"``.
    """
    if not masvs_id:
        return None
    m = _MASVS_ID.match(masvs_id.strip())
    if not m:
        return None
    prefix = m.group(1)
    return prefix if prefix in MASVS_CATEGORIES else None


def category_name(masvs_id: str) -> Optional[str]:
    """Human-readable category name for a control id, or ``None``."""
    cat = category_of(masvs_id)
    return MASVS_CATEGORIES.get(cat) if cat else None


def is_valid_control(masvs_id: str) -> bool:
    """True if ``masvs_id`` is a well-formed, known MASVS v2 control id."""
    return category_of(masvs_id) is not None


def masvs_help_uri(masvs_id: str) -> str:
    """A stable documentation URI for a control (the MASVS site root)."""
    return _MASVS_URL


def mastg_help_uri(mastg_test: str) -> Optional[str]:
    """Documentation URI for a MASTG test id, or ``None`` if empty."""
    if not mastg_test:
        return None
    return _MASTG_URL + mastg_test.strip()
