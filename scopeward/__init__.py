"""scopeward — engagement authorization for authorized mobile security testing.

scopeward is the consent layer for a mobile penetration-testing toolkit. Every
analysis or instrumentation action must be checked against a *signed engagement
scope* that names the authorized target apps, devices, time window and rules of
engagement. Anything outside that scope is refused before it can run.

The package is dependency-free (Python standard library only) so it can be
vendored into any tool in the suite.
"""

from .scope import Scope, Target, Device, ScopeError
from .signing import sign_scope, verify_scope, SignatureError
from .authz import Authorizer, ScopeViolation
from .evidence import EvidenceLog, EvidenceError
from .findings import Finding, Severity

__all__ = [
    "Scope",
    "Target",
    "Device",
    "ScopeError",
    "sign_scope",
    "verify_scope",
    "SignatureError",
    "Authorizer",
    "ScopeViolation",
    "EvidenceLog",
    "EvidenceError",
    "Finding",
    "Severity",
]

__version__ = "0.1.0"
