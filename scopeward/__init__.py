"""scopeward — engagement authorization for authorized mobile security testing.

scopeward is the consent layer for a mobile penetration-testing toolkit. Every
analysis or instrumentation action must be checked against a *signed engagement
scope* that names the authorized target apps, devices, time window and rules of
engagement. Anything outside that scope is refused before it can run.

The package is dependency-free (Python standard library only) so it can be
vendored into any tool in the suite.
"""

from .scope import Scope, Target, Device, ScopeError
from .signing import sign_scope, verify_scope, compute_signature, SignatureError
from .authz import Authorizer, ScopeViolation
from .evidence import EvidenceLog, EvidenceError
from .findings import Finding, Severity
from .reasons import Decision, ReasonCode, describe, REASON_DESCRIPTIONS
from .grants import Grant, Capability, expand_capabilities
from .revocation import Revocation, RevocationList, RevocationKind
from .schema import validate as validate_scope, validate_document, SchemaValidationError, SchemaError
from .sarif import findings_to_sarif
from . import masvs

__all__ = [
    "Scope",
    "Target",
    "Device",
    "ScopeError",
    "sign_scope",
    "verify_scope",
    "compute_signature",
    "SignatureError",
    "Authorizer",
    "ScopeViolation",
    "EvidenceLog",
    "EvidenceError",
    "Finding",
    "Severity",
    # reason codes / decisions
    "Decision",
    "ReasonCode",
    "describe",
    "REASON_DESCRIPTIONS",
    # capability ladder + grants
    "Grant",
    "Capability",
    "expand_capabilities",
    # revocation
    "Revocation",
    "RevocationList",
    "RevocationKind",
    # schema validation
    "validate_scope",
    "validate_document",
    "SchemaValidationError",
    "SchemaError",
    # sarif + masvs
    "findings_to_sarif",
    "masvs",
]

__version__ = "0.2.0"
