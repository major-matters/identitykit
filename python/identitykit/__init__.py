"""IdentityKit: portable, signed, resolvable agent identity plus the cross-walk
onto DID, FIDO, AP2, and EUDI. Deterministic, fail-closed, off-the-shelf crypto.

    from identitykit import build_identity, sign_identity, verify_identity, resolve

The "who" beneath the agent-safety family: MandateKit (may), BudgetGuard (spends),
WitnessKit (did) all reference keys that IdentityKit makes resolvable.
"""

from __future__ import annotations

from . import crosswalk
from .errors import (
    IdentityError,
    InvalidIdentity,
    ResolutionError,
    UnsupportedMethod,
)
from .identity import build_identity, sign_identity, validate, verify_identity
from .reputation import ReputationLog, make_attestation, verify_attestation
from .resolver import did_web_url, resolve
from .signing import (
    did_key_from_public,
    generate_keypair,
    public_from_did_key,
    public_from_seed,
)

__version__ = "0.0.1"

__all__ = [
    "build_identity",
    "sign_identity",
    "verify_identity",
    "validate",
    "resolve",
    "did_web_url",
    "generate_keypair",
    "did_key_from_public",
    "public_from_did_key",
    "public_from_seed",
    "make_attestation",
    "verify_attestation",
    "ReputationLog",
    "crosswalk",
    "IdentityError",
    "InvalidIdentity",
    "ResolutionError",
    "UnsupportedMethod",
    "__version__",
]
