"""IdentityKit exceptions. Verification fails closed: anything malformed,
unresolvable, or unverifiable raises rather than returning a usable identity."""

from __future__ import annotations

from typing import Optional


class IdentityError(Exception):
    """Base for every IdentityKit failure."""


class InvalidIdentity(IdentityError):
    """The document is structurally invalid or its proof did not verify."""

    def __init__(self, message: str, *, field: Optional[str] = None):
        super().__init__(message)
        self.field = field


class ResolutionError(IdentityError):
    """The identifier could not be resolved to a document."""


class UnsupportedMethod(ResolutionError):
    """No resolver is registered for this identifier method."""
