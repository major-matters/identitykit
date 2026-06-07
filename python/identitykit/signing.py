"""Document signing, verification, and did:key codec for IdentityKit.

Ed25519 via the vetted `cryptography` library when present, falling back to the
pure-Python RFC 8032 reference (NOT constant-time) with a warning. The signing
key is a 32-byte seed that never leaves the caller. `did:key` uses standard
multibase base58btc with the ed25519 multicodec prefix, so identifiers are
interoperable with any did:key implementation. Zero third-party deps required.
"""

from __future__ import annotations

import base64
import os
import warnings
from typing import Tuple

from .canonical import canonicalize

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    _BACKEND = "cryptography"
except ImportError:  # pragma: no cover - exercised only without the dep
    from . import ed25519 as _ref

    _BACKEND = "pure-python"
    warnings.warn(
        "identitykit: 'cryptography' is not installed; falling back to a pure-Python "
        "Ed25519 reference that is NOT constant-time. Install 'cryptography' for "
        "production use.",
        RuntimeWarning,
        stacklevel=2,
    )


# -- raw Ed25519 -------------------------------------------------------------

def public_from_seed(seed: bytes) -> bytes:
    if _BACKEND == "cryptography":
        return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    return _ref.publickey(seed)


def sign_bytes(message: bytes, seed: bytes) -> bytes:
    if _BACKEND == "cryptography":
        return Ed25519PrivateKey.from_private_bytes(seed).sign(message)
    return _ref.sign(message, seed, _ref.publickey(seed))


def verify_bytes(signature: bytes, message: bytes, public_key: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    if _BACKEND == "cryptography":
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
        except Exception:
            return False
    return _ref.verify(signature, message, public_key)


def generate_keypair() -> Tuple[bytes, bytes]:
    """Return (private_seed, public_key) as raw 32-byte values."""
    seed = os.urandom(32)
    return seed, public_from_seed(seed)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def unb64(s: str) -> bytes:
    return base64.b64decode(s)


# -- base58btc (Bitcoin alphabet), for did:key multibase ---------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}


def _b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out


def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        if ch not in _B58_INDEX:
            raise ValueError(f"invalid base58 character {ch!r}")
        n = n * 58 + _B58_INDEX[ch]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


# Multicodec prefix for an Ed25519 public key: 0xed 0x01 (varint).
_ED25519_MULTICODEC = b"\xed\x01"


def did_key_from_public(public_key: bytes) -> str:
    """Encode a raw Ed25519 public key as a did:key identifier."""
    if len(public_key) != 32:
        raise ValueError("ed25519 public key must be 32 bytes")
    return "did:key:z" + _b58encode(_ED25519_MULTICODEC + public_key)


def public_from_did_key(did: str) -> bytes:
    """Decode a did:key Ed25519 identifier back to its raw public key."""
    if not did.startswith("did:key:z"):
        raise ValueError("not an ed25519 did:key (expected 'did:key:z' multibase prefix)")
    # A valid ed25519 did:key body is ~48 chars; cap the input so a hostile,
    # oversized string can't force a pathological base58/bigint decode.
    if len(did) > 120:
        raise ValueError("did:key is implausibly long")
    decoded = _b58decode(did[len("did:key:z"):])
    if decoded[:2] != _ED25519_MULTICODEC:
        raise ValueError("did:key is not an Ed25519 key (wrong multicodec prefix)")
    pub = decoded[2:]
    if len(pub) != 32:
        raise ValueError("decoded public key is not 32 bytes")
    return pub


# -- detached proof over a canonical document --------------------------------

def make_proof(document: dict, seed: bytes, *, key_id: str = None) -> dict:
    """Sign the canonical form of `document` and return a detached proof object."""
    public_key = public_from_seed(seed)
    signature = sign_bytes(canonicalize(document), seed)
    proof = {
        "type": "Ed25519Signature2020",
        "public_key": b64(public_key),
        "value": b64(signature),
    }
    if key_id:
        proof["key_id"] = key_id
    return proof


def verify_proof(document: dict, proof: dict) -> bool:
    """True iff `proof` is a valid Ed25519 signature over `document`. Never raises."""
    if not isinstance(proof, dict) or proof.get("type") != "Ed25519Signature2020":
        return False
    try:
        public_key = unb64(proof["public_key"])
        value = unb64(proof["value"])
        return verify_bytes(value, canonicalize(document), public_key)
    except Exception:
        return False
