"""The AgentIdentity document: a signed, portable description of an agent and who
operates it. JSON-friendly dict, signed with a detached Ed25519 proof.

Key control differs by identifier method, and that difference is the whole point:

  did:key  the id *is* a public key. The proof must be made by that exact key.
           Self-certifying and offline-verifiable; trust nothing but the key.
  did:web  the id is a domain. The document is fetched over TLS from that domain,
           and the proof must be made by a key the document itself lists. Trust
           is anchored in DNS/TLS, not the key alone.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from . import signing
from .errors import InvalidIdentity

SCHEMA = "https://identitykit.dev/schema/agent-identity/v0"

VALID_PURPOSES = {"controller", "auth", "mandate-issuer", "witness-signer", "assertion"}
VALID_BINDING_STANDARDS = {"did", "fido", "ap2", "eudi", "vc"}
VALID_OPERATOR_TYPES = {"org", "person"}


def _require(cond: bool, message: str, field: Optional[str] = None) -> None:
    if not cond:
        raise InvalidIdentity(message, field=field)


def build_identity(
    id: str,
    operator: Dict,
    keys: List[Dict],
    *,
    capabilities: Optional[List[str]] = None,
    bindings: Optional[List[Dict]] = None,
    created: Optional[str] = None,
) -> Dict:
    """Assemble an unsigned identity document. Validates structure; sign with
    sign_identity()."""
    doc = {
        "@schema": SCHEMA,
        "id": id,
        "operator": operator,
        "keys": keys,
        "capabilities": list(capabilities or []),
        "bindings": list(bindings or []),
    }
    if created is not None:
        doc["created"] = created
    validate(doc)
    return doc


def validate(doc: Dict) -> Dict:
    """Structural validation. Raises InvalidIdentity; returns the document."""
    _require(isinstance(doc, dict), "identity must be an object")
    _require(isinstance(doc.get("id"), str) and doc["id"], "id is required", "id")
    method = doc["id"].split(":")
    _require(len(method) >= 3 and method[0] == "did" and method[1] in ("key", "web"),
             "id must be a did:key or did:web identifier", "id")

    op = doc.get("operator")
    _require(isinstance(op, dict), "operator is required", "operator")
    _require(isinstance(op.get("name"), str) and op["name"], "operator.name is required", "operator.name")
    _require(op.get("type") in VALID_OPERATOR_TYPES,
             f"operator.type must be one of {sorted(VALID_OPERATOR_TYPES)}", "operator.type")

    keys = doc.get("keys")
    _require(isinstance(keys, list) and len(keys) >= 1, "at least one key is required", "keys")
    seen_ids = set()
    for i, k in enumerate(keys):
        _require(isinstance(k, dict), f"keys[{i}] must be an object", "keys")
        _require(isinstance(k.get("id"), str) and k["id"], f"keys[{i}].id is required", "keys")
        _require(k["id"] not in seen_ids, f"duplicate key id {k['id']!r}", "keys")
        seen_ids.add(k["id"])
        _require(isinstance(k.get("public_key"), str) and k["public_key"],
                 f"keys[{i}].public_key is required", "keys")
        purposes = k.get("purpose")
        plist = purposes if isinstance(purposes, list) else [purposes]
        _require(all(p in VALID_PURPOSES for p in plist),
                 f"keys[{i}].purpose must be from {sorted(VALID_PURPOSES)}", "keys")
        try:
            signing.unb64(k["public_key"])
        except Exception:
            raise InvalidIdentity(f"keys[{i}].public_key is not valid base64", field="keys")

    bindings = doc.get("bindings", [])
    _require(isinstance(bindings, list), "bindings must be a list", "bindings")
    for i, b in enumerate(bindings):
        _require(isinstance(b, dict) and b.get("standard") in VALID_BINDING_STANDARDS,
                 f"bindings[{i}].standard must be from {sorted(VALID_BINDING_STANDARDS)}", "bindings")
        _require(isinstance(b.get("ref"), str) and b["ref"], f"bindings[{i}].ref is required", "bindings")

    _require(isinstance(doc.get("capabilities", []), list), "capabilities must be a list", "capabilities")
    return doc


def sign_identity(doc: Dict, seed: bytes, *, key_id: Optional[str] = None) -> Dict:
    """Attach a detached Ed25519 proof. The document (without proof) is what gets
    signed, so re-verification is exact."""
    validate(doc)
    body = {k: v for k, v in doc.items() if k != "proof"}
    signed = dict(body)
    signed["proof"] = signing.make_proof(body, seed, key_id=key_id)
    return signed


def verify_identity(doc: Dict) -> bool:
    """Structural validity + proof validity + key control for the id method.
    Never raises; returns False on any failure."""
    try:
        validate(doc)
        proof = doc.get("proof")
        if not isinstance(proof, dict):
            return False
        body = {k: v for k, v in doc.items() if k != "proof"}
        if not signing.verify_proof(body, proof):
            return False

        proof_key = signing.unb64(proof["public_key"])
        method = doc["id"].split(":")[1]

        if method == "key":
            # Self-certifying: the proof key must BE the key in the identifier.
            return signing.public_from_did_key(doc["id"]) == proof_key

        if method == "web":
            # Domain-anchored: the proof key must be one the document lists with
            # a controlling purpose. (Domain/TLS trust is the resolver's job.)
            for k in doc["keys"]:
                purposes = k.get("purpose")
                plist = purposes if isinstance(purposes, list) else [purposes]
                if not ({"controller", "auth"} & set(plist)):
                    continue
                if signing.unb64(k["public_key"]) == proof_key:
                    return True
            return False

        return False
    except Exception:
        return False
