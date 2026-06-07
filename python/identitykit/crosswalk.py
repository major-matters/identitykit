"""Cross-walk: map an AgentIdentity onto the standards that will carry agent
identity. Pure functions, no network. This is the library form of the
State of Agent Identity report, and it is deliberately explicit about what each
target standard does and does not capture.

v0 targets: W3C DID Documents (full), AP2 issuer view (full, ties to MandateKit),
and binding extractors for FIDO / EUDI / Verifiable Credentials (references only,
since those credentials live in their own systems).
"""

from __future__ import annotations

from typing import Dict, List

from . import signing

_PURPOSE_TO_DID_REL = {
    "auth": "authentication",
    "assertion": "assertionMethod",
    "mandate-issuer": "assertionMethod",
    "witness-signer": "assertionMethod",
    "controller": "capabilityInvocation",
}


def _multibase(public_key_b64: str) -> str:
    pub = signing.unb64(public_key_b64)
    return signing.did_key_from_public(pub)[len("did:key:"):]  # the 'z...' part


def to_did_document(doc: Dict) -> Dict:
    """AgentIdentity -> W3C DID Document. Lossy by design: capabilities, operator
    detail, and non-DID bindings have no DID Document home and are dropped."""
    did = doc["id"]
    vms: List[Dict] = []
    rels: Dict[str, List[str]] = {}
    for k in doc.get("keys", []):
        vm_id = k["id"] if k["id"].startswith(did) else f"{did}#{k['id'].lstrip('#')}"
        vms.append({
            "id": vm_id,
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyMultibase": _multibase(k["public_key"]),
        })
        purposes = k.get("purpose")
        for p in (purposes if isinstance(purposes, list) else [purposes]):
            rel = _PURPOSE_TO_DID_REL.get(p)
            if rel:
                rels.setdefault(rel, []).append(vm_id)
    out = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": vms,
    }
    out.update(rels)
    return out


def did_key_to_did_document(did: str) -> Dict:
    """Standard did:key resolution to a DID Document (single key, all relationships)."""
    pub = signing.public_from_did_key(did)
    mb = signing.did_key_from_public(pub)[len("did:key:"):]
    vm_id = f"{did}#{mb}"
    vm = {"id": vm_id, "type": "Ed25519VerificationKey2020", "controller": did, "publicKeyMultibase": mb}
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [vm],
        "authentication": [vm_id],
        "assertionMethod": [vm_id],
        "capabilityInvocation": [vm_id],
    }


def ap2_issuer(doc: Dict) -> Dict:
    """An AP2 (Agent Payments Protocol) issuer view, so a MandateKit verifier can
    pin a mandate's issuer to this resolvable identity rather than a bare key."""
    issuer_keys = [
        k["public_key"]
        for k in doc.get("keys", [])
        if "mandate-issuer" in (k["purpose"] if isinstance(k.get("purpose"), list) else [k.get("purpose")])
    ]
    binding = next((b["ref"] for b in doc.get("bindings", []) if b.get("standard") == "ap2"), None)
    return {
        "issuer_id": doc["id"],
        "operator": doc.get("operator", {}).get("name"),
        "mandate_issuer_keys": issuer_keys,
        "ap2_binding": binding,
    }


def bindings_for(doc: Dict, standard: str) -> List[str]:
    """The external credential references bound under a given standard (fido, eudi, vc, ...)."""
    return [b["ref"] for b in doc.get("bindings", []) if b.get("standard") == standard]
