"""Reputation as verifiable claims, not a score.

A reputation event is a signed attestation made by one identity about another:
"issuer asserts that subject did X, here is the evidence." v0 stores and verifies
these. It does NOT aggregate, rank, or score them, because reputation scoring
invites sybil and gaming attacks that v0 makes no claim to have solved. The
reader sees who said what about whom, with proof, and decides.

Attestations are evidence-linked by design: `evidence_ref` should point at a
WitnessKit trail or a settled mandate, not an opinion.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from . import signing

VALID_TYPES = {
    "mandate-honored",
    "action-witnessed",
    "dispute-raised",
    "dispute-resolved",
    "operator-verified",
}


def make_attestation(
    subject: str,
    type: str,
    issuer_id: str,
    issuer_seed: bytes,
    *,
    evidence_ref: Optional[str] = None,
    time: Optional[str] = None,
    note: Optional[str] = None,
) -> Dict:
    """Create a signed attestation. `time` is caller-supplied so records are
    reproducible and the library stays clock-free."""
    if type not in VALID_TYPES:
        raise ValueError(f"type must be one of {sorted(VALID_TYPES)}")
    claim = {
        "subject": subject,
        "type": type,
        "issuer": issuer_id,
        "evidence_ref": evidence_ref,
        "time": time,
        "note": note,
    }
    claim = {k: v for k, v in claim.items() if v is not None}
    return {**claim, "proof": signing.make_proof(claim, issuer_seed)}


def verify_attestation(att: Dict) -> bool:
    """Proof is valid AND, when the issuer is a did:key, the signing key controls
    that issuer id. Never raises."""
    try:
        if not isinstance(att, dict) or att.get("type") not in VALID_TYPES:
            return False
        proof = att.get("proof")
        if not isinstance(proof, dict):
            return False
        claim = {k: v for k, v in att.items() if k != "proof"}
        if not signing.verify_proof(claim, proof):
            return False
        issuer = att.get("issuer", "")
        if isinstance(issuer, str) and issuer.startswith("did:key:"):
            return signing.public_from_did_key(issuer) == signing.unb64(proof["public_key"])
        # For non-key issuers (e.g. did:web), key control is established by
        # resolving the issuer separately; the signature itself is still checked.
        return True
    except Exception:
        return False


class ReputationLog:
    """An append-only set of verified attestations. Rejects anything that does
    not verify. No scoring, by design."""

    def __init__(self) -> None:
        self._items: List[Dict] = []

    def add(self, att: Dict) -> None:
        if not verify_attestation(att):
            raise ValueError("attestation failed verification; refusing to add")
        self._items.append(att)

    def for_subject(self, subject: str) -> List[Dict]:
        return [a for a in self._items if a.get("subject") == subject]

    def __len__(self) -> int:
        return len(self._items)
