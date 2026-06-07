#!/usr/bin/env python3
"""IdentityKit demo. Zero install (pure-Python crypto fallback if `cryptography`
is absent):

    python3 demo.py

Builds an agent identity, signs and verifies it, shows did:key self-certification,
the cross-walk onto a W3C DID Document and an AP2 issuer view, an evidence-linked
reputation attestation, and that tampering is caught.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "python"))

from identitykit import (  # noqa: E402
    ReputationLog,
    build_identity,
    crosswalk,
    did_key_from_public,
    generate_keypair,
    make_attestation,
    sign_identity,
    verify_identity,
)
from identitykit import signing  # noqa: E402

LINE = "-" * 64


def banner(t):
    print(f"\n{LINE}\n  {t}\n{LINE}")


def main():
    banner("1. Build and sign an agent identity (did:key)")
    seed, pub = generate_keypair()
    did = did_key_from_public(pub)
    print(f"  id: {did[:46]}...")
    doc = build_identity(
        id=did,
        operator={"name": "Acme Robotics", "type": "org"},
        keys=[{"id": f"{did}#0", "purpose": ["controller", "mandate-issuer"], "public_key": signing.b64(pub)}],
        capabilities=["search", "purchase"],
        bindings=[{"standard": "ap2", "ref": "ap2:issuer:acme"}],
        created="2026-06-07T00:00:00Z",
    )
    signed = sign_identity(doc, seed)
    print(f"  verify_identity -> {verify_identity(signed)}")

    banner("2. did:key is self-certifying")
    print("  The identifier IS the public key, so the signature proves control")
    print("  with no registry and no network. Sign with a different key:")
    other_seed, _ = generate_keypair()
    forged = sign_identity(doc, other_seed)
    print(f"  verify_identity(forged) -> {verify_identity(forged)}  (rejected)")

    banner("3. Cross-walk onto the standards")
    did_doc = crosswalk.to_did_document(signed)
    print("  W3C DID Document:")
    print("   ", json.dumps(did_doc, indent=2)[:240].replace("\n", "\n    "), "...")
    ap2 = crosswalk.ap2_issuer(signed)
    print(f"\n  AP2 issuer view (ties to MandateKit): operator={ap2['operator']!r}, "
          f"binding={ap2['ap2_binding']!r}")

    banner("4. Reputation as verifiable claims (no score)")
    iss_seed, iss_pub = generate_keypair()
    issuer = did_key_from_public(iss_pub)
    att = make_attestation(did, "mandate-honored", issuer, iss_seed,
                           evidence_ref="witnesskit:trail:9f2a", time="2026-06-07T00:00:00Z")
    log = ReputationLog()
    log.add(att)
    print(f"  attestation added and verified. claims about this agent: {len(log.for_subject(did))}")
    print(f"  type={att['type']!r}, evidence={att['evidence_ref']!r}")

    banner("5. Tamper is caught")
    signed["operator"]["name"] = "Evil Corp"
    print(f"  changed operator name -> verify_identity = {verify_identity(signed)}")

    banner("The 'who' beneath mandate / spend / witness.")
    print("  github.com/major-matters  ·  majorlabs.co\n")


if __name__ == "__main__":
    main()
