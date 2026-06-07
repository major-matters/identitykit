# IdentityKit

**Portable, signed, resolvable agent identity, plus the cross-walk onto the standards that will carry it.** Deterministic, fail-closed, off-the-shelf crypto. v0.

As AI agents start to spend money and call APIs on someone's behalf, every counterparty asks the same question networks have always asked of parties: **who is this, who stands behind it, and what is its track record?** Today each platform answers that for itself, so a "verified" agent is a stranger everywhere else. IdentityKit is a portable answer.

It is the **"who"** beneath the rest of the [Major Labs](https://majorlabs.co) agent-safety family:

> **IdentityKit** says who the agent is. **MandateKit** says what it may do. **BudgetGuard** caps what it spends. **WitnessKit** proves what it did.

MandateKit and WitnessKit already pin to raw public keys; IdentityKit makes those keys resolvable, attributable, and reputation-bearing.

---

## What it does

- **Sign a portable identity document** — an `AgentIdentity`: identifier, operator, public keys (with purposes), declared capabilities, and bindings to external credentials. Signed with a detached Ed25519 proof over RFC 8785 canonical JSON.
- **Resolve and verify** — two identifier methods, with the trust model spelled out:
  - **`did:key`** — the identifier *is* the public key. Self-certifying, offline, trust nothing but the key.
  - **`did:web`** — the identifier is a domain. The document is fetched over HTTPS from that domain's well-known location and verified. Trust is anchored in DNS/TLS.
- **Cross-walk** — map an identity onto a **W3C DID Document**, an **AP2 issuer view** (ties straight into MandateKit), and **FIDO / EUDI / Verifiable Credential** bindings.
- **Reputation as verifiable claims** — store and verify signed, evidence-linked attestations (a mandate honored, an action witnessed). **No score, no ranking** — see below.

---

## Install

```bash
pip install identitykit          # Python 3.8+ (install 'cryptography' for constant-time Ed25519)
npm install identitykit          # Node 22.6+
```

The Python core runs with zero third-party deps via a pure-Python Ed25519 fallback; install `cryptography` for production. The TS core uses Node's built-in Ed25519 and one small dependency (`canonicalize`) for RFC 8785.

---

## Quickstart (Python)

```python
from identitykit import generate_keypair, did_key_from_public, build_identity, sign_identity, verify_identity, crosswalk

seed, pub = generate_keypair()
did = did_key_from_public(pub)

identity = build_identity(
    id=did,
    operator={"name": "Acme Robotics", "type": "org"},
    keys=[{"id": f"{did}#0", "purpose": ["controller", "mandate-issuer"], "public_key": __import__("identitykit").signing.b64(pub)}],
    bindings=[{"standard": "ap2", "ref": "ap2:issuer:acme"}],
)
signed = sign_identity(identity, seed)
assert verify_identity(signed)               # True; tamper anywhere -> False

did_document = crosswalk.to_did_document(signed)   # W3C DID Document
ap2 = crosswalk.ap2_issuer(signed)                 # issuer view for MandateKit
```

## Quickstart (TypeScript)

```ts
import { generateKeypair, didKeyFromPublic, buildIdentity, signIdentity, verifyIdentity, b64 } from "identitykit";

const { seed, publicKey } = generateKeypair();
const did = didKeyFromPublic(publicKey);
const signed = signIdentity(
  buildIdentity(did, { name: "Acme Robotics", type: "org" }, [
    { id: `${did}#0`, purpose: ["controller", "mandate-issuer"], public_key: b64(publicKey) },
  ]),
  seed,
);
verifyIdentity(signed); // true
```

Run the demo: `python3 demo.py` or `npm run demo`.

---

## Reputation, deliberately thin

Reputation is where identity systems die: sybil attacks, gaming, "who attests the attesters." v0 **does not score**. It stores and verifies signed attestations that are evidence-linked (an `evidence_ref` should point at a WitnessKit trail or a settled mandate), and lets the reader decide. "Reputation" here means *here are the verifiable claims about this agent and who made them*, with proof. A scored model is out of scope until the data and the abuse model are understood.

---

## Honest limitations (v0)

- **did:web trust is where you fetched it.** `verify_identity` on a did:web document proves internal consistency (the proof matches a listed controller key). It does **not** prove the document is authentic on its own — that comes from resolving it from the actual domain over TLS. Use `resolve()` for that.
- **SSRF on did:web.** The default resolver blocks loopback, private, and link-local hosts (including the cloud metadata IP), but does not resolve DNS, so a hostname pointing at an internal address is still the caller's risk. Use an allow-list for untrusted input.
- **No revocation or rotation yet.** A v0 identity is a point-in-time document. Key rotation and revocation lists are planned.
- **Two methods only.** `did:key` and `did:web`. No ledger-backed methods, by choice (no blockchain).

---

## License

MIT. Built by [Major Labs](https://majorlabs.co) · [github.com/major-matters](https://github.com/major-matters)
