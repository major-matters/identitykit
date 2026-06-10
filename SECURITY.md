# Security

IdentityKit decides whether an agent identity is genuine, so it **fails closed**: anything malformed, unresolvable, or unverifiable raises or returns false, never a usable identity.

## Threat model

Defends against:
- a forged identity (signed by a key that does not control the identifier);
- a tampered document (any field changed after signing);
- an attacker steering `did:web` resolution at internal services (SSRF);
- a hostile `did:key` string crafted to exhaust the decoder.

Does **not** defend against:
- a caller who bypasses the library entirely;
- DNS-level attacks on `did:web` (rebinding, a hostname that resolves to an internal IP) — use an allow-list for untrusted input;
- key compromise (there is no revocation in v0).

## Guarantees

- **Signatures cover the whole document.** The proof is computed over the canonical (RFC 8785) form of every field except `proof` itself, so no field can be added or changed without breaking verification.
- **Key control is method-specific and enforced.** `did:key` verification requires the proof key to *be* the key in the identifier (self-certifying). `did:web` verification requires the proof key to be one the document lists with a controlling purpose.
- **did:web is HTTPS-only and SSRF-guarded.** The default resolver refuses non-HTTPS URLs and blocks loopback, private, link-local (including `169.254.169.254`), and internal-looking hosts. The fetch is injectable so callers can impose stricter policy.
- **did:key decoding is bounded.** Oversized identifiers are rejected before the base58/bigint decode runs.
- **Reputation verifies on ingest.** `ReputationLog.add` refuses any attestation whose proof does not verify; for a `did:key` issuer it also checks the signing key controls that issuer id.

These are covered by unit tests (forgery, tamper, id-mismatch, SSRF, length-cap) and property tests in both runtimes; bandit and CodeQL run in CI.

## Known limitations

- `verify_identity` on a `did:web` document proves internal consistency only; authenticity requires resolving it from the domain.
- No key rotation or revocation in v0.
- DNS-based SSRF is out of scope for the default guard.

## Reporting

v0 research artifact. Open an issue at [github.com/major-matters](https://github.com/major-matters) for anything that looks like a fail-open.

## Audit status (v0)

This is a v0 release. It has been independently hardened — CodeQL, bandit, semgrep, property-based tests, and adversarial tier 1-2 reviews, all passing in CI — but it has **not** had a third-party security audit. Treat it accordingly for anything high-stakes.

## Security review welcome

We actively want researcher eyes on this. If you find a fail-open, a signature bypass, an SSRF path, or any way to defeat a guarantee in this document, please open an issue. Credit given. The shared crypto core (Ed25519 + RFC 8785 canonicalization) and the did:web SSRF guard are the highest-value targets.

## v0.0.2 hardening (2026-06-10 internal audit)

- **did:web SSRF guard rewritten.** The previous guard only recognized dotted-decimal IPv4; alternate encodings (decimal `2130706433`, octal, hex, IPv4-mapped IPv6, NAT64) that `getaddrinfo` still resolves to internal hosts now get normalized and blocked, including the cloud metadata address `169.254.169.254`. The guard is also re-applied on every HTTP redirect hop; the TS fetch now has a timeout and a streamed response-size cap; `..`/empty did:web path segments are rejected.
- **did:web key control (known limit).** A fetched did:web document still validates against its own embedded keys. The HTTPS fetch + host guard are the authenticity anchor; for high-stakes use, pin the controlling key out of band rather than trusting the document as its own root of trust.
- **Canonicalization fallback.** The dependency-free fallback now fails closed (rejects floats and out-of-safe-range integers) instead of emitting bytes that diverge from RFC 8785. `rfc8785` (a declared dependency) remains the primary path; "byte-identical across Python and TypeScript" holds on that path.
