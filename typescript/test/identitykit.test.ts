/** IdentityKit v0 (TypeScript) test suite. Run: npm test (node --test). */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  buildIdentity,
  signIdentity,
  verifyIdentity,
  validate,
  resolve,
  didKeyFromPublic,
  publicFromDidKey,
  generateKeypair,
  makeAttestation,
  verifyAttestation,
  ReputationLog,
  crosswalk,
  b64,
  unb64,
  InvalidIdentity,
  type AgentIdentity,
} from "../src/index.ts";
import * as signing from "../src/signing.ts";
import { hostIsBlocked } from "../src/resolver.ts";

function didKeyIdentity(pub: Buffer, over: Partial<{ bindings: AgentIdentity["bindings"] }> = {}): AgentIdentity {
  const did = didKeyFromPublic(pub);
  return buildIdentity(
    did,
    { name: "Acme Robotics", type: "org" },
    [{ id: `${did}#0`, purpose: ["controller", "auth", "mandate-issuer"], public_key: b64(pub) }],
    {
      capabilities: ["search", "purchase"],
      bindings: over.bindings ?? [{ standard: "ap2", ref: "ap2:issuer:acme" }],
      created: "2026-06-07T00:00:00Z",
    },
  );
}

test("did:key roundtrip", () => {
  const { publicKey } = generateKeypair();
  const did = didKeyFromPublic(publicKey);
  assert.ok(did.startsWith("did:key:z"));
  assert.ok(publicFromDidKey(did).equals(publicKey));
});

test("sign and verify did:key", () => {
  const { seed, publicKey } = generateKeypair();
  const signed = signIdentity(didKeyIdentity(publicKey), seed);
  assert.equal(verifyIdentity(signed), true);
});

test("tamper breaks verification", () => {
  const { seed, publicKey } = generateKeypair();
  const signed = signIdentity(didKeyIdentity(publicKey), seed);
  signed.operator.name = "Evil Corp";
  assert.equal(verifyIdentity(signed), false);
});

test("did:key proof must match id", () => {
  const a = generateKeypair();
  const b = generateKeypair();
  const doc = didKeyIdentity(a.publicKey); // id encodes a
  const signed = signIdentity(doc, b.seed); // signed by b -> fails self-cert
  assert.equal(verifyIdentity(signed), false);
});

test("validate rejects bad structure", () => {
  const { publicKey } = generateKeypair();
  assert.throws(
    () => validate({ id: "not-a-did", operator: { name: "x", type: "org" }, keys: [{ id: "k", purpose: "auth", public_key: b64(publicKey) }] } as AgentIdentity),
    InvalidIdentity,
  );
  assert.throws(
    () => validate({ id: "did:key:zABC", operator: { name: "x", type: "alien" }, keys: [] } as unknown as AgentIdentity),
    InvalidIdentity,
  );
});

test("resolve did:key offline", async () => {
  const { publicKey } = generateKeypair();
  const did = didKeyFromPublic(publicKey);
  const res = (await resolve(did)) as { method: string; public_key: string };
  assert.equal(res.method, "key");
  assert.ok(unb64(res.public_key).equals(publicKey));
});

test("resolve did:web with injected fetch", async () => {
  const { seed, publicKey } = generateKeypair();
  const did = "did:web:example.com";
  const doc = buildIdentity(did, { name: "Example Co", type: "org" }, [
    { id: `${did}#owner`, purpose: ["controller", "auth"], public_key: b64(publicKey) },
  ], { created: "2026-06-07T00:00:00Z" });
  const signed = signIdentity(doc, seed);
  let url = "";
  const out = (await resolve(did, { fetch: (u) => { url = u; return signed; } })) as AgentIdentity;
  assert.equal(url, "https://example.com/.well-known/agent-identity.json");
  assert.equal(out.operator.name, "Example Co");
});

test("resolve did:web rejects id mismatch", async () => {
  const { seed, publicKey } = generateKeypair();
  const doc = buildIdentity("did:web:evil.com", { name: "x", type: "org" }, [
    { id: "k", purpose: ["controller"], public_key: b64(publicKey) },
  ]);
  const signed = signIdentity(doc, seed);
  await assert.rejects(() => resolve("did:web:example.com", { fetch: () => signed }), InvalidIdentity);
});

test("crosswalk did document", () => {
  const { seed, publicKey } = generateKeypair();
  const signed = signIdentity(didKeyIdentity(publicKey), seed);
  const dd = crosswalk.toDidDocument(signed);
  assert.equal((dd as { id: string }).id, signed.id);
  assert.ok("authentication" in dd);
});

test("crosswalk ap2 issuer", () => {
  const { seed, publicKey } = generateKeypair();
  const signed = signIdentity(didKeyIdentity(publicKey), seed);
  const ap2 = crosswalk.ap2Issuer(signed);
  assert.equal(ap2.issuer_id, signed.id);
  assert.equal(ap2.operator, "Acme Robotics");
  assert.ok(ap2.mandate_issuer_keys.includes(b64(publicKey)));
  assert.equal(ap2.ap2_binding, "ap2:issuer:acme");
});

test("reputation log verifies and rejects tamper", () => {
  const subj = generateKeypair();
  const iss = generateKeypair();
  const subject = didKeyFromPublic(subj.publicKey);
  const issuer = didKeyFromPublic(iss.publicKey);
  const att = makeAttestation(subject, "mandate-honored", issuer, iss.seed, { evidenceRef: "witnesskit:trail:abc", time: "2026-06-07T00:00:00Z" });
  assert.equal(verifyAttestation(att), true);
  const log = new ReputationLog();
  log.add(att);
  assert.equal(log.forSubject(subject).length, 1);
  att.subject = "did:key:zEVIL";
  assert.throws(() => log.add(att), /failed verification/);
});

test("attestation issuer key must match did:key", () => {
  const iss = generateKeypair();
  const other = generateKeypair();
  const issuer = didKeyFromPublic(iss.publicKey);
  const claim = { subject: "did:key:zX", type: "mandate-honored", issuer };
  const forged = { ...claim, proof: signing.makeProof(claim, other.seed) };
  assert.equal(verifyAttestation(forged as never), false);
});

test("did:web ssrf blocked", async () => {
  for (const bad of ["localhost", "127.0.0.1", "169.254.169.254", "10.0.0.5", "192.168.1.1", "foo.local", "::1"]) {
    assert.ok(hostIsBlocked(bad), bad);
  }
  for (const ok of ["example.com", "agents.acme.io", "8.8.8.8"]) {
    assert.ok(!hostIsBlocked(ok), ok);
  }
  await assert.rejects(() => resolve("did:web:169.254.169.254"), /private\/loopback/);
});

test("did:key length cap", () => {
  assert.throws(() => publicFromDidKey("did:key:z" + "1".repeat(200)), /implausibly long/);
});

test("cross-language wire compatibility (Ed25519 + JCS)", () => {
  // A fixed seed must produce a verifiable signature; this is the shared wire format.
  const seed = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
  const pub = signing.publicFromSeed(seed);
  const signed = signIdentity(didKeyIdentity(pub), seed);
  assert.equal(verifyIdentity(signed), true);
});
