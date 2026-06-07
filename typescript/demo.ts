/** IdentityKit demo. Run: npm run demo (node demo.ts). */

import {
  buildIdentity,
  signIdentity,
  verifyIdentity,
  didKeyFromPublic,
  generateKeypair,
  makeAttestation,
  ReputationLog,
  crosswalk,
  b64,
} from "./src/index.ts";

const LINE = "-".repeat(64);
const banner = (t: string) => console.log(`\n${LINE}\n  ${t}\n${LINE}`);

banner("1. Build and sign an agent identity (did:key)");
const { seed, publicKey } = generateKeypair();
const did = didKeyFromPublic(publicKey);
console.log(`  id: ${did.slice(0, 46)}...`);
const doc = buildIdentity(
  did,
  { name: "Acme Robotics", type: "org" },
  [{ id: `${did}#0`, purpose: ["controller", "mandate-issuer"], public_key: b64(publicKey) }],
  { capabilities: ["search", "purchase"], bindings: [{ standard: "ap2", ref: "ap2:issuer:acme" }], created: "2026-06-07T00:00:00Z" },
);
const signed = signIdentity(doc, seed);
console.log(`  verifyIdentity -> ${verifyIdentity(signed)}`);

banner("2. did:key is self-certifying");
const other = generateKeypair();
const forged = signIdentity(doc, other.seed);
console.log(`  verifyIdentity(forged) -> ${verifyIdentity(forged)}  (rejected)`);

banner("3. Cross-walk onto the standards");
const didDoc = crosswalk.toDidDocument(signed);
console.log("  W3C DID Document:", JSON.stringify(didDoc).slice(0, 160), "...");
const ap2 = crosswalk.ap2Issuer(signed);
console.log(`  AP2 issuer view (ties to MandateKit): operator=${JSON.stringify(ap2.operator)}, binding=${JSON.stringify(ap2.ap2_binding)}`);

banner("4. Reputation as verifiable claims (no score)");
const iss = generateKeypair();
const issuer = didKeyFromPublic(iss.publicKey);
const att = makeAttestation(did, "mandate-honored", issuer, iss.seed, { evidenceRef: "witnesskit:trail:9f2a", time: "2026-06-07T00:00:00Z" });
const log = new ReputationLog();
log.add(att);
console.log(`  attestation added and verified. claims about this agent: ${log.forSubject(did).length}`);

banner("5. Tamper is caught");
signed.operator.name = "Evil Corp";
console.log(`  changed operator name -> verifyIdentity = ${verifyIdentity(signed)}`);

banner("The 'who' beneath mandate / spend / witness.");
console.log("  github.com/major-matters  ·  majorlabs.co\n");
