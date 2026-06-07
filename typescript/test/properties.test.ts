/** Property-based tests for IdentityKit. Run: npm test. */

import { test } from "node:test";
import fc from "fast-check";

import {
  buildIdentity,
  signIdentity,
  verifyIdentity,
  didKeyFromPublic,
  publicFromDidKey,
  generateKeypair,
  b64,
} from "../src/index.ts";
import * as signing from "../src/signing.ts";

const printable = fc.string({ minLength: 1, maxLength: 24 }).filter((s) => /^[\x20-\x7e]+$/.test(s));

test("did:key roundtrip for random keys", () => {
  fc.assert(
    fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), (bytes) => {
      const seed = Buffer.from(bytes);
      const pub = signing.publicFromSeed(seed);
      return publicFromDidKey(didKeyFromPublic(pub)).equals(pub);
    }),
  );
});

test("sign/verify roundtrips for valid identities", () => {
  fc.assert(
    fc.property(printable, fc.constantFrom("org", "person"), (name, otype) => {
      const { seed, publicKey } = generateKeypair();
      const did = didKeyFromPublic(publicKey);
      const doc = buildIdentity(did, { name, type: otype as "org" | "person" }, [
        { id: `${did}#0`, purpose: ["controller"], public_key: b64(publicKey) },
      ]);
      return verifyIdentity(signIdentity(doc, seed)) === true;
    }),
  );
});

test("any operator-name tamper breaks verification", () => {
  fc.assert(
    fc.property(printable, (newName) => {
      const { seed, publicKey } = generateKeypair();
      const did = didKeyFromPublic(publicKey);
      const doc = buildIdentity(did, { name: "original", type: "org" }, [
        { id: `${did}#0`, purpose: ["controller"], public_key: b64(publicKey) },
      ]);
      const signed = signIdentity(doc, seed);
      if (newName === "original") return true;
      signed.operator.name = newName;
      return verifyIdentity(signed) === false;
    }),
  );
});
