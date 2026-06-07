/**
 * Document signing, verification, and the did:key codec, backed by Node's
 * built-in Ed25519 (no external crypto dependency). Keys are raw 32-byte values,
 * wire-compatible with the Python port: same canonical bytes, same signatures,
 * same base64. did:key uses standard multibase base58btc with the ed25519
 * multicodec prefix.
 */

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
} from "node:crypto";
import { canonicalize } from "./canonical.ts";

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface Proof {
  type: "Ed25519Signature2020";
  public_key: string;
  value: string;
  key_id?: string;
}

export function generateKeypair(): { seed: Buffer; publicKey: Buffer } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  return { seed: Buffer.from(seed), publicKey: Buffer.from(pub) };
}

function privFromSeed(seed: Buffer) {
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: "der", type: "pkcs8" });
}
function pubFromRaw(pub: Buffer) {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, pub]), format: "der", type: "spki" });
}

export function publicFromSeed(seed: Buffer): Buffer {
  const der = createPublicKey(privFromSeed(seed)).export({ format: "der", type: "spki" }).subarray(-32);
  return Buffer.from(der);
}

export function signBytes(message: Buffer, seed: Buffer): Buffer {
  return Buffer.from(nodeSign(null, message, privFromSeed(seed)));
}

export function verifyBytes(signature: Buffer, message: Buffer, publicKey: Buffer): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  try {
    return nodeVerify(null, message, pubFromRaw(publicKey), signature);
  } catch {
    return false;
  }
}

export const b64 = (b: Buffer): string => b.toString("base64");
export const unb64 = (s: string): Buffer => Buffer.from(s, "base64");

// -- base58btc (Bitcoin alphabet) --------------------------------------------

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_INDEX: Record<string, number> = Object.fromEntries([...B58].map((c, i) => [c, i]));

function b58encode(data: Buffer): string {
  let n = 0n;
  for (const byte of data) n = n * 256n + BigInt(byte);
  let out = "";
  while (n > 0n) {
    const r = Number(n % 58n);
    n = n / 58n;
    out = B58[r] + out;
  }
  let pad = 0;
  for (const b of data) { if (b === 0) pad++; else break; }
  return "1".repeat(pad) + out;
}

function b58decode(s: string): Buffer {
  let n = 0n;
  for (const ch of s) {
    if (!(ch in B58_INDEX)) throw new Error(`invalid base58 character ${ch}`);
    n = n * 58n + BigInt(B58_INDEX[ch]);
  }
  const bytes: number[] = [];
  while (n > 0n) { bytes.unshift(Number(n % 256n)); n = n / 256n; }
  let pad = 0;
  for (const ch of s) { if (ch === "1") pad++; else break; }
  return Buffer.from([...new Array(pad).fill(0), ...bytes]);
}

const ED25519_MULTICODEC = Buffer.from([0xed, 0x01]);

export function didKeyFromPublic(publicKey: Buffer): string {
  if (publicKey.length !== 32) throw new Error("ed25519 public key must be 32 bytes");
  return "did:key:z" + b58encode(Buffer.concat([ED25519_MULTICODEC, publicKey]));
}

export function publicFromDidKey(did: string): Buffer {
  if (!did.startsWith("did:key:z")) throw new Error("not an ed25519 did:key");
  // Cap input length so a hostile oversized string can't force a pathological
  // base58/bigint decode (a valid ed25519 did:key body is ~48 chars).
  if (did.length > 120) throw new Error("did:key is implausibly long");
  const decoded = b58decode(did.slice("did:key:z".length));
  if (decoded[0] !== 0xed || decoded[1] !== 0x01) throw new Error("did:key is not Ed25519");
  const pub = decoded.subarray(2);
  if (pub.length !== 32) throw new Error("decoded public key is not 32 bytes");
  return Buffer.from(pub);
}

// -- detached proof ----------------------------------------------------------

export function makeProof(document: unknown, seed: Buffer, keyId?: string): Proof {
  const proof: Proof = {
    type: "Ed25519Signature2020",
    public_key: b64(publicFromSeed(seed)),
    value: b64(signBytes(canonicalize(document), seed)),
  };
  if (keyId) proof.key_id = keyId;
  return proof;
}

export function verifyProof(document: unknown, proof: unknown): boolean {
  if (!proof || typeof proof !== "object") return false;
  const p = proof as Proof;
  if (p.type !== "Ed25519Signature2020") return false;
  try {
    return verifyBytes(unb64(p.value), canonicalize(document), unb64(p.public_key));
  } catch {
    return false;
  }
}
