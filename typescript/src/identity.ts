/** The AgentIdentity document: signed, portable, with method-specific key control.
 *  did:key is self-certifying; did:web is domain-anchored. */

import * as signing from "./signing.ts";
import { InvalidIdentity } from "./errors.ts";

export const SCHEMA = "https://identitykit.dev/schema/agent-identity/v0";

export const VALID_PURPOSES = new Set(["controller", "auth", "mandate-issuer", "witness-signer", "assertion"]);
export const VALID_BINDING_STANDARDS = new Set(["did", "fido", "ap2", "eudi", "vc"]);
export const VALID_OPERATOR_TYPES = new Set(["org", "person"]);

export interface Key {
  id: string;
  purpose: string | string[];
  public_key: string;
}
export interface Operator {
  name: string;
  type: "org" | "person";
  [k: string]: unknown;
}
export interface Binding {
  standard: string;
  ref: string;
}
export interface AgentIdentity {
  "@schema": string;
  id: string;
  operator: Operator;
  keys: Key[];
  capabilities: string[];
  bindings: Binding[];
  created?: string;
  proof?: signing.Proof;
}

function req(cond: boolean, message: string, field?: string): void {
  if (!cond) throw new InvalidIdentity(message, field);
}

const purposesOf = (k: Key): string[] => (Array.isArray(k.purpose) ? k.purpose : [k.purpose]);

export interface BuildOpts {
  capabilities?: string[];
  bindings?: Binding[];
  created?: string;
}

export function buildIdentity(id: string, operator: Operator, keys: Key[], opts: BuildOpts = {}): AgentIdentity {
  const doc: AgentIdentity = {
    "@schema": SCHEMA,
    id,
    operator,
    keys,
    capabilities: [...(opts.capabilities ?? [])],
    bindings: [...(opts.bindings ?? [])],
  };
  if (opts.created !== undefined) doc.created = opts.created;
  validate(doc);
  return doc;
}

export function validate(doc: AgentIdentity): AgentIdentity {
  req(!!doc && typeof doc === "object", "identity must be an object");
  req(typeof doc.id === "string" && !!doc.id, "id is required", "id");
  const m = doc.id.split(":");
  req(m.length >= 3 && m[0] === "did" && (m[1] === "key" || m[1] === "web"), "id must be did:key or did:web", "id");

  const op = doc.operator;
  req(!!op && typeof op === "object", "operator is required", "operator");
  req(typeof op.name === "string" && !!op.name, "operator.name is required", "operator.name");
  req(VALID_OPERATOR_TYPES.has(op.type), "operator.type must be org|person", "operator.type");

  req(Array.isArray(doc.keys) && doc.keys.length >= 1, "at least one key is required", "keys");
  const seen = new Set<string>();
  doc.keys.forEach((k, i) => {
    req(!!k && typeof k === "object", `keys[${i}] must be an object`, "keys");
    req(typeof k.id === "string" && !!k.id, `keys[${i}].id is required`, "keys");
    req(!seen.has(k.id), `duplicate key id ${k.id}`, "keys");
    seen.add(k.id);
    req(typeof k.public_key === "string" && !!k.public_key, `keys[${i}].public_key is required`, "keys");
    req(purposesOf(k).every((p) => VALID_PURPOSES.has(p)), `keys[${i}].purpose invalid`, "keys");
    try {
      const decoded = signing.unb64(k.public_key);
      req(decoded.length > 0, `keys[${i}].public_key empty`, "keys");
    } catch {
      throw new InvalidIdentity(`keys[${i}].public_key is not valid base64`, "keys");
    }
  });

  const bindings = doc.bindings ?? [];
  req(Array.isArray(bindings), "bindings must be a list", "bindings");
  bindings.forEach((b, i) => {
    req(!!b && VALID_BINDING_STANDARDS.has(b.standard), `bindings[${i}].standard invalid`, "bindings");
    req(typeof b.ref === "string" && !!b.ref, `bindings[${i}].ref is required`, "bindings");
  });
  req(Array.isArray(doc.capabilities ?? []), "capabilities must be a list", "capabilities");
  return doc;
}

function body(doc: AgentIdentity): Record<string, unknown> {
  const { proof, ...rest } = doc;
  void proof;
  return rest;
}

export function signIdentity(doc: AgentIdentity, seed: Buffer, keyId?: string): AgentIdentity {
  validate(doc);
  const { proof: _omit, ...b } = doc;
  void _omit;
  return { ...b, proof: signing.makeProof(b, seed, keyId) };
}

export function verifyIdentity(doc: AgentIdentity): boolean {
  try {
    validate(doc);
    const proof = doc.proof;
    if (!proof || typeof proof !== "object") return false;
    const b = body(doc);
    if (!signing.verifyProof(b, proof)) return false;

    const proofKey = signing.unb64(proof.public_key);
    const method = doc.id.split(":")[1];

    if (method === "key") {
      return signing.publicFromDidKey(doc.id).equals(proofKey);
    }
    if (method === "web") {
      for (const k of doc.keys) {
        const ps = purposesOf(k);
        if (!ps.includes("controller") && !ps.includes("auth")) continue;
        if (signing.unb64(k.public_key).equals(proofKey)) return true;
      }
      return false;
    }
    return false;
  } catch {
    return false;
  }
}
