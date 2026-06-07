/** Cross-walk: map an AgentIdentity onto DID Documents, an AP2 issuer view, and
 *  external credential bindings. Pure functions, no network. */

import * as signing from "./signing.ts";
import { type AgentIdentity, type Key } from "./identity.ts";

const PURPOSE_TO_DID_REL: Record<string, string> = {
  auth: "authentication",
  assertion: "assertionMethod",
  "mandate-issuer": "assertionMethod",
  "witness-signer": "assertionMethod",
  controller: "capabilityInvocation",
};

const purposesOf = (k: Key): string[] => (Array.isArray(k.purpose) ? k.purpose : [k.purpose]);
const multibase = (publicKeyB64: string): string =>
  signing.didKeyFromPublic(signing.unb64(publicKeyB64)).slice("did:key:".length);

export function toDidDocument(doc: AgentIdentity): Record<string, unknown> {
  const did = doc.id;
  const vms: Record<string, unknown>[] = [];
  const rels: Record<string, string[]> = {};
  for (const k of doc.keys) {
    const vmId = k.id.startsWith(did) ? k.id : `${did}#${k.id.replace(/^#/, "")}`;
    vms.push({ id: vmId, type: "Ed25519VerificationKey2020", controller: did, publicKeyMultibase: multibase(k.public_key) });
    for (const p of purposesOf(k)) {
      const rel = PURPOSE_TO_DID_REL[p];
      if (rel) (rels[rel] ??= []).push(vmId);
    }
  }
  return { "@context": ["https://www.w3.org/ns/did/v1"], id: did, verificationMethod: vms, ...rels };
}

export function didKeyToDidDocument(did: string): Record<string, unknown> {
  const pub = signing.publicFromDidKey(did);
  const mb = signing.didKeyFromPublic(pub).slice("did:key:".length);
  const vmId = `${did}#${mb}`;
  return {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: did,
    verificationMethod: [{ id: vmId, type: "Ed25519VerificationKey2020", controller: did, publicKeyMultibase: mb }],
    authentication: [vmId],
    assertionMethod: [vmId],
    capabilityInvocation: [vmId],
  };
}

export interface Ap2IssuerView {
  issuer_id: string;
  operator?: string;
  mandate_issuer_keys: string[];
  ap2_binding: string | null;
}

export function ap2Issuer(doc: AgentIdentity): Ap2IssuerView {
  const keys = doc.keys.filter((k) => purposesOf(k).includes("mandate-issuer")).map((k) => k.public_key);
  const binding = doc.bindings?.find((b) => b.standard === "ap2")?.ref ?? null;
  return { issuer_id: doc.id, operator: doc.operator?.name, mandate_issuer_keys: keys, ap2_binding: binding };
}

export function bindingsFor(doc: AgentIdentity, standard: string): string[] {
  return (doc.bindings ?? []).filter((b) => b.standard === standard).map((b) => b.ref);
}
