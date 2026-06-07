/** Reputation as verifiable claims, not a score. Signed, evidence-linked
 *  attestations; verify on add; no aggregation. */

import * as signing from "./signing.ts";

export const VALID_TYPES = new Set([
  "mandate-honored",
  "action-witnessed",
  "dispute-raised",
  "dispute-resolved",
  "operator-verified",
]);

export interface Attestation {
  subject: string;
  type: string;
  issuer: string;
  evidence_ref?: string;
  time?: string;
  note?: string;
  proof: signing.Proof;
}

export interface MakeAttestationOpts {
  evidenceRef?: string;
  time?: string;
  note?: string;
}

export function makeAttestation(
  subject: string,
  type: string,
  issuerId: string,
  issuerSeed: Buffer,
  opts: MakeAttestationOpts = {},
): Attestation {
  if (!VALID_TYPES.has(type)) throw new Error(`type must be one of ${[...VALID_TYPES].join(", ")}`);
  const claim: Record<string, unknown> = { subject, type, issuer: issuerId };
  if (opts.evidenceRef !== undefined) claim.evidence_ref = opts.evidenceRef;
  if (opts.time !== undefined) claim.time = opts.time;
  if (opts.note !== undefined) claim.note = opts.note;
  return { ...(claim as object), proof: signing.makeProof(claim, issuerSeed) } as Attestation;
}

export function verifyAttestation(att: Attestation): boolean {
  try {
    if (!att || typeof att !== "object" || !VALID_TYPES.has(att.type)) return false;
    const proof = att.proof;
    if (!proof || typeof proof !== "object") return false;
    const { proof: _p, ...claim } = att;
    void _p;
    if (!signing.verifyProof(claim, proof)) return false;
    const issuer = att.issuer ?? "";
    if (typeof issuer === "string" && issuer.startsWith("did:key:")) {
      return signing.publicFromDidKey(issuer).equals(signing.unb64(proof.public_key));
    }
    return true;
  } catch {
    return false;
  }
}

export class ReputationLog {
  private items: Attestation[] = [];

  add(att: Attestation): void {
    if (!verifyAttestation(att)) throw new Error("attestation failed verification; refusing to add");
    this.items.push(att);
  }

  forSubject(subject: string): Attestation[] {
    return this.items.filter((a) => a.subject === subject);
  }

  get length(): number {
    return this.items.length;
  }
}
