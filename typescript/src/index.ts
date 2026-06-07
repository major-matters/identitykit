/** IdentityKit: portable, signed, resolvable agent identity plus the cross-walk
 *  onto DID, FIDO, AP2, and EUDI. Deterministic, fail-closed, off-the-shelf crypto.
 *
 *  The "who" beneath the agent-safety family. */

export { IdentityError, InvalidIdentity, ResolutionError, UnsupportedMethod } from "./errors.ts";
export {
  type AgentIdentity,
  type Key,
  type Operator,
  type Binding,
  buildIdentity,
  signIdentity,
  verifyIdentity,
  validate,
  SCHEMA,
} from "./identity.ts";
export { resolve, didWebUrl, type Fetcher } from "./resolver.ts";
export {
  generateKeypair,
  publicFromSeed,
  didKeyFromPublic,
  publicFromDidKey,
  b64,
  unb64,
  type Proof,
} from "./signing.ts";
export {
  makeAttestation,
  verifyAttestation,
  ReputationLog,
  type Attestation,
} from "./reputation.ts";
export * as crosswalk from "./crosswalk.ts";

export const VERSION = "0.0.1";
