/** Resolve a DID to a verified identity. did:key offline; did:web over HTTPS
 *  with an injectable fetch. */

import * as signing from "./signing.ts";
import { InvalidIdentity, ResolutionError, UnsupportedMethod } from "./errors.ts";
import { type AgentIdentity, verifyIdentity } from "./identity.ts";

export const WELL_KNOWN = ".well-known/agent-identity.json";
const MAX_BYTES = 1_000_000;

export type Fetcher = (url: string) => Promise<unknown> | unknown;

export function didWebUrl(id: string): string {
  const parts = id.split(":");
  if (parts.length < 3 || parts[0] !== "did" || parts[1] !== "web") {
    throw new ResolutionError(`not a did:web identifier: ${id}`);
  }
  const domain = parts[2].replace("%3A", ":");
  const segments = parts.slice(3);
  return segments.length
    ? `https://${domain}/${segments.join("/")}/agent-identity.json`
    : `https://${domain}/${WELL_KNOWN}`;
}

/** Block obvious SSRF targets (loopback, private, link-local incl. the cloud
 *  metadata IP, internal-looking names). No DNS resolution, so a hostname
 *  pointing at an internal IP is still the caller's risk; use an allow-list for
 *  untrusted input. */
export function hostIsBlocked(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (!h || h === "localhost" || /\.(local|internal|localhost)$/.test(h)) return true;
  const v4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [a, b] = v4.slice(1).map(Number);
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 169 && b === 254) return true; // link-local + metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a >= 224) return true; // multicast/reserved
  }
  if (h === "::1" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80")) return true;
  return false;
}

async function httpFetch(url: string): Promise<unknown> {
  if (!url.startsWith("https://")) throw new ResolutionError("did:web resolution requires HTTPS");
  if (hostIsBlocked(new URL(url).hostname)) {
    throw new ResolutionError(`refusing to resolve a private/loopback host: ${new URL(url).hostname}`);
  }
  const res = await fetch(url, { headers: { Accept: "application/json", "User-Agent": "identitykit/0.0.1" } });
  if (!res.ok) throw new ResolutionError(`fetch failed: HTTP ${res.status}`);
  const text = await res.text();
  if (text.length > MAX_BYTES) throw new ResolutionError("identity document exceeds size limit");
  return JSON.parse(text);
}

export interface DidKeyResolution {
  id: string;
  method: "key";
  public_key: string;
  note: string;
}

export async function resolve(id: string, opts: { fetch?: Fetcher } = {}): Promise<AgentIdentity | DidKeyResolution> {
  if (typeof id !== "string" || !id.startsWith("did:") || (id.match(/:/g) ?? []).length < 2) {
    throw new ResolutionError(`not a DID: ${id}`);
  }
  const method = id.split(":")[1];

  if (method === "key") {
    const pub = signing.publicFromDidKey(id);
    return {
      id,
      method: "key",
      public_key: signing.b64(pub),
      note: "did:key carries no hosted document; transport the signed AgentIdentity with it.",
    };
  }

  if (method === "web") {
    const url = didWebUrl(id);
    const doc = (await (opts.fetch ?? httpFetch)(url)) as AgentIdentity;
    if (!doc || typeof doc !== "object") throw new ResolutionError("fetched document is not a JSON object");
    if (doc.id !== id) throw new InvalidIdentity(`document id ${doc.id} does not match requested ${id}`, "id");
    if (!verifyIdentity(doc)) throw new InvalidIdentity("fetched document failed verification");
    return doc;
  }

  throw new UnsupportedMethod(`no resolver for did method ${method} (v0 supports key, web)`);
}
