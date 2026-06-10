/** Resolve a DID to a verified identity. did:key offline; did:web over HTTPS
 *  with an injectable fetch. */

import * as signing from "./signing.ts";
import { InvalidIdentity, ResolutionError, UnsupportedMethod } from "./errors.ts";
import { type AgentIdentity, verifyIdentity } from "./identity.ts";

export const WELL_KNOWN = ".well-known/agent-identity.json";
const MAX_BYTES = 1_000_000;

export type Fetcher = (url: string) => Promise<unknown> | unknown;

const FETCH_TIMEOUT_MS = 15_000;
const MAX_REDIRECTS = 3;

export function didWebUrl(id: string): string {
  const parts = id.split(":");
  if (parts.length < 3 || parts[0] !== "did" || parts[1] !== "web") {
    throw new ResolutionError(`not a did:web identifier: ${id}`);
  }
  const domain = parts[2].replace("%3A", ":");
  const segments = parts.slice(3);
  // Reject path-traversal / empty segments so a DID cannot escape its own path.
  if (segments.some((s) => s === "" || s === "." || s === "..")) {
    throw new ResolutionError(`did:web has empty or traversal path segment: ${id}`);
  }
  return segments.length
    ? `https://${domain}/${segments.join("/")}/agent-identity.json`
    : `https://${domain}/${WELL_KNOWN}`;
}

/** Parse one IPv4 octet as libc inet_aton does: hex (0x..), octal (0..), decimal. */
function parseV4Octet(p: string): number | null {
  if (p === "") return null;
  const low = p.toLowerCase();
  if (low.startsWith("0x")) return /^0x[0-9a-f]+$/.test(low) ? parseInt(low, 16) : null;
  if (p.startsWith("0") && p.length > 1) return /^[0-7]+$/.test(p) ? parseInt(p, 8) : null;
  return /^[0-9]+$/.test(p) ? parseInt(p, 10) : null;
}

/** Parse an IPv4 literal in any encoding (dotted decimal/octal/hex, 1-to-4-part
 *  shorthand, bare integer) into a 32-bit value, matching getaddrinfo. */
function literalToV4(h: string): number | null {
  const parts = h.split(".");
  if (parts.length < 1 || parts.length > 4) return null;
  const nums = parts.map(parseV4Octet);
  if (nums.some((n) => n === null)) return null;
  const ns = nums as number[];
  const widths = { 1: [32], 2: [8, 24], 3: [8, 8, 16], 4: [8, 8, 8, 8] }[parts.length]!;
  const shifts = { 1: [0], 2: [24, 0], 3: [24, 16, 0], 4: [24, 16, 8, 0] }[parts.length]!;
  let v = 0;
  for (let i = 0; i < ns.length; i++) {
    if (ns[i] < 0 || ns[i] >= 2 ** widths[i]) return null;
    v += ns[i] * 2 ** shifts[i];
  }
  return v >>> 0;
}

function v4Blocked(v: number): boolean {
  const a = (v >>> 24) & 255;
  const b = (v >>> 16) & 255;
  if (a === 0 || a === 10 || a === 127) return true; // this-network, private, loopback
  if (a === 169 && b === 254) return true; // link-local incl. 169.254.169.254 metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a >= 224) return true; // multicast + reserved + broadcast
  return false;
}

/** Expand an IPv6 literal (incl. :: compression and embedded IPv4) to 16 bytes. */
function ipv6ToBytes(h: string): Uint8Array | null {
  if (!h.includes(":")) return null;
  let str = h;
  // Fold an embedded IPv4 tail (e.g. ::ffff:127.0.0.1) into two hextets.
  const lastColon = str.lastIndexOf(":");
  const tail = str.slice(lastColon + 1);
  if (tail.includes(".")) {
    const v4 = literalToV4(tail);
    if (v4 === null) return null;
    str = str.slice(0, lastColon + 1) + ((v4 >>> 16) & 0xffff).toString(16) + ":" + (v4 & 0xffff).toString(16);
  }
  const halves = str.split("::");
  if (halves.length > 2) return null;
  let groups: string[];
  if (halves.length === 2) {
    const head = halves[0] ? halves[0].split(":") : [];
    const back = halves[1] ? halves[1].split(":") : [];
    const missing = 8 - head.length - back.length;
    if (missing < 1) return null;
    groups = [...head, ...Array(missing).fill("0"), ...back];
  } else {
    groups = str.split(":");
  }
  if (groups.length !== 8) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(groups[i])) return null;
    const val = parseInt(groups[i], 16);
    bytes[i * 2] = (val >> 8) & 255;
    bytes[i * 2 + 1] = val & 255;
  }
  return bytes;
}

function v6Blocked(b: Uint8Array): boolean {
  // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible: check the embedded v4.
  const firstTen = b.slice(0, 10).every((x) => x === 0);
  if (firstTen && b[10] === 0xff && b[11] === 0xff) {
    return v4Blocked(((b[12] << 24) | (b[13] << 16) | (b[14] << 8) | b[15]) >>> 0);
  }
  if (b.every((x) => x === 0)) return true; // ::
  if (firstTen && b[10] === 0 && b[11] === 0 && b[15] === 1) return true; // ::1 loopback
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true; // fe80::/10 link-local
  if ((b[0] & 0xfe) === 0xfc) return true; // fc00::/7 unique-local
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0xc0) return true; // fec0::/10 site-local
  if (b[0] === 0xff) return true; // ff00::/8 multicast
  // 64:ff9b::/96 NAT64: block the prefix and the IPv4 it translates.
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) {
    return v4Blocked(((b[12] << 24) | (b[13] << 16) | (b[14] << 8) | b[15]) >>> 0);
  }
  return false;
}

/** Block SSRF targets across every IP encoding (loopback, private, link-local
 *  incl. the cloud metadata IP, internal-looking names). No DNS resolution, so a
 *  hostname pointing at an internal IP is still the caller's risk; use an
 *  allow-list for untrusted input. */
export function hostIsBlocked(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").trim().toLowerCase();
  if (!h || h === "localhost" || /\.(local|internal|localhost)$/.test(h)) return true;
  const v6 = ipv6ToBytes(h);
  if (v6) return v6Blocked(v6);
  const v4 = literalToV4(h);
  if (v4 !== null) return v4Blocked(v4);
  return false; // a hostname; not resolved here
}

async function httpFetch(url: string, redirectsLeft = MAX_REDIRECTS): Promise<unknown> {
  if (!url.startsWith("https://")) throw new ResolutionError("did:web resolution requires HTTPS");
  const host = new URL(url).hostname;
  if (hostIsBlocked(host)) {
    throw new ResolutionError(`refusing to resolve a private/loopback host: ${host}`);
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetch(url, {
      headers: { Accept: "application/json", "User-Agent": "identitykit/0.0.2" },
      redirect: "manual",
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
  // Re-check the SSRF guard on every redirect hop rather than following blindly.
  if (res.status >= 300 && res.status < 400) {
    const loc = res.headers.get("location");
    if (!loc) throw new ResolutionError("did:web redirect without a Location header");
    if (redirectsLeft <= 0) throw new ResolutionError("did:web exceeded redirect limit");
    return httpFetch(new URL(loc, url).toString(), redirectsLeft - 1);
  }
  if (!res.ok) throw new ResolutionError(`fetch failed: HTTP ${res.status}`);
  // Stream with a hard byte cap so a huge/slow body cannot exhaust memory.
  const reader = res.body?.getReader();
  if (!reader) throw new ResolutionError("did:web response has no body");
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.length;
      if (total > MAX_BYTES) {
        await reader.cancel();
        throw new ResolutionError("identity document exceeds size limit");
      }
      chunks.push(value);
    }
  }
  const buf = Buffer.concat(chunks.map((c) => Buffer.from(c)));
  return JSON.parse(buf.toString("utf8"));
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
