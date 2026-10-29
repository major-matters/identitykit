/** Regression tests for the did:web SSRF guard (audit 2026-06-10, finding #2/#3/#10).
 *  Run: npm test (node --test). */

import { test } from "node:test";
import assert from "node:assert/strict";

import { hostIsBlocked, didWebUrl } from "../src/resolver.ts";

const BLOCKED = [
  "127.0.0.1", "2130706433", "0x7f.0.0.1", "0177.0.0.1", "127.1",
  "::ffff:127.0.0.1", "0:0:0:0:0:ffff:127.0.0.1",
  "169.254.169.254", "2852039166", "0xa9fea9fe",
  "localhost", "foo.internal", "x.local",
  "10.0.0.5", "192.168.1.1", "172.16.0.1", "100.64.0.1",
  "::1", "fe80::1", "fc00::1", "fd00::1", "fec0::1", "::", "0.0.0.0",
  "64:ff9b::7f00:1", // NAT64 of 127.0.0.1
];

const ALLOWED = ["example.com", "did.example.org", "93.184.216.34", "8.8.8.8", "2606:4700:4700::1111"];

test("every internal IP encoding is blocked", () => {
  for (const h of BLOCKED) assert.equal(hostIsBlocked(h), true, `SSRF leak: ${h}`);
});

test("globally routable hosts are allowed", () => {
  for (const h of ALLOWED) assert.equal(hostIsBlocked(h), false, `false block: ${h}`);
});

test("did:web path traversal is rejected", () => {
  for (const did of ["did:web:example.com:..:admin", "did:web:example.com:a::b", "did:web:example.com:."]) {
    assert.throws(() => didWebUrl(did), `not rejected: ${did}`);
  }
});

// 2026-10-29: did:web host handling. Every %3A becomes ":" (not only the first), and the host must be
// a plain name or IP literal with an optional numeric port; anything else is rejected before a URL is built.
test("didWebUrl decodes a %3A port and rejects hosts that are not plain host[:port]", () => {
  assert.equal(didWebUrl("did:web:example.com%3A8443"), "https://example.com:8443/.well-known/agent-identity.json");
  assert.equal(didWebUrl("did:web:example.com%3a8443:agents:alpha"), "https://example.com:8443/agents/alpha/agent-identity.json");
  for (const bad of [
    "did:web:example.com%3A8443%3A9000", // two ports after full replacement
    "did:web:example.com%2Fadmin", // percent-encoded slash
    "did:web:user@example.com", // userinfo
    "did:web:example.com?x=1", // query
    "did:web:example.com#frag", // fragment
    "did:web:", // empty host
  ]) {
    assert.throws(() => didWebUrl(bad), `not rejected: ${bad}`);
  }
});
