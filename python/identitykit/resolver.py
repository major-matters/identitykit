"""Resolve an identifier to a verified identity.

did:key is offline and self-certifying: the key is in the id. did:web fetches a
signed AgentIdentity document over HTTPS from the domain's well-known location
and verifies it. The fetch is injectable so resolution can be tested offline and
so callers can supply their own transport, caching, or allow-list.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.parse
import urllib.request
from typing import Callable, Dict, Optional

from . import signing
from .errors import InvalidIdentity, ResolutionError, UnsupportedMethod
from .identity import verify_identity

WELL_KNOWN = ".well-known/agent-identity.json"
_MAX_BYTES = 1_000_000  # refuse oversized documents

Fetcher = Callable[[str], Dict]


def did_web_url(id: str) -> str:
    """Map a did:web identifier to its HTTPS document URL (did:web spec path rules)."""
    parts = id.split(":")
    if len(parts) < 3 or parts[0] != "did" or parts[1] != "web":
        raise ResolutionError(f"not a did:web identifier: {id!r}")
    domain = parts[2].replace("%3A", ":")  # encoded port, if any
    segments = parts[3:]
    # Reject path-traversal / empty segments so a DID cannot escape its own path.
    if any(s in ("", ".", "..") for s in segments):
        raise ResolutionError(f"did:web has empty or traversal path segment: {id!r}")
    if segments:
        return f"https://{domain}/{'/'.join(segments)}/agent-identity.json"
    return f"https://{domain}/{WELL_KNOWN}"


def _parse_ipv4_octet(part: str) -> int:
    """Parse one octet as libc inet_aton does: hex (0x..), octal (0..), or decimal."""
    if part == "":
        raise ValueError("empty octet")
    low = part.lower()
    if low.startswith("0x"):
        return int(low, 16)
    if part.startswith("0") and len(part) > 1:
        return int(part, 8)
    return int(part, 10)


def _literal_to_ip(h: str):
    """Best-effort parse of an IP *literal* in any encoding the C resolver accepts
    (dotted decimal/octal/hex, 1-to-4-part shorthand, bare integer, IPv6,
    IPv4-mapped IPv6). Returns an ipaddress object, or None if `h` is a hostname.

    This closes the SSRF gap where ipaddress.ip_address() is strict but the actual
    socket connection's getaddrinfo() accepts forms like 2130706433 or 0x7f.0.0.1."""
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    parts = h.split(".")
    if not (1 <= len(parts) <= 4):
        return None
    try:
        nums = [_parse_ipv4_octet(p) for p in parts]
    except ValueError:
        return None
    # inet_aton shorthand: the final part absorbs the remaining low-order bytes.
    widths = {1: [32], 2: [8, 24], 3: [8, 8, 16], 4: [8, 8, 8, 8]}[len(parts)]
    shifts = {1: [0], 2: [24, 0], 3: [24, 16, 0], 4: [24, 16, 8, 0]}[len(parts)]
    value = 0
    for num, width, shift in zip(nums, widths, shifts):
        if num < 0 or num >= (1 << width):
            return None
        value |= num << shift
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _ip_is_blocked(ip) -> bool:
    """Block anything not globally routable, after unwrapping IPv4-mapped IPv6.
    Covers loopback, private, link-local (incl. 169.254.169.254), reserved,
    multicast, unspecified, and site-local in one rule."""
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        # Deprecated site-local fec0::/10 is classed global by ipaddress; block it.
        elif (int(ip) >> 118) == 0x3FB:  # fec0::/10
            return True
    return not ip.is_global


def _host_is_blocked(host: str) -> bool:
    """Block obvious SSRF targets across every IP encoding, plus internal-looking
    names. Does not resolve DNS, so a hostname pointing at an internal IP is still
    the caller's risk — use an allow-list for untrusted input."""
    h = host.strip().strip("[]").lower()
    if not h or h == "localhost" or h.endswith((".local", ".internal", ".localhost")):
        return True
    ip = _literal_to_ip(h)
    if ip is not None:
        return _ip_is_blocked(ip)
    return False


class _GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-apply the HTTPS + SSRF host checks on every redirect hop, so a public
    did:web document cannot 302 the resolver onto an internal host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise ResolutionError("did:web redirect to a non-HTTPS URL is blocked")
        host = urllib.parse.urlparse(newurl).hostname or ""
        if _host_is_blocked(host):
            raise ResolutionError(f"did:web redirect to a private/loopback host: {host!r}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_opener = urllib.request.build_opener(_GuardedRedirectHandler())


def _http_fetch(url: str) -> Dict:
    if not url.startswith("https://"):
        raise ResolutionError("did:web resolution requires HTTPS")
    host = urllib.parse.urlparse(url).hostname or ""
    if _host_is_blocked(host):
        raise ResolutionError(f"refusing to resolve a private/loopback host: {host!r}")
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "identitykit/0.0.2"})
    # https enforced above; redirects re-checked by _GuardedRedirectHandler.
    with _opener.open(req, timeout=15) as resp:  # nosec B310 # noqa: S310
        raw = resp.read(_MAX_BYTES + 1)
    if len(raw) > _MAX_BYTES:
        raise ResolutionError("identity document exceeds size limit")
    return json.loads(raw.decode("utf-8"))


def resolve(id: str, *, fetch: Optional[Fetcher] = None) -> Dict:
    """Resolve `id` to a verified result.

    did:web -> the fetched, signature-verified AgentIdentity document.
    did:key -> a minimal self-resolved stub carrying the controlling key. A
               did:key has no hosted document, so any richer AgentIdentity must
               travel alongside it and be checked with verify_identity().
    """
    if not isinstance(id, str) or id.count(":") < 2 or not id.startswith("did:"):
        raise ResolutionError(f"not a DID: {id!r}")
    method = id.split(":")[1]

    if method == "key":
        pub = signing.public_from_did_key(id)  # raises on a malformed key
        return {
            "id": id,
            "method": "key",
            "public_key": signing.b64(pub),
            "note": "did:key carries no hosted document; transport the signed AgentIdentity with it.",
        }

    if method == "web":
        url = did_web_url(id)
        doc = (fetch or _http_fetch)(url)
        if not isinstance(doc, dict):
            raise ResolutionError("fetched document is not a JSON object")
        if doc.get("id") != id:
            raise InvalidIdentity(f"document id {doc.get('id')!r} does not match requested {id!r}", field="id")
        if not verify_identity(doc):
            raise InvalidIdentity("fetched document failed verification")
        return doc

    raise UnsupportedMethod(f"no resolver for did method {method!r} (v0 supports key, web)")
