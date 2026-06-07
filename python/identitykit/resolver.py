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
    if segments:
        return f"https://{domain}/{'/'.join(segments)}/agent-identity.json"
    return f"https://{domain}/{WELL_KNOWN}"


def _host_is_blocked(host: str) -> bool:
    """Block obvious SSRF targets: loopback, private, link-local (incl. the cloud
    metadata IP), and internal-looking names. Does not resolve DNS, so a hostname
    pointing at an internal IP is still the caller's risk — use an allow-list for
    untrusted input."""
    h = host.split(":")[0].strip("[]").lower()
    if not h or h == "localhost" or h.endswith((".local", ".internal", ".localhost")):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    except ValueError:
        return False


def _http_fetch(url: str) -> Dict:
    if not url.startswith("https://"):
        raise ResolutionError("did:web resolution requires HTTPS")
    host = urllib.parse.urlparse(url).hostname or ""
    if _host_is_blocked(host):
        raise ResolutionError(f"refusing to resolve a private/loopback host: {host!r}")
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "identitykit/0.0.1"})
    # https enforced above; file:/custom schemes cannot reach here.
    with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310 # noqa: S310
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
