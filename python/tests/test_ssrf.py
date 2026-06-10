"""Regression tests for the did:web SSRF guard (audit 2026-06-10, finding #2/#3/#10).

The strict ipaddress.ip_address() check let alternate IP encodings through that
getaddrinfo() still resolves to internal hosts. These lock the normalized guard.
Run: python3 tests/test_ssrf.py  (or pytest)
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from identitykit.resolver import _host_is_blocked, did_web_url  # noqa: E402
from identitykit.errors import ResolutionError  # noqa: E402

# Every encoding of an internal address the resolver must refuse.
BLOCKED = [
    "127.0.0.1", "2130706433", "0x7f.0.0.1", "0177.0.0.1", "127.1",
    "::ffff:127.0.0.1", "0:0:0:0:0:ffff:127.0.0.1",
    "169.254.169.254", "2852039166", "0xa9fea9fe",  # cloud metadata, decimal + hex
    "localhost", "foo.internal", "x.local",
    "10.0.0.5", "192.168.1.1", "172.16.0.1", "100.64.0.1",
    "::1", "fe80::1", "fc00::1", "fd00::1", "fec0::1", "::", "0.0.0.0",
]

# Globally routable hosts the resolver must still allow.
ALLOWED = ["example.com", "did.example.org", "93.184.216.34", "8.8.8.8", "2606:4700:4700::1111"]


def test_blocked_encodings():
    for h in BLOCKED:
        assert _host_is_blocked(h), f"SSRF leak: {h!r} was not blocked"


def test_public_hosts_allowed():
    for h in ALLOWED:
        assert not _host_is_blocked(h), f"false block: {h!r}"


def test_path_traversal_rejected():
    for did in ["did:web:example.com:..:admin", "did:web:example.com:a::b", "did:web:example.com:."]:
        try:
            did_web_url(did)
            assert False, f"path traversal not rejected: {did!r}"
        except ResolutionError:
            pass


if __name__ == "__main__":
    test_blocked_encodings()
    test_public_hosts_allowed()
    test_path_traversal_rejected()
    print("SSRF regression tests passed")
