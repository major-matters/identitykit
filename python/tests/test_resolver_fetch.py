"""The did:web body read runs under one overall deadline and the 1 MB cap (audit 2026-10-31, M1).

A local plain-HTTP server stands in for the did:web host so the read loop can be exercised
without TLS; the HTTPS and host guards in `_http_fetch` are tested elsewhere.
Run: python3 tests/test_resolver_fetch.py  (or pytest)
"""

import http.server
import os
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from identitykit.errors import ResolutionError  # noqa: E402
from identitykit.resolver import _MAX_BYTES, _read_body  # noqa: E402


class _Quiet(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep the test output clean
        pass


class _Drip(_Quiet):
    """Sends headers at once, then one byte every 50 ms, forever (until the client leaves)."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "1000000")
        self.end_headers()
        try:
            for _ in range(1000000):
                self.wfile.write(b" ")
                self.wfile.flush()
                time.sleep(0.05)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


class _Huge(_Quiet):
    """Sends well over the cap, quickly."""

    def do_GET(self):
        body = b" " * (_MAX_BYTES + 100_000)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


class _Small(_Quiet):
    def do_GET(self):
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _Server:
    def __init__(self, handler):
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]

    def __enter__(self):
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self.port

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


def _open(port):
    return urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5)  # nosec B310 - loopback test server


def test_slow_drip_body_is_cut_off_at_the_deadline():
    with _Server(_Drip) as port:
        resp = _open(port)
        start = time.monotonic()
        try:
            _read_body(resp, deadline=start + 0.6)
            assert False, "a dripping body was read to the end"
        except ResolutionError as e:
            assert "time budget" in str(e)
        elapsed = time.monotonic() - start
        assert elapsed < 3.0, f"deadline not honored: took {elapsed:.1f}s"
        resp.close()


def test_oversized_body_is_refused_at_the_cap():
    with _Server(_Huge) as port:
        resp = _open(port)
        try:
            _read_body(resp, deadline=time.monotonic() + 10)
            assert False, "an oversized body was accepted"
        except ResolutionError as e:
            assert "size limit" in str(e)
        resp.close()


def test_small_body_reads_whole():
    with _Server(_Small) as port:
        resp = _open(port)
        assert _read_body(resp, deadline=time.monotonic() + 10) == b'{"ok": true}'
        resp.close()


if __name__ == "__main__":
    test_slow_drip_body_is_cut_off_at_the_deadline()
    test_oversized_body_is_refused_at_the_cap()
    test_small_body_reads_whole()
    print("resolver fetch tests passed")
