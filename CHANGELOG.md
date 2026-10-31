# Changelog

Notable changes to this repository.

## 0.0.4 (TypeScript) and 0.0.3 (Python), 2026-10-31

Both packages. No change to the identity document, the attestation format or
the resolution rules for a well-formed did:web; a document signed by 0.0.2 or
0.0.3 verifies unchanged.

- `did_web_url` (Python) now does what `didWebUrl` (TypeScript) has done since
  the October fix: every `%3A` in the host becomes `:` (any case, not only the
  first) and the host must be a plain name or IP literal with an optional
  numeric port before a URL is built. A did:web with userinfo, a query, a
  fragment or a percent-encoded slash is rejected. Regression cases in both
  suites (`test_ssrf.py`, `ssrf.test.ts`), including `did:web:127.0.0.1%3A80@example.com`.
- did:web fetch: one deadline now covers headers and body in both languages.
  The TypeScript resolver cleared its timer when the headers arrived, so a
  server that then dripped the body held it open; the Python resolver read the
  body under a per-read socket timeout only. Both read the body in chunks under
  the 15 second budget and the existing 1 MB cap. Tests: a slow-drip server
  (Python) and a never-ending stream behind a stubbed `fetch` (TypeScript).
- Python `__version__` matches `pyproject.toml` (it had stayed at 0.0.1), and
  the did:web `User-Agent` string is derived from the package version in both
  languages instead of a literal.
- README: `cryptography` and `rfc8785` are declared dependencies, not optional
  extras; the pure-Python fallbacks cover only a checkout without them.
- Shared Ed25519 reference file: the docstring no longer names MandateKit (the
  file is the same bytes in all four signing kits); CI pins the SHA-256 of
  `ed25519.py`, `canonical.py` and `canonical.ts`.
- Repository: CI runs every file under `python/tests` through pytest
  (`test_ssrf.py` had never run in CI), installs with `npm ci`, pins every
  action to a commit SHA, declares read-only permissions and pins the Semgrep
  image; Dependabot for npm, pip and Actions; a tag-driven Release workflow
  with Trusted Publishing; SECURITY.md points to private vulnerability
  reporting; CITATION.cff carries the version.

## 0.0.3 (2026-10-07)

TypeScript package only; no change to the identity document, the resolver or
the attestation format.

- `npm test`, `npm run test:build` and `npm run demo` now pass
  `--experimental-strip-types`, so they work on Node 22.6 to 22.17 as the
  README promised (type stripping is unflagged only from 22.18).
- The module's exported `VERSION` now matches `package.json` (it had stayed at
  0.0.1 through the 0.0.2 release).
- README: the Node version note.

## 2026-09-08

- README: added "The accountability stack, September 2026" positioning section
  linking the suite to the MM Control Stack Compact.
