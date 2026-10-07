# Changelog

Notable changes to this repository.

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
