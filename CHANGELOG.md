# Changelog

All notable changes. Versions are git tags; each tag has a Forgejo release with checksums.

## 1.2.0 - 2026-10-16

- **Score and grade (A+ to F)** in the style of the Mozilla HTTP Observatory, with `--fail-on-grade`.
- New checks: HSTS preload-list eligibility, cookie `__Host-`/`__Secure-` prefix rules and script-readable
  session cookies, CORS (an `Access-Control-Allow-Origin` echoing any origin, with or without credentials),
  Cross-Origin-Opener/Embedder/Resource-Policy, Subresource Integrity on cross-origin scripts/stylesheets,
  Referrer-Policy strength, and the redirect chain (first hop must be HTTPS on the same host).
- **Exit codes now follow the shared convention:** `--fail-on` (default `missing`) makes MISSING/FAIL
  checks exit 1, and an unreachable target exits 2. 1.x exited 0 unless a `--fail-on-*` flag was given;
  pass `--fail-on never` for the old behaviour.
- Installable as a package: `pipx install git+https://git.canutethegreat.com/CanuteTheGreat/http-header-auditor.git`
  puts a `http-header-auditor` command on PATH (pyproject.toml, MIT license metadata).
- `--version` flag.
- Exit codes follow the shared convention: 0 = clean, 1 = findings at/above the gate, 2 = error or bad usage.
- Every tag now publishes a Forgejo release with this changelog, the wheel, the sdist and SHA256SUMS.
- CI installs the package with pip in a clean venv and checks `--version`/`--help` on every push.

## 1.1.0 - 2026-10-16

- Audit every Set-Cookie header by attribute, exact CSP wildcard parsing, quoted HSTS max-age, check the http:// twin of https URLs, unreachable targets fail --fail-on-* gates; add CI tests
- Add MIT LICENSE file

## 1.0.0 - 2026-09-17

- First public release.
