# http-header-auditor

A stdlib-only, zero-dependency live HTTP security header scanner. No API
keys, no browser, no third-party services -- just Python 3's `urllib`.

## What it checks

- **Strict-Transport-Security (HSTS)**: present? `includeSubDomains`? long enough `max-age`?
  Eligible for the browser preload list (1 year + `includeSubDomains` + `preload`)?
- **X-Content-Type-Options**: `nosniff` present?
- **X-Frame-Options / CSP `frame-ancestors`**: clickjacking protection?
- **Content-Security-Policy**: present? overly permissive (`unsafe-inline`, `unsafe-eval`, wildcard `default-src`/`script-src`)?
- **Referrer-Policy**: present, and not `unsafe-url`/`no-referrer-when-downgrade`?
- **Permissions-Policy**: present?
- **Server / X-Powered-By**: leaking stack/version info?
- **Set-Cookie**: `Secure` / `HttpOnly` / `SameSite` on every cookie (each `Set-Cookie`
  header separately), `SameSite=None` without `Secure`, the `__Host-` (Secure, `Path=/`,
  no `Domain`) and `__Secure-` prefix rules, and session-looking cookies readable by scripts
- **CORS**: the request carries a foreign `Origin`; an `Access-Control-Allow-Origin` that echoes
  it (FAIL with `Allow-Credentials: true`), or `*` (info)
- **Cross-Origin-Opener / Embedder / Resource-Policy** (reported)
- **Subresource Integrity**: cross-origin `<script src>` and stylesheets in the page need
  `integrity=` hashes (and must not load over plain HTTP)
- **Redirects**: does plain `http://` redirect to HTTPS, and does the first hop go to
  `https://` on the *same* host (so the browser can pick up HSTS) before any cross-host
  redirect? (For an `https://` URL on the default port the `http://` twin is checked; if
  nothing listens on plain HTTP at all, that's reported as info.)

Every URL gets a **score and grade (A+ to F)** in the style of the Mozilla HTTP
Observatory: start at 100, subtract penalties (no CSP -25, no HSTS -20, no clickjacking
protection -20, no HTTP->HTTPS redirect -20, cookies without `Secure` -20, credentialed
CORS for any origin -50, scripts over plain HTTP -50, ...), and add bonuses (preload-eligible
HSTS, `frame-ancestors`, strict Referrer-Policy, SameSite on every cookie, SRI everywhere)
only once the score is 90 or more. The numbers follow the Observatory's published table
closely but this is an independent implementation, so grades can differ slightly.

## Install

```sh
pipx install git+https://git.canutethegreat.com/CanuteTheGreat/http-header-auditor.git        # latest release branch; puts `http-header-auditor` on PATH
pipx install git+https://git.canutethegreat.com/CanuteTheGreat/http-header-auditor.git@v1.2.0  # a pinned release
brew install canutethegreat/errant-tools/http-header-auditor   # after: brew tap canutethegreat/errant-tools https://git.canutethegreat.com/CanuteTheGreat/homebrew-errant-tools
scoop install errant-tools/http-header-auditor                 # after: scoop bucket add errant-tools https://git.canutethegreat.com/CanuteTheGreat/scoop-errant-tools
```

Or download the single file (stdlib-only Python 3.8+) and run it directly:
`curl -fsSLO https://errant.solutions/downloads/http_header_auditor.py && python3 http_header_auditor.py --help`.
Every [release](https://git.canutethegreat.com/CanuteTheGreat/http-header-auditor/releases) has a changelog, the wheel, the sdist and a `SHA256SUMS` file.
Not on PyPI yet, so plain `pipx install http-header-auditor` doesn't work until it's published there.

## Usage

```
http-header-auditor https://example.com [https://another.com ...]
http-header-auditor https://example.com --json
http-header-auditor https://example.com --fail-on weak        # exit 1 on WEAK too
http-header-auditor https://example.com --fail-on-grade B     # exit 1 if the grade is below B
http-header-auditor https://example.com --fail-on never       # report only
```

Exit codes (same convention as every Errant Solutions tool):

| Code | Meaning |
|---|---|
| 0 | no check at or above `--fail-on` (default `missing`: MISSING or FAIL) and the grade meets `--fail-on-grade` |
| 1 | otherwise |
| 2 | a target couldn't be fetched at all (connection or certificate error) and nothing else failed, or bad usage |

`--fail-on-missing-hsts` still works (exit 1 on missing HSTS even with `--fail-on never`);
`--fail-on-any-missing` is the same as the default. `--timeout N` sets the per-request
timeout in seconds (default 10). Python 3.8+. 1.x users note: the tool used to exit 0 by
default; it now fails on MISSING/FAIL checks like the other tools.

## Why this exists

Part of the [Errant Solutions](https://errant.solutions) toolbox: small,
free, stdlib-only auditing tools built from spare capacity. Pay what you
want if it's useful: see errant.solutions for the link.

## License

MIT — see LICENSE. Do whatever you want with it.
