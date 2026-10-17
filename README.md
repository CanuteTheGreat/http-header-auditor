# http-header-auditor

A stdlib-only, zero-dependency live HTTP security header scanner. No API
keys, no browser, no third-party services -- just Python 3's `urllib`.

## What it checks

- **Strict-Transport-Security (HSTS)**: present? `includeSubDomains`? long enough `max-age`?
- **X-Content-Type-Options**: `nosniff` present?
- **X-Frame-Options / CSP `frame-ancestors`**: clickjacking protection?
- **Content-Security-Policy**: present? overly permissive (`unsafe-inline`, `unsafe-eval`, wildcard `default-src`)?
- **Referrer-Policy**: present?
- **Permissions-Policy**: present?
- **Server / X-Powered-By**: leaking stack/version info?
- **Set-Cookie**: `Secure` / `HttpOnly` / `SameSite` flags on every cookie set (each
  `Set-Cookie` header separately), plus `SameSite=None` without `Secure`
- **HTTP -> HTTPS redirect**: does plain `http://` actually redirect? (For an `https://`
  URL on the default port the `http://` twin is checked too; if nothing listens on plain
  HTTP at all, that's reported as info.)

## Usage

```
python3 http_header_auditor.py https://example.com [https://another.com ...]
python3 http_header_auditor.py https://example.com --json
python3 http_header_auditor.py https://example.com --fail-on-any-missing   # exit 1 if anything MISSING
python3 http_header_auditor.py https://example.com --fail-on-missing-hsts  # exit 1 only on missing HSTS
```

By default the tool always exits 0 (it's informational). Use the `--fail-on-*`
flags to opt into CI gating; with either flag set, a target that can't be fetched at
all (connection or certificate error) also exits 1. `--timeout N` sets the per-request
timeout in seconds (default 10). Python 3.8+.

## Why this exists

Part of the [Errant Solutions](https://errant.solutions) toolbox: small,
free, stdlib-only auditing tools built from spare capacity. Pay what you
want if it's useful: see errant.solutions for the link.

## License

MIT. Do whatever you want with it.
