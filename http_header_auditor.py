#!/usr/bin/env python3
"""
http-header-auditor: a stdlib-only, zero-dependency live HTTP security header
scanner for Errant Solutions (errant.solutions).

Fetches one or more URLs and reports on the presence/quality of security-
relevant HTTP response headers, without needing any API keys, browser, or
third-party service. Designed to be run from any machine with network access
and Python 3, no pip installs required.

Checks performed:
  - Strict-Transport-Security (HSTS): present? includeSubDomains? max-age long enough?
  - X-Content-Type-Options: nosniff present?
  - X-Frame-Options / frame-ancestors (CSP): clickjacking protection present?
  - Content-Security-Policy: present? overly permissive (unsafe-inline / * )?
  - Referrer-Policy: present and reasonably strict?
  - Permissions-Policy: present?
  - Server / X-Powered-By: version-revealing headers leaking stack info?
  - Set-Cookie: Secure / HttpOnly / SameSite flags on any cookies set?
  - Redirect behavior: does http:// redirect to https://?

Output: human-readable report by default, or --json for machine-readable output.
Exit code: 0 always by default (informational tool); pass --fail-on-missing-hsts
or --fail-on-any-missing to opt into non-zero exit codes for CI gating.

No third-party libraries. Uses only urllib from the Python standard library.
"""

import argparse
import json
import sys
import ssl
import urllib.request
import urllib.error
from http.client import HTTPResponse


USER_AGENT = "http-header-auditor/1.0 (+https://errant.solutions)"


def fetch(url, timeout=10, allow_redirects=True):
    """Fetch a URL, return (final_url, status, headers_dict, redirect_chain)."""
    redirect_chain = []
    current_url = url
    ctx = ssl.create_default_context()

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            redirect_chain.append((req.full_url, code, newurl))
            if not allow_redirects:
                return None
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(current_url, headers={"User-Agent": USER_AGENT})
    try:
        resp = opener.open(req, timeout=timeout)
        final_url = resp.geturl()
        status = resp.status
        headers = {k: v for k, v in resp.getheaders()}
        resp.close()
        return final_url, status, headers, redirect_chain
    except urllib.error.HTTPError as e:
        headers = {k: v for k, v in e.headers.items()} if e.headers else {}
        return e.url or current_url, e.code, headers, redirect_chain
    except Exception as e:
        return None, None, {}, redirect_chain


def norm_headers(headers):
    """Case-insensitive header lookup dict."""
    return {k.lower(): v for k, v in headers.items()}


def check_hsts(h):
    val = h.get("strict-transport-security")
    if not val:
        return {"header": "Strict-Transport-Security", "status": "MISSING",
                "detail": "No HSTS header -- browsers will allow plain HTTP on this host."}
    max_age = None
    for part in val.split(";"):
        part = part.strip()
        if part.lower().startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1])
            except ValueError:
                pass
    include_sub = "includesubdomains" in val.lower()
    issues = []
    if max_age is None:
        issues.append("no max-age directive")
    elif max_age < 15552000:  # 180 days
        issues.append(f"max-age={max_age}s is under 180 days (recommended >=15552000)")
    if not include_sub:
        issues.append("missing includeSubDomains")
    if issues:
        return {"header": "Strict-Transport-Security", "status": "WEAK",
                "detail": f"Present but: {'; '.join(issues)}. Raw: {val}"}
    return {"header": "Strict-Transport-Security", "status": "OK", "detail": val}


def check_simple_present(h, header_name, expected_substr=None, friendly=None):
    val = h.get(header_name.lower())
    friendly = friendly or header_name
    if not val:
        return {"header": header_name, "status": "MISSING",
                "detail": f"No {friendly} header present."}
    if expected_substr and expected_substr.lower() not in val.lower():
        return {"header": header_name, "status": "WEAK",
                "detail": f"Present but does not contain '{expected_substr}'. Raw: {val}"}
    return {"header": header_name, "status": "OK", "detail": val}


def check_frame_protection(h):
    xfo = h.get("x-frame-options")
    csp = h.get("content-security-policy", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    if xfo or has_frame_ancestors:
        detail = []
        if xfo:
            detail.append(f"X-Frame-Options: {xfo}")
        if has_frame_ancestors:
            detail.append("CSP frame-ancestors directive present")
        return {"header": "X-Frame-Options / frame-ancestors", "status": "OK",
                "detail": "; ".join(detail)}
    return {"header": "X-Frame-Options / frame-ancestors", "status": "MISSING",
            "detail": "No clickjacking protection (neither X-Frame-Options nor CSP frame-ancestors)."}


def check_csp(h):
    csp = h.get("content-security-policy")
    if not csp:
        return {"header": "Content-Security-Policy", "status": "MISSING",
                "detail": "No CSP header -- no defense-in-depth against XSS/injection."}
    issues = []
    lower = csp.lower()
    if "unsafe-inline" in lower:
        issues.append("allows 'unsafe-inline'")
    if "unsafe-eval" in lower:
        issues.append("allows 'unsafe-eval'")
    if "default-src *" in lower or "default-src: *" in lower:
        issues.append("default-src is wildcard '*'")
    if issues:
        return {"header": "Content-Security-Policy", "status": "WEAK",
                "detail": f"Present but permissive: {'; '.join(issues)}. Raw: {csp}"}
    return {"header": "Content-Security-Policy", "status": "OK", "detail": csp}


def check_server_leak(h):
    server = h.get("server", "")
    xpb = h.get("x-powered-by", "")
    issues = []
    if server and any(c.isdigit() for c in server):
        issues.append(f"Server header reveals version: '{server}'")
    if xpb:
        issues.append(f"X-Powered-By header present: '{xpb}'")
    if issues:
        return {"header": "Server / X-Powered-By", "status": "INFO",
                "detail": "; ".join(issues)}
    return {"header": "Server / X-Powered-By", "status": "OK",
            "detail": "No version-revealing Server/X-Powered-By headers."}


def check_cookies(headers_raw):
    # headers_raw may have multiple Set-Cookie values; http.client folds them
    # into one comma-joined string in some cases, so split conservatively.
    cookies = []
    for k, v in headers_raw.items():
        if k.lower() == "set-cookie":
            cookies.append(v)
    if not cookies:
        return {"header": "Set-Cookie", "status": "INFO", "detail": "No cookies set."}
    findings = []
    for c in cookies:
        flags_lower = c.lower()
        missing = []
        if "secure" not in flags_lower:
            missing.append("Secure")
        if "httponly" not in flags_lower:
            missing.append("HttpOnly")
        if "samesite" not in flags_lower:
            missing.append("SameSite")
        name = c.split("=", 1)[0]
        if missing:
            findings.append(f"cookie '{name}' missing: {', '.join(missing)}")
        else:
            findings.append(f"cookie '{name}' OK")
    status = "WEAK" if any("missing" in f for f in findings) else "OK"
    return {"header": "Set-Cookie", "status": status, "detail": "; ".join(findings)}


def audit_url(url, timeout=10):
    result = {"url": url, "checks": []}

    https_url = url
    if url.startswith("http://"):
        https_url = "https://" + url[len("http://"):]

    final_url, status, headers_raw, redirects = fetch(https_url, timeout=timeout)
    if final_url is None:
        result["error"] = f"Could not fetch {https_url} (connection/SSL error)."
        return result

    h = norm_headers(headers_raw)
    result["final_url"] = final_url
    result["status_code"] = status

    result["checks"].append(check_hsts(h))
    result["checks"].append(check_simple_present(h, "X-Content-Type-Options", "nosniff"))
    result["checks"].append(check_frame_protection(h))
    result["checks"].append(check_csp(h))
    result["checks"].append(check_simple_present(h, "Referrer-Policy"))
    result["checks"].append(check_simple_present(h, "Permissions-Policy"))
    result["checks"].append(check_server_leak(h))
    result["checks"].append(check_cookies(headers_raw))

    # HTTP -> HTTPS redirect check (only meaningful if original was http://)
    if url.startswith("http://"):
        http_final, http_status, _, http_redirects = fetch(url, timeout=timeout)
        if http_final and http_final.startswith("https://"):
            result["checks"].append({"header": "HTTP->HTTPS redirect", "status": "OK",
                                      "detail": f"http:// redirects to {http_final}"})
        else:
            result["checks"].append({"header": "HTTP->HTTPS redirect", "status": "MISSING",
                                      "detail": "Plain HTTP does not redirect to HTTPS."})

    return result


def print_report(results):
    for r in results:
        print(f"\n=== {r['url']} ===")
        if "error" in r:
            print(f"  ERROR: {r['error']}")
            continue
        print(f"  Final URL: {r.get('final_url')}  (HTTP {r.get('status_code')})")
        for c in r["checks"]:
            marker = {"OK": "[OK]  ", "MISSING": "[MISS]", "WEAK": "[WEAK]", "INFO": "[INFO]"}.get(c["status"], "[??]")
            print(f"  {marker} {c['header']}: {c['detail']}")


def main():
    ap = argparse.ArgumentParser(description="Live HTTP security header auditor (stdlib-only).")
    ap.add_argument("urls", nargs="+", help="One or more URLs to audit (https:// or http://)")
    ap.add_argument("--json", action="store_true", help="Output machine-readable JSON instead of text")
    ap.add_argument("--timeout", type=float, default=10, help="Per-request timeout in seconds (default 10)")
    ap.add_argument("--fail-on-missing-hsts", action="store_true",
                    help="Exit 1 if any target is missing HSTS")
    ap.add_argument("--fail-on-any-missing", action="store_true",
                    help="Exit 1 if any check comes back MISSING for any target")
    args = ap.parse_args()

    results = [audit_url(u, timeout=args.timeout) for u in args.urls]

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_report(results)

    exit_code = 0
    for r in results:
        for c in r.get("checks", []):
            if args.fail_on_any_missing and c["status"] == "MISSING":
                exit_code = 1
            if args.fail_on_missing_hsts and c["header"] == "Strict-Transport-Security" and c["status"] == "MISSING":
                exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
