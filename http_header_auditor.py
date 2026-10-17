#!/usr/bin/env python3
"""
http-header-auditor: a stdlib-only, zero-dependency live HTTP security header
scanner for Errant Solutions (errant.solutions).

Fetches one or more URLs and reports on the presence/quality of security-
relevant HTTP response headers, without needing any API keys, browser, or
third-party service. Designed to be run from any machine with network access
and Python 3, no pip installs required.

Checks performed:
  - Strict-Transport-Security (HSTS): present? includeSubDomains? max-age long
    enough? preload-list eligible (1 year + includeSubDomains + preload)?
  - X-Content-Type-Options: nosniff present?
  - X-Frame-Options / frame-ancestors (CSP): clickjacking protection present?
  - Content-Security-Policy: present? overly permissive (unsafe-inline / * )?
  - Referrer-Policy: present and reasonably strict?
  - Permissions-Policy: present?
  - Server / X-Powered-By: version-revealing headers leaking stack info?
  - Set-Cookie: Secure / HttpOnly / SameSite flags, and the __Host- / __Secure-
    prefix rules, on every cookie set
  - CORS: Access-Control-Allow-Origin echoing any origin with credentials, or '*'
  - Cross-Origin-Opener/Embedder/Resource-Policy
  - Subresource Integrity on cross-origin scripts and stylesheets in the page
  - Redirects: does http:// redirect to https://, on the same host first?

Every URL gets an Observatory-style score (start at 100, penalties, bonuses
once the score is 90+) and a grade from A+ to F.

Output: human-readable report by default, or --json for machine-readable output.
Exit codes: 0 = nothing at or above --fail-on (default: missing) and the grade
meets --fail-on-grade, 1 = otherwise, 2 = a target couldn't be fetched at all
(when nothing else failed) or bad usage.

No third-party libraries. Uses only urllib from the Python standard library.
"""

__version__ = "1.2.0"

import argparse
import html.parser
import json
import sys
import ssl
import urllib.parse
import urllib.request
import urllib.error


USER_AGENT = "http-header-auditor/1.0 (+https://errant.solutions)"


PROBE_ORIGIN = "https://http-header-auditor.invalid"
GRADES = [(100, "A+"), (90, "A"), (85, "A-"), (80, "B+"), (70, "B"), (65, "B-"), (60, "C+"), (50, "C"),
          (45, "C-"), (40, "D+"), (30, "D"), (25, "D-"), (-10 ** 9, "F")]
GRADE_ORDER = [g for _, g in GRADES]


def grade_for(score):
    return next(g for floor, g in GRADES if score >= floor)


def fetch(url, timeout=10, allow_redirects=True, want_body=False):
    """Fetch a URL, return (final_url, status, headers_dict, redirect_chain[, body])."""
    r = _fetch(url, timeout, allow_redirects)
    return r if want_body else r[:4]


def _fetch(url, timeout=10, allow_redirects=True):
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
    req = urllib.request.Request(current_url, headers={"User-Agent": USER_AGENT, "Origin": PROBE_ORIGIN})
    try:
        resp = opener.open(req, timeout=timeout)
        final_url = resp.geturl()
        status = resp.status
        headers = list(resp.getheaders())  # list of pairs: Set-Cookie may repeat
        body = resp.read(2 * 1024 * 1024)
        resp.close()
        return final_url, status, headers, redirect_chain, body
    except urllib.error.HTTPError as e:
        headers = list(e.headers.items()) if e.headers else []
        try:
            body = e.read(2 * 1024 * 1024)
        except Exception:
            body = b""
        return e.url or current_url, e.code, headers, redirect_chain, body
    except Exception as e:
        reason = getattr(e, "reason", None) or e
        return None, str(reason), [], redirect_chain, b""


def norm_headers(headers):
    """Case-insensitive header lookup dict (repeated headers joined with ', ')."""
    out = {}
    for k, v in headers:
        k = k.lower()
        out[k] = out[k] + ", " + v if k in out else v
    return out


def check_hsts(h):
    val = h.get("strict-transport-security")
    if not val:
        return {"header": "Strict-Transport-Security", "status": "MISSING", "score": -20,
                "detail": "No HSTS header -- browsers will allow plain HTTP on this host."}
    max_age = None
    for part in val.split(";"):
        part = part.strip()
        if part.lower().startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1].strip().strip('"'))
            except ValueError:
                pass
    directives = [d.strip().lower() for d in val.split(";")]
    include_sub = "includesubdomains" in directives
    preload = "preload" in directives
    issues = []
    score = 0
    if max_age is None:
        issues.append("no max-age directive")
        score = -20
    elif max_age < 15552000:  # 180 days
        issues.append(f"max-age={max_age}s is under 180 days (recommended >=15552000)")
        score = -10
    if not include_sub:
        issues.append("missing includeSubDomains")
    eligible = bool(max_age and max_age >= 31536000 and include_sub and preload)
    if issues:
        return {"header": "Strict-Transport-Security", "status": "WEAK", "score": score, "preload_eligible": False,
                "detail": f"Present but: {'; '.join(issues)}. Raw: {val}"}
    need = [w for w, ok in (("max-age>=31536000", max_age >= 31536000), ("the preload directive", preload)) if not ok]
    note = " (preload-list eligible: 1 year, includeSubDomains, preload)" if eligible else (
        " (not preload-eligible: needs %s)" % " and ".join(need))
    return {"header": "Strict-Transport-Security", "status": "OK", "score": 5 if eligible else 0,
            "bonus": eligible, "preload_eligible": eligible, "detail": val + note}


def check_simple_present(h, header_name, expected_substr=None, friendly=None, missing_score=0):
    val = h.get(header_name.lower())
    friendly = friendly or header_name
    if not val:
        return {"header": header_name, "status": "MISSING", "score": missing_score,
                "detail": f"No {friendly} header present."}
    if expected_substr and expected_substr.lower() not in val.lower():
        return {"header": header_name, "status": "WEAK", "score": missing_score,
                "detail": f"Present but does not contain '{expected_substr}'. Raw: {val}"}
    return {"header": header_name, "status": "OK", "score": 0, "detail": val}


STRICT_REFERRERS = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}


def check_referrer(h):
    val = h.get("referrer-policy")
    if not val:
        return {"header": "Referrer-Policy", "status": "MISSING", "score": 0, "detail": "No Referrer-Policy header present."}
    last = [v.strip().lower() for v in val.split(",") if v.strip()][-1:]  # browsers use the last value they know
    if last and last[0] in ("unsafe-url", "no-referrer-when-downgrade"):
        return {"header": "Referrer-Policy", "status": "WEAK", "score": -5,
                "detail": f"'{last[0]}' sends full URLs to other sites. Raw: {val}"}
    if last and last[0] in STRICT_REFERRERS:
        return {"header": "Referrer-Policy", "status": "OK", "score": 5, "bonus": True, "detail": val}
    return {"header": "Referrer-Policy", "status": "OK", "score": 0, "detail": val}


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
        return {"header": "X-Frame-Options / frame-ancestors", "status": "OK", "score": 5 if has_frame_ancestors else 0,
                "bonus": has_frame_ancestors, "detail": "; ".join(detail)}
    return {"header": "X-Frame-Options / frame-ancestors", "status": "MISSING", "score": -20,
            "detail": "No clickjacking protection (neither X-Frame-Options nor CSP frame-ancestors)."}


def check_csp(h):
    csp = h.get("content-security-policy")
    if not csp:
        return {"header": "Content-Security-Policy", "status": "MISSING", "score": -25,
                "detail": "No CSP header -- no defense-in-depth against XSS/injection."}
    issues = []
    lower = csp.lower()
    if "unsafe-inline" in lower:
        issues.append("allows 'unsafe-inline'")
    if "unsafe-eval" in lower:
        issues.append("allows 'unsafe-eval'")
    for directive in lower.split(";"):
        tokens = directive.split()
        if tokens and tokens[0].rstrip(":") in ("default-src", "script-src") and "*" in tokens[1:]:
            issues.append(f"{tokens[0].rstrip(':')} is wildcard '*'")
    if issues:
        return {"header": "Content-Security-Policy", "status": "WEAK", "score": -20,
                "detail": f"Present but permissive: {'; '.join(issues)}. Raw: {csp}"}
    return {"header": "Content-Security-Policy", "status": "OK", "score": 0, "detail": csp}


def check_server_leak(h):
    server = h.get("server", "")
    xpb = h.get("x-powered-by", "")
    issues = []
    if server and any(c.isdigit() for c in server):
        issues.append(f"Server header reveals version: '{server}'")
    if xpb:
        issues.append(f"X-Powered-By header present: '{xpb}'")
    if issues:
        return {"header": "Server / X-Powered-By", "status": "INFO", "score": 0,
                "detail": "; ".join(issues)}
    return {"header": "Server / X-Powered-By", "status": "OK", "score": 0,
            "detail": "No version-revealing Server/X-Powered-By headers."}


SESSION_HINTS = ("sess", "sid", "auth", "token", "login", "jwt")


def check_cookies(headers_raw, https=True):
    """headers_raw is the list of (name, value) pairs, so every Set-Cookie header
    is audited, not just the last one."""
    cookies = [v for k, v in headers_raw if k.lower() == "set-cookie"]
    if not cookies:
        return {"header": "Set-Cookie", "status": "INFO", "detail": "No cookies set.", "score": 0}
    findings = []
    weak = False
    score = 0
    all_samesite = True
    for c in cookies:
        parts = [p.strip() for p in c.split(";")]
        name = parts[0].split("=", 1)[0].strip()
        attrs = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else "")
                 for p in parts[1:] if p}
        missing = [flag for flag in ("Secure", "HttpOnly", "SameSite") if flag.lower() not in attrs]
        notes = []
        if "samesite" not in attrs:
            all_samesite = False
        if attrs.get("samesite", "").lower() == "none" and "secure" not in attrs:
            notes.append("SameSite=None without Secure is rejected by browsers")
        if name.startswith("__Host-") and ("secure" not in attrs or attrs.get("path") != "/" or "domain" in attrs):
            notes.append("__Host- prefix requires Secure, Path=/ and no Domain (browsers drop it)")
            score -= 20
        elif name.startswith("__Secure-") and "secure" not in attrs:
            notes.append("__Secure- prefix requires Secure (browsers drop it)")
            score -= 20
        if https and "secure" not in attrs:
            score -= 20
        if "httponly" not in attrs and any(hint in name.lower() for hint in SESSION_HINTS):
            notes.append("looks like a session cookie but is readable by scripts")
            score -= 10
        if missing or notes:
            weak = True
            findings.append(f"cookie '{name}' missing: {', '.join(missing)}" if missing else f"cookie '{name}'")
            if notes:
                findings[-1] += " (" + "; ".join(notes) + ")"
        else:
            findings.append(f"cookie '{name}' OK")
    out = {"header": "Set-Cookie", "status": "WEAK" if weak else "OK", "detail": "; ".join(findings),
           "score": max(score, -40)}
    if not weak and all_samesite:
        out["score"], out["bonus"] = 5, True
    return out


def check_cors(h):
    acao = h.get("access-control-allow-origin", "").strip()
    creds = h.get("access-control-allow-credentials", "").strip().lower() == "true"
    if not acao:
        return {"header": "CORS", "status": "OK", "score": 0, "detail": "No Access-Control-Allow-Origin for a foreign Origin."}
    if acao == PROBE_ORIGIN or (acao == "null"):
        return {"header": "CORS", "status": "FAIL" if creds else "WEAK", "score": -50 if creds else -20,
                "detail": f"Access-Control-Allow-Origin echoes an arbitrary Origin ({acao})"
                          + (" WITH credentials -- any site can read authenticated responses" if creds else "")}
    if acao == "*":
        return {"header": "CORS", "status": "INFO", "score": 0,
                "detail": "Access-Control-Allow-Origin: * (fine for public content; never for anything per-user)"}
    return {"header": "CORS", "status": "OK", "score": 0, "detail": f"Access-Control-Allow-Origin: {acao}"}


def check_cross_origin_isolation(h):
    present = {n: h.get(n.lower()) for n in ("Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy",
                                             "Cross-Origin-Resource-Policy") if h.get(n.lower())}
    if not present:
        return {"header": "COOP / COEP / CORP", "status": "INFO", "score": 0,
                "detail": "None of Cross-Origin-Opener/Embedder/Resource-Policy set (optional hardening)."}
    weak = [k for k, v in present.items() if v.split(";")[0].strip().lower() in ("unsafe-none", "cross-origin")]
    return {"header": "COOP / COEP / CORP", "status": "OK", "score": 0,
            "detail": "; ".join(f"{k}: {v}" for k, v in present.items())
                      + (f" ({', '.join(weak)} explicitly permissive)" if weak else "")}


class _Subresources(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.items = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script" and a.get("src"):
            self.items.append(("script", a["src"], "integrity" in a))
        elif tag == "link" and "stylesheet" in (a.get("rel") or "").lower() and a.get("href"):
            self.items.append(("stylesheet", a["href"], "integrity" in a))


def check_sri(final_url, h, body):
    ctype = h.get("content-type", "").lower()
    text = body.decode("utf-8", "replace") if body else ""
    if "html" not in ctype and not text.lstrip()[:15].lower().startswith(("<!doctype html", "<html")):
        return {"header": "Subresource Integrity", "status": "INFO", "score": 0, "detail": "Not an HTML page."}
    p = _Subresources()
    try:
        p.feed(text)
    except Exception:
        pass
    host = urllib.parse.urlsplit(final_url).netloc.lower()
    external = []
    for kind, ref, has_integrity in p.items:
        full = urllib.parse.urljoin(final_url, ref)
        parts = urllib.parse.urlsplit(full)
        if parts.netloc.lower() != host:
            external.append((kind, full, parts.scheme, has_integrity))
    if not external:
        return {"header": "Subresource Integrity", "status": "OK", "score": 0,
                "detail": "No cross-origin scripts or stylesheets."}
    insecure = [u for _, u, scheme, _ in external if scheme == "http"]
    unprotected = [u for _, u, scheme, ok in external if not ok and scheme != "http"]
    if insecure:
        return {"header": "Subresource Integrity", "status": "FAIL", "score": -50,
                "detail": "Cross-origin resources loaded over plain HTTP: " + ", ".join(insecure)}
    if unprotected:
        return {"header": "Subresource Integrity", "status": "WEAK", "score": -5,
                "detail": "Cross-origin resources without an integrity= hash: " + ", ".join(unprotected)}
    return {"header": "Subresource Integrity", "status": "OK", "score": 5, "bonus": True,
            "detail": f"All {len(external)} cross-origin scripts/stylesheets carry integrity= hashes."}


def score_checks(checks):
    base = 100 + sum(c.get("score", 0) for c in checks if not c.get("bonus"))
    bonus = sum(c.get("score", 0) for c in checks if c.get("bonus"))
    total = base + bonus if base >= 90 else base
    return total, grade_for(total)


def audit_url(url, timeout=10):
    result = {"url": url, "checks": []}

    https_url = url
    if url.startswith("http://"):
        https_url = "https://" + url[len("http://"):]

    final_url, status, headers_raw, redirects, body = fetch(https_url, timeout=timeout, want_body=True)
    if final_url is None:
        result["error"] = f"Could not fetch {https_url} (connection/SSL error: {status})."
        return result

    h = norm_headers(headers_raw)
    result["final_url"] = final_url
    result["status_code"] = status

    result["checks"].append(check_hsts(h))
    result["checks"].append(check_simple_present(h, "X-Content-Type-Options", "nosniff", missing_score=-5))
    result["checks"].append(check_frame_protection(h))
    result["checks"].append(check_csp(h))
    result["checks"].append(check_referrer(h))
    result["checks"].append(check_simple_present(h, "Permissions-Policy"))
    result["checks"].append(check_server_leak(h))
    result["checks"].append(check_cookies(headers_raw, final_url.startswith("https://")))
    result["checks"].append(check_cors(h))
    result["checks"].append(check_cross_origin_isolation(h))
    result["checks"].append(check_sri(final_url, h, body))

    # HTTP -> HTTPS redirect check. For an https:// URL the plain-HTTP twin is
    # derived on port 80 (skipped when the URL names a non-default port, since the
    # matching HTTP port can't be known).
    http_url = None
    if url.startswith("http://"):
        http_url = url
    elif url.startswith("https://"):
        netloc = urllib.parse.urlsplit(url).netloc
        if ":" not in netloc.rsplit("]", 1)[-1]:
            http_url = "http://" + url[len("https://"):]
    if http_url:
        http_final, http_status, _, http_redirects = fetch(http_url, timeout=timeout)
        host = urllib.parse.urlsplit(http_url).hostname
        first = urllib.parse.urlsplit(http_redirects[0][2]) if http_redirects else None
        if http_final and http_final.startswith("https://") and first is not None and (
                first.scheme != "https" or first.hostname != host):
            result["checks"].append({"header": "HTTP->HTTPS redirect", "status": "WEAK", "score": -5,
                                      "detail": f"http:// ends at {http_final}, but the first redirect goes to "
                                                f"{http_redirects[0][2]} -- redirect to https://{host} first so "
                                                f"the browser can pick up HSTS for this host"})
        elif http_final and http_final.startswith("https://"):
            result["checks"].append({"header": "HTTP->HTTPS redirect", "status": "OK", "score": 0,
                                      "detail": f"http:// redirects to {http_final}"})
        elif http_final is None:
            result["checks"].append({"header": "HTTP->HTTPS redirect", "status": "INFO", "score": 0,
                                      "detail": f"Plain HTTP not served ({http_status}) -- nothing to redirect."})
        else:
            result["checks"].append({"header": "HTTP->HTTPS redirect", "status": "MISSING", "score": -20,
                                      "detail": f"Plain HTTP does not redirect to HTTPS (HTTP {http_status} "
                                                f"at {http_final})."})

    result["score"], result["grade"] = score_checks(result["checks"])
    return result


def print_report(results):
    for r in results:
        print(f"\n=== {r['url']} ===")
        if "error" in r:
            print(f"  ERROR: {r['error']}")
            continue
        print(f"  Final URL: {r.get('final_url')}  (HTTP {r.get('status_code')})")
        print(f"  Grade: {r['grade']}  (score {r['score']}/100)")
        for c in r["checks"]:
            marker = {"OK": "[OK]  ", "MISSING": "[MISS]", "WEAK": "[WEAK]", "INFO": "[INFO]",
                      "FAIL": "[FAIL]"}.get(c["status"], "[??]")
            pts = f" ({c['score']:+d})" if c.get("score") else ""
            print(f"  {marker} {c['header']}: {c['detail']}{pts}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="http-header-auditor", description="Live HTTP security header auditor (stdlib-only).",
                                 epilog="Exit codes: 0 clean, 1 checks at/above --fail-on or grade below --fail-on-grade, "
                                        "2 a target could not be fetched or bad usage.")
    ap.add_argument("--version", action="version", version="%(prog)s " + __version__)
    ap.add_argument("urls", nargs="+", help="One or more URLs to audit (https:// or http://)")
    ap.add_argument("--json", action="store_true", help="Output machine-readable JSON instead of text")
    ap.add_argument("--timeout", type=float, default=10, help="Per-request timeout in seconds (default 10)")
    ap.add_argument("--fail-on", choices=["missing", "weak", "never"], default="missing",
                    help="exit 1 when a check is MISSING/FAIL (default), also WEAK, or never")
    ap.add_argument("--fail-on-grade", metavar="GRADE", choices=GRADE_ORDER,
                    help="exit 1 when a URL's grade is worse than GRADE (e.g. B)")
    ap.add_argument("--fail-on-missing-hsts", action="store_true",
                    help="Exit 1 if any target is missing HSTS (even with --fail-on never)")
    ap.add_argument("--fail-on-any-missing", action="store_true",
                    help="Same as --fail-on missing (kept for 1.x scripts)")
    args = ap.parse_args(argv)

    results = [audit_url(u, timeout=args.timeout) for u in args.urls]

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_report(results)

    statuses = {"missing": ("MISSING", "FAIL"), "weak": ("MISSING", "FAIL", "WEAK"), "never": ()}[
        "missing" if args.fail_on_any_missing else args.fail_on]
    failed = errored = False
    for r in results:
        if "error" in r:
            errored = True
        for c in r.get("checks", []):
            if c["status"] in statuses:
                failed = True
            if args.fail_on_missing_hsts and c["header"] == "Strict-Transport-Security" and c["status"] == "MISSING":
                failed = True
        if args.fail_on_grade and "grade" in r and GRADE_ORDER.index(r["grade"]) > GRADE_ORDER.index(args.fail_on_grade):
            failed = True
    return 1 if failed else (2 if errored else 0)


if __name__ == "__main__":
    sys.exit(main())
