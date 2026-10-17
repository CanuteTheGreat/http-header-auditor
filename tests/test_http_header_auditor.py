"""End-to-end tests for http_header_auditor.py (run unmodified as a subprocess).

A real local HTTPS server on 127.0.0.1:443 (certificate from a throwaway CA
made with the openssl CLI, trusted through SSL_CERT_FILE) and a plain-HTTP
server on 127.0.0.1:80 serve one response profile per path, so every check
runs against real TLS, real redirects and real repeated Set-Cookie headers.
Ports 80/443 need root, which the CI container (ci/run-tests.sh) has.
"""
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "http_header_auditor.py")

GOOD = [("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
        ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"),
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"), ("Permissions-Policy", "camera=()"),
        ("Set-Cookie", "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"),
        ("Set-Cookie", "csrf=xyz; Path=/; Secure; HttpOnly; SameSite=Strict")]
PROFILES = {
    "/good": (200, GOOD),
    "/weak": (200, [("Strict-Transport-Security", "max-age=300"), ("X-Content-Type-Options", "sniff-please"),
                    ("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'"),
                    ("Server", "nginx/1.18.0"), ("X-Powered-By", "PHP/8.1.2"),
                    ("Set-Cookie", "pref=2; Secure; HttpOnly; SameSite=Lax"),
                    ("Set-Cookie", "sid=1; Path=/"),
                    ("Set-Cookie", "secure_httponly_samesite=1; Path=/")]),
    "/bare": (200, []),
    "/quoted": (200, [("Strict-Transport-Security", 'max-age="31536000"; includeSubDomains'),
                      ("Content-Security-Policy", "default-src 'self' *.example.test; script-src *"),
                      ("Set-Cookie", "x=1; HttpOnly; SameSite=None")]),
    "/missing-page": (404, [("Strict-Transport-Security", "max-age=31536000; includeSubDomains")]),
    "/cookies": (200, GOOD[:6] + [("Set-Cookie", "__Host-sid=1; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=localhost"),
                                  ("Set-Cookie", "__Secure-pref=1; HttpOnly; SameSite=Lax"),
                                  ("Set-Cookie", "session_token=1; Secure; SameSite=Lax"),
                                  ("Set-Cookie", "__Host-ok=1; Secure; HttpOnly; SameSite=Strict; Path=/")]),
    "/cors-echo": (200, GOOD[:6] + [("Access-Control-Allow-Origin", "ECHO"), ("Access-Control-Allow-Credentials", "true")]),
    "/cors-echo-nocreds": (200, GOOD[:6] + [("Access-Control-Allow-Origin", "ECHO")]),
    "/cors-star": (200, GOOD[:6] + [("Access-Control-Allow-Origin", "*")]),
    "/isolated": (200, GOOD[:6] + [("Cross-Origin-Opener-Policy", "same-origin"),
                                   ("Cross-Origin-Resource-Policy", "same-site"), ("Content-Type", "text/html")]),
    "/sri-ok": (200, GOOD[:6] + [("Content-Type", "text/html; charset=utf-8")]),
    "/sri-missing": (200, GOOD[:6] + [("Content-Type", "text/html")]),
    "/sri-http": (200, GOOD[:6] + [("Content-Type", "text/html")]),
    "/referrer-unsafe": (200, [h for h in GOOD[:6] if h[0] != "Referrer-Policy"] + [("Referrer-Policy", "unsafe-url")]),
}
BODIES = {
    "/sri-ok": b'<!doctype html><script src="/local.js"></script><script src="https://cdn.example.test/a.js" '
               b'integrity="sha384-abc" crossorigin="anonymous"></script>'
               b'<link rel="stylesheet" href="https://cdn.example.test/a.css" integrity="sha384-def">',
    "/sri-missing": b'<html><script src="https://cdn.example.test/a.js"></script>'
                    b'<link rel="stylesheet" href="//cdn.example.test/a.css"></html>',
    "/sri-http": b'<html><script src="http://cdn.example.test/a.js" integrity="sha384-x"></script></html>',
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def version_string(self):
        return "nginx"  # instead of BaseHTTP/x Python/y, which leaks a version

    def do_GET(self):
        if self.path == "/hop":
            self.send_response(302)
            self.send_header("Location", "/good")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/slow":
            time.sleep(4)
        if self.path == "/cross-host-hop":
            self.send_response(301)
            self.send_header("Location", "https://127.0.0.1/good")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        code, headers = PROFILES.get(self.path, (200, []))
        body = BODIES.get(self.path, b"<html><body>test</body></html>")
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, self.headers.get("Origin", "") if v == "ECHO" else v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class PlainHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/sri-ok":  # first hop goes to another host's https, not this host's
            self.send_response(301)
            self.send_header("Location", "https://127.0.0.1/sri-ok")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/bare":  # this one is served over plain HTTP without a redirect
            body = b"plain"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(301)
        self.send_header("Location", "https://localhost" + self.path)
        self.send_header("Content-Length", "0")
        self.end_headers()


def openssl(*args):
    subprocess.run(["openssl"] + list(args), check=True, capture_output=True)


def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    SERVERS.append(server)
    return server


def setUpModule():
    global TMP, CA, SERVERS, ALT_PORT
    SERVERS = []
    TMP = tempfile.mkdtemp()
    CA, ca_key = os.path.join(TMP, "ca.pem"), os.path.join(TMP, "ca.key")
    key, csr, crt, ext = (os.path.join(TMP, n) for n in ("srv.key", "srv.csr", "srv.crt", "srv.ext"))
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", ca_key, "-out", CA, "-days", "2",
            "-subj", "/CN=http-header-auditor test CA", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    with open(ext, "w") as f:
        f.write("subjectAltName=DNS:localhost,IP:127.0.0.1,IP:127.0.0.3\nbasicConstraints=CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
                "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", "/CN=localhost")
    openssl("x509", "-req", "-in", csr, "-CA", CA, "-CAkey", ca_key, "-CAcreateserial", "-days", "2",
            "-out", crt, "-extfile", ext)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    for addr in (("0.0.0.0", 443), ("127.0.0.1", 0)):
        s = ThreadingHTTPServer(addr, Handler)
        s.socket = ctx.wrap_socket(s.socket, server_side=True)
        serve(s)
    ALT_PORT = SERVERS[-1].server_address[1]
    serve(ThreadingHTTPServer(("127.0.0.1", 80), PlainHandler))  # 127.0.0.3 has no plain HTTP


def tearDownModule():
    for s in SERVERS:
        s.shutdown()
    shutil.rmtree(TMP, ignore_errors=True)


def run(*args):
    env = dict(os.environ, SSL_CERT_FILE=CA)
    return subprocess.run([sys.executable, TOOL] + list(args), capture_output=True, text=True, env=env,
                          timeout=120)


def audit(url, *extra):
    p = run(url, "--json", *extra)
    res = json.loads(p.stdout)
    return p, res[0], {c["header"]: c for c in res[0].get("checks", [])}


class TestChecks(unittest.TestCase):
    def test_good_site_all_ok(self):
        p, r, c = audit("https://localhost/good")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(r["status_code"], 200)
        bad = {k: v for k, v in c.items() if v["status"] != "OK" and k != "COOP / COEP / CORP"}
        self.assertEqual(bad, {})
        self.assertEqual(c["COOP / COEP / CORP"]["status"], "INFO")
        self.assertEqual((r["score"], r["grade"]), (120, "A+"))  # 100 + preload + frame-ancestors + referrer + SameSite
        self.assertTrue(c["Strict-Transport-Security"]["preload_eligible"])
        self.assertEqual(c["Set-Cookie"]["detail"], "cookie 'sid' OK; cookie 'csrf' OK")
        self.assertIn("http:// redirects to https://localhost/good", c["HTTP->HTTPS redirect"]["detail"])

    def test_weak_site(self):
        _, _, c = audit("https://localhost/weak")
        hsts = c["Strict-Transport-Security"]
        self.assertEqual(hsts["status"], "WEAK")
        self.assertIn("max-age=300s is under 180 days", hsts["detail"])
        self.assertIn("missing includeSubDomains", hsts["detail"])
        self.assertEqual(c["X-Content-Type-Options"]["status"], "WEAK")
        csp = c["Content-Security-Policy"]
        self.assertEqual(csp["status"], "WEAK")
        for needle in ("unsafe-inline", "unsafe-eval", "default-src is wildcard"):
            self.assertIn(needle, csp["detail"])
        self.assertEqual(c["X-Frame-Options / frame-ancestors"]["status"], "MISSING")
        leak = c["Server / X-Powered-By"]
        self.assertEqual(leak["status"], "INFO")
        self.assertIn("nginx/1.18.0", leak["detail"])
        self.assertIn("PHP/8.1.2", leak["detail"])
        cookies = c["Set-Cookie"]
        self.assertEqual(cookies["status"], "WEAK")
        # every Set-Cookie header is audited, attribute names (not substrings) decide
        self.assertIn("cookie 'pref' OK", cookies["detail"])
        self.assertIn("cookie 'sid' missing: Secure, HttpOnly, SameSite", cookies["detail"])
        self.assertIn("cookie 'secure_httponly_samesite' missing: Secure, HttpOnly, SameSite", cookies["detail"])

    def test_bare_site_missing_and_no_redirect(self):
        _, _, c = audit("https://localhost/bare")
        for h in ("Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options / frame-ancestors",
                  "Content-Security-Policy", "Referrer-Policy", "Permissions-Policy", "HTTP->HTTPS redirect"):
            self.assertEqual(c[h]["status"], "MISSING", h)
        self.assertEqual(c["Set-Cookie"], {"header": "Set-Cookie", "status": "INFO", "detail": "No cookies set.", "score": 0})

    def test_quoted_max_age_csp_parsing_and_samesite_none(self):
        _, _, c = audit("https://localhost/quoted")
        self.assertEqual(c["Strict-Transport-Security"]["status"], "OK")
        csp = c["Content-Security-Policy"]["detail"]
        self.assertIn("script-src is wildcard", csp)
        self.assertNotIn("default-src is wildcard", csp)  # *.example.test is not '*'
        self.assertIn("SameSite=None without Secure", c["Set-Cookie"]["detail"])

    def test_grades(self):
        _, r, _ = audit("https://localhost/bare")
        # no CSP -25, no HSTS -20, no XFO -20, no nosniff -5, no redirect -20 => 10
        self.assertEqual((r["score"], r["grade"]), (10, "F"))
        _, r, _ = audit("https://localhost/weak")
        self.assertEqual(r["grade"], "F")
        _, r, c = audit("https://localhost/quoted")
        self.assertFalse(c["Strict-Transport-Security"]["preload_eligible"])
        self.assertIn("needs the preload directive", c["Strict-Transport-Security"]["detail"])

    def test_cookie_prefixes_and_session_cookies(self):
        _, _, c = audit("https://localhost/cookies")
        d = c["Set-Cookie"]["detail"]
        self.assertIn("cookie '__Host-sid' (__Host- prefix requires Secure, Path=/ and no Domain", d)
        self.assertIn("cookie '__Secure-pref' missing: Secure (__Secure- prefix requires Secure", d)
        self.assertIn("cookie 'session_token' missing: HttpOnly (looks like a session cookie", d)
        self.assertIn("cookie '__Host-ok' OK", d)
        self.assertEqual(c["Set-Cookie"]["score"], -40)  # capped

    def test_cors(self):
        _, _, c = audit("https://localhost/cors-echo")
        self.assertEqual(c["CORS"]["status"], "FAIL")
        self.assertIn("WITH credentials", c["CORS"]["detail"])
        self.assertEqual(audit("https://localhost/cors-echo")[0].returncode, 1)
        self.assertEqual(audit("https://localhost/cors-echo-nocreds")[2]["CORS"]["status"], "WEAK")
        self.assertEqual(audit("https://localhost/cors-star")[2]["CORS"]["status"], "INFO")
        self.assertEqual(audit("https://localhost/good")[2]["CORS"]["status"], "OK")

    def test_cross_origin_isolation_headers(self):
        c = audit("https://localhost/isolated")[2]["COOP / COEP / CORP"]
        self.assertEqual(c["status"], "OK")
        self.assertIn("Cross-Origin-Opener-Policy: same-origin", c["detail"])

    def test_subresource_integrity(self):
        _, _, c = audit("https://localhost/sri-ok")
        self.assertEqual(c["Subresource Integrity"]["status"], "OK")
        self.assertIn("All 2 cross-origin", c["Subresource Integrity"]["detail"])
        _, _, c = audit("https://localhost/sri-missing")
        self.assertEqual(c["Subresource Integrity"]["status"], "WEAK")
        self.assertIn("https://cdn.example.test/a.js", c["Subresource Integrity"]["detail"])
        self.assertIn("https://cdn.example.test/a.css", c["Subresource Integrity"]["detail"])
        _, _, c = audit("https://localhost/sri-http")
        self.assertEqual(c["Subresource Integrity"]["status"], "FAIL")
        self.assertEqual(audit("https://localhost/good")[2]["Subresource Integrity"]["status"], "OK")

    def test_redirect_to_another_host_first_is_weak(self):
        c = audit("https://localhost/sri-ok")[2]["HTTP->HTTPS redirect"]
        self.assertEqual(c["status"], "WEAK")
        self.assertIn("first redirect goes to https://127.0.0.1/sri-ok", c["detail"])

    def test_referrer_policy(self):
        c = audit("https://localhost/referrer-unsafe")[2]["Referrer-Policy"]
        self.assertEqual(c["status"], "WEAK")

    def test_error_status_still_audited(self):
        _, r, c = audit("https://localhost/missing-page")
        self.assertEqual(r["status_code"], 404)
        self.assertEqual(c["Strict-Transport-Security"]["status"], "OK")

    def test_redirect_followed_to_final_url(self):
        _, r, c = audit("https://localhost/hop")
        self.assertEqual(r["final_url"], "https://localhost/good")
        self.assertEqual(c["Content-Security-Policy"]["status"], "OK")

    def test_http_url_input(self):
        _, r, c = audit("http://localhost/good")
        self.assertEqual(r["final_url"], "https://localhost/good")
        self.assertEqual(c["HTTP->HTTPS redirect"]["status"], "OK")

    def test_plain_http_not_served_is_info(self):
        _, _, c = audit("https://127.0.0.3/good")
        self.assertEqual(c["HTTP->HTTPS redirect"]["status"], "INFO")
        self.assertIn("not served", c["HTTP->HTTPS redirect"]["detail"])

    def test_non_default_port_skips_redirect_check(self):
        _, r, c = audit("https://localhost:%d/good" % ALT_PORT)
        self.assertEqual(r["status_code"], 200)
        self.assertNotIn("HTTP->HTTPS redirect", c)


class TestCli(unittest.TestCase):
    def test_text_report(self):
        p = run("https://localhost/weak", "https://localhost/good")
        self.assertEqual(p.returncode, 1)  # /weak has MISSING checks: the default gate
        self.assertIn("Grade: A+  (score 120/100)", p.stdout)
        self.assertIn("=== https://localhost/weak ===", p.stdout)
        self.assertIn("=== https://localhost/good ===", p.stdout)
        self.assertIn("Final URL: https://localhost/good  (HTTP 200)", p.stdout)
        self.assertIn("[WEAK] Strict-Transport-Security", p.stdout)
        self.assertIn("[MISS] X-Frame-Options / frame-ancestors", p.stdout)
        self.assertIn("[INFO] Server / X-Powered-By", p.stdout)
        self.assertIn("[OK]   Referrer-Policy", p.stdout)

    def test_fail_on_flags(self):
        self.assertEqual(run("https://localhost/good", "--fail-on-any-missing").returncode, 0)
        self.assertEqual(run("https://localhost/bare", "--fail-on-any-missing").returncode, 1)
        self.assertEqual(run("https://localhost/bare", "--fail-on-missing-hsts").returncode, 1)
        self.assertEqual(run("https://localhost/weak", "--fail-on", "never", "--fail-on-missing-hsts").returncode, 0)
        self.assertEqual(run("https://localhost/bare").returncode, 1)  # MISSING fails the default gate
        self.assertEqual(run("https://localhost/bare", "--fail-on", "never").returncode, 0)
        self.assertEqual(run("https://localhost/good", "--fail-on", "weak").returncode, 0)
        self.assertEqual(run("https://localhost/quoted", "--fail-on", "weak").returncode, 1)
        self.assertEqual(run("https://localhost/good", "--fail-on-grade", "A+").returncode, 0)
        self.assertEqual(run("https://localhost/quoted", "--fail-on", "never", "--fail-on-grade", "B").returncode, 1)
        self.assertEqual(run("https://localhost/good", "--fail-on-grade", "Z").returncode, 2)

    def test_unreachable_target(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        url = "https://127.0.0.1:%d/" % port
        p = run(url)
        self.assertEqual(p.returncode, 2)  # unreachable = error, never a pass
        self.assertIn("ERROR: Could not fetch", p.stdout)
        self.assertIn("refused", p.stdout.lower())
        self.assertEqual(run(url, "--fail-on", "never").returncode, 2)
        self.assertEqual(run(url, "https://localhost/bare").returncode, 1)  # a real failure outranks the error

    def test_untrusted_certificate_is_an_error(self):
        p = subprocess.run([sys.executable, TOOL, "https://localhost/good"], capture_output=True, text=True,
                           env=dict(os.environ, SSL_CERT_FILE=os.path.join(TMP, "no-such-bundle.pem")), timeout=60)
        self.assertIn("ERROR: Could not fetch", p.stdout)
        self.assertIn("CERTIFICATE_VERIFY_FAILED", p.stdout)

    def test_timeout_option(self):
        t = time.time()
        p = run("https://localhost:%d/slow" % ALT_PORT, "--timeout", "1")
        self.assertIn("ERROR: Could not fetch", p.stdout)
        self.assertLess(time.time() - t, 4)

    def test_version(self):
        self.assertRegex(run("--version").stdout, r"^http-header-auditor \d+\.\d+\.\d+$")

    def test_usage(self):
        self.assertEqual(run().returncode, 2)
        p = run("--help")
        for opt in ("--json", "--timeout", "--fail-on-missing-hsts", "--fail-on-any-missing", "--fail-on", "--fail-on-grade"):
            self.assertIn(opt, p.stdout)


if __name__ == "__main__":
    unittest.main()
