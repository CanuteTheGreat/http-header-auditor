"""Detection accuracy against the Mozilla HTTP Observatory scoring table.

OBSERVATORY below is copied from the Observatory's published methodology
(github.com/mozilla/http-observatory, httpobs/docs/scoring.md, 2024-02-27). Each profile is
served for real (same local HTTPS + HTTP servers as the main suite) and annotated with the
Observatory test result a careful reading of that table gives; the expected score is computed
from the table (bonuses only when the score without them is >= 90), never from the tool.
The two places where the tool knowingly differs from the Observatory are listed in DEVIATIONS,
each with its reason, and are applied explicitly.
"""
import unittest

import test_http_header_auditor as base

OBSERVATORY = {
    "csp-implemented-with-no-unsafe-default-src-none": 10, "csp-implemented-with-no-unsafe": 5,
    "csp-implemented-with-unsafe-inline-in-style-src-only": 0, "csp-implemented-with-unsafe-eval": -10,
    "csp-implemented-with-unsafe-inline": -20, "csp-not-implemented": -25,
    "cookies-secure-with-httponly-sessions-and-samesite": 5, "cookies-not-found": 0,
    "cookies-without-secure-flag-but-protected-by-hsts": -5,
    "cookies-session-without-secure-flag-but-protected-by-hsts": -10, "cookies-without-secure-flag": -20,
    "cookies-samesite-flag-invalid": -20, "cookies-session-without-httponly-flag": -30,
    "cookies-session-without-secure-flag": -40,
    "hsts-implemented-max-age-at-least-six-months": 0, "hsts-implemented-max-age-less-than-six-months": -10,
    "hsts-not-implemented": -20,
    "redirection-to-https": 0, "redirection-missing": -20,
    "referrer-policy-private": 5, "referrer-policy-not-implemented": 0, "referrer-policy-unsafe": -5,
    "referrer-policy-header-invalid": -5,
    "sri-not-implemented-but-no-scripts-loaded": 0,
    "x-content-type-options-nosniff": 0, "x-content-type-options-not-implemented": -5,
    "x-frame-options-implemented-via-csp": 5, "x-frame-options-sameorigin-or-deny": 0,
    "x-frame-options-not-implemented": -20, "x-frame-options-header-invalid": -20,
}
BONUSES = {k for k, v in OBSERVATORY.items() if v > 0}
DEVIATIONS = {
    # the tool can't see the browser preload list, so it rewards eligibility (1y + includeSubDomains + preload)
    "hsts-preload-eligible": 5,
    # max-age=0 switches HSTS off; the Observatory still files it under "less than six months" (-10)
    "hsts-max-age-zero": -10,
}

HSTS = ("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
HSTS_PRELOAD = ("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
NOSNIFF = ("X-Content-Type-Options", "nosniff")
PROFILES = {
    "/obs-strict": ([HSTS_PRELOAD, NOSNIFF,
                     ("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; "
                                                 "img-src 'self'; frame-ancestors 'none'; base-uri 'none'"),
                     ("Referrer-Policy", "no-referrer"), ("Set-Cookie", "sid=1; Path=/; Secure; HttpOnly; SameSite=Strict")],
                    ["csp-implemented-with-no-unsafe-default-src-none", "hsts-implemented-max-age-at-least-six-months",
                     "x-frame-options-implemented-via-csp", "referrer-policy-private",
                     "cookies-secure-with-httponly-sessions-and-samesite", "x-content-type-options-nosniff",
                     "redirection-to-https", "sri-not-implemented-but-no-scripts-loaded"], ["hsts-preload-eligible"]),
    "/obs-style-inline": ([HSTS, NOSNIFF, ("Content-Security-Policy",
                                           "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'")],
                          ["csp-implemented-with-unsafe-inline-in-style-src-only", "x-frame-options-implemented-via-csp",
                           "hsts-implemented-max-age-at-least-six-months", "referrer-policy-not-implemented",
                           "cookies-not-found", "redirection-to-https"], []),
    "/obs-eval": ([HSTS, NOSNIFF, ("Content-Security-Policy",
                                   "default-src 'self'; script-src 'self' 'unsafe-eval'; frame-ancestors 'none'")],
                  ["csp-implemented-with-unsafe-eval", "x-frame-options-implemented-via-csp",
                   "hsts-implemented-max-age-at-least-six-months", "redirection-to-https"], []),
    "/obs-inline-script": ([HSTS, NOSNIFF, ("X-Frame-Options", "DENY"),
                            ("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")],
                           ["csp-implemented-with-unsafe-inline", "x-frame-options-sameorigin-or-deny",
                            "hsts-implemented-max-age-at-least-six-months", "redirection-to-https"], []),
    "/obs-nonce-inline": ([HSTS, NOSNIFF, ("X-Frame-Options", "SAMEORIGIN"),
                           ("Content-Security-Policy", "default-src 'self'; script-src 'nonce-r4nd0m' 'unsafe-inline'")],
                          # browsers ignore 'unsafe-inline' next to a nonce (CSP2+): no script hole, but no
                          # "no unsafe" bonus either
                          ["csp-implemented-with-unsafe-inline-in-style-src-only", "x-frame-options-sameorigin-or-deny",
                           "hsts-implemented-max-age-at-least-six-months", "redirection-to-https"], []),
    "/obs-xfo-junk": ([HSTS, NOSNIFF, ("X-Frame-Options", "ALLOWALL")],
                      ["x-frame-options-header-invalid", "csp-not-implemented",
                       "hsts-implemented-max-age-at-least-six-months", "redirection-to-https"], []),
    "/obs-frame-star": ([HSTS, NOSNIFF, ("Content-Security-Policy", "default-src 'self'; frame-ancestors *")],
                        ["x-frame-options-not-implemented", "csp-implemented-with-no-unsafe",
                         "hsts-implemented-max-age-at-least-six-months", "redirection-to-https"], []),
    "/obs-hsts-short": ([("Strict-Transport-Security", "max-age=86400"), NOSNIFF, ("X-Frame-Options", "DENY"),
                         ("Content-Security-Policy", "default-src 'self'")],
                        ["hsts-implemented-max-age-less-than-six-months", "csp-implemented-with-no-unsafe",
                         "x-frame-options-sameorigin-or-deny", "redirection-to-https"], []),
    "/obs-hsts-zero": ([("Strict-Transport-Security", "max-age=0"), NOSNIFF, ("X-Frame-Options", "DENY"),
                        ("Content-Security-Policy", "default-src 'self'")],
                       ["hsts-implemented-max-age-less-than-six-months", "csp-implemented-with-no-unsafe",
                        "x-frame-options-sameorigin-or-deny", "redirection-to-https"], ["hsts-max-age-zero"]),
    "/obs-session-readable": ([HSTS, NOSNIFF, ("X-Frame-Options", "DENY"), ("Content-Security-Policy", "default-src 'self'"),
                               ("Set-Cookie", "PHPSESSID=1; Path=/; Secure; SameSite=Lax")],
                              ["cookies-session-without-httponly-flag", "csp-implemented-with-no-unsafe",
                               "x-frame-options-sameorigin-or-deny", "hsts-implemented-max-age-at-least-six-months",
                               "redirection-to-https"], []),
    "/obs-session-insecure-hsts": ([HSTS, NOSNIFF, ("X-Frame-Options", "DENY"),
                                    ("Content-Security-Policy", "default-src 'self'"),
                                    ("Set-Cookie", "connect.sid=1; Path=/; HttpOnly; SameSite=Lax")],
                                   ["cookies-session-without-secure-flag-but-protected-by-hsts",
                                    "csp-implemented-with-no-unsafe", "x-frame-options-sameorigin-or-deny",
                                    "hsts-implemented-max-age-at-least-six-months", "redirection-to-https"], []),
    "/obs-session-insecure": ([NOSNIFF, ("X-Frame-Options", "DENY"), ("Content-Security-Policy", "default-src 'self'"),
                               ("Set-Cookie", "laravel_session=1; Path=/; HttpOnly; SameSite=Lax")],
                              ["cookies-session-without-secure-flag", "hsts-not-implemented",
                               "csp-implemented-with-no-unsafe", "x-frame-options-sameorigin-or-deny",
                               "redirection-to-https"], []),
    "/obs-pref-insecure-hsts": ([HSTS, NOSNIFF, ("X-Frame-Options", "DENY"), ("Content-Security-Policy", "default-src 'self'"),
                                 ("Set-Cookie", "theme=dark; Path=/; SameSite=Lax")],
                                ["cookies-without-secure-flag-but-protected-by-hsts", "csp-implemented-with-no-unsafe",
                                 "x-frame-options-sameorigin-or-deny", "hsts-implemented-max-age-at-least-six-months",
                                 "redirection-to-https"], []),
    "/obs-csrf-readable": ([HSTS, NOSNIFF, ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
                            ("Referrer-Policy", "strict-origin-when-cross-origin"),
                            ("Set-Cookie", "csrftoken=abc; Path=/; Secure; SameSite=Lax"),
                            ("Set-Cookie", "sessionid=x; Path=/; Secure; HttpOnly; SameSite=Lax")],
                           ["cookies-secure-with-httponly-sessions-and-samesite", "csp-implemented-with-no-unsafe",
                            "x-frame-options-implemented-via-csp", "referrer-policy-private",
                            "hsts-implemented-max-age-at-least-six-months", "redirection-to-https"], []),
    "/obs-samesite-invalid": ([HSTS, NOSNIFF, ("X-Frame-Options", "DENY"), ("Content-Security-Policy", "default-src 'self'"),
                               ("Set-Cookie", "pref=1; Path=/; Secure; SameSite=Sometimes")],
                              ["cookies-samesite-flag-invalid", "csp-implemented-with-no-unsafe",
                               "x-frame-options-sameorigin-or-deny", "hsts-implemented-max-age-at-least-six-months",
                               "redirection-to-https"], []),
    "/obs-referrer-invalid": ([HSTS, NOSNIFF, ("X-Frame-Options", "DENY"), ("Content-Security-Policy", "default-src 'self'"),
                               ("Referrer-Policy", "no-refferer")],
                              ["referrer-policy-header-invalid", "csp-implemented-with-no-unsafe",
                               "x-frame-options-sameorigin-or-deny", "hsts-implemented-max-age-at-least-six-months",
                               "redirection-to-https"], []),
    "/obs-no-nosniff": ([HSTS, ("X-Frame-Options", "DENY"), ("Content-Security-Policy", "default-src 'self'")],
                        ["x-content-type-options-not-implemented", "csp-implemented-with-no-unsafe",
                         "x-frame-options-sameorigin-or-deny", "hsts-implemented-max-age-at-least-six-months",
                         "redirection-to-https"], []),
    "/bare": ([], ["csp-not-implemented", "hsts-not-implemented", "x-frame-options-not-implemented",
                   "x-content-type-options-not-implemented", "redirection-missing", "referrer-policy-not-implemented",
                   "cookies-not-found"], []),
}


def expected_score(results, deviations):
    penalties = sum(OBSERVATORY[r] for r in results if r not in BONUSES)
    bonuses = sum(OBSERVATORY[r] for r in results if r in BONUSES)
    dev_pen = sum(DEVIATIONS[d] for d in deviations if DEVIATIONS[d] < 0)
    dev_bonus = sum(DEVIATIONS[d] for d in deviations if DEVIATIONS[d] > 0)
    score = 100 + penalties + dev_pen
    return score + bonuses + dev_bonus if score >= 90 else score


def setUpModule():
    for path, (headers, _, _) in PROFILES.items():
        if path != "/bare":
            base.PROFILES[path] = (200, headers)
    base.setUpModule()


def tearDownModule():
    base.tearDownModule()


class TestObservatoryTable(unittest.TestCase):
    def test_scores_and_grades(self):
        for path, (_, results, deviations) in PROFILES.items():
            with self.subTest(profile=path):
                want = expected_score(results, deviations)
                _, r, _ = base.audit("https://localhost" + path)
                self.assertEqual((r["score"], r["grade"]), (want, base_grade(want)),
                                 "%s: Observatory results %s" % (path, results))


def base_grade(score):
    for floor, g in ((100, "A+"), (90, "A"), (85, "A-"), (80, "B+"), (70, "B"), (65, "B-"), (60, "C+"), (50, "C"),
                     (45, "C-"), (40, "D+"), (30, "D"), (25, "D-")):
        if score >= floor:
            return g
    return "F"


if __name__ == "__main__":
    unittest.main()
