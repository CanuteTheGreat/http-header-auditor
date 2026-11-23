"""Shared CLI contract (docs/CLI-CONTRACT.md): exit codes, --json schema, --quiet, stderr for errors.

Reuses the local HTTPS fixture servers of test_http_header_auditor.py (a throwaway CA, a server on an
unprivileged port and ports 80/443, which the CI container may bind); the tool runs as a subprocess.
"""
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr
from unittest import mock

import contract_support as cs
import test_http_header_auditor as T

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import http_header_auditor as tool  # noqa: E402

SCHEMA = cs.load_schema(ROOT, "http-header-auditor")


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


def cli(*args):
    return cs.run_cli(T.TOOL, args, env={"SSL_CERT_FILE": T.CA})


def good():
    return "https://localhost:%d/good" % T.ALT_PORT


def bare():
    return "https://localhost:%d/bare" % T.ALT_PORT


UNREACHABLE = "https://127.0.0.1:1/"  # nothing listens there: connection refused, no real network


class TestExitCodes(unittest.TestCase):
    def test_clean_is_0(self):
        self.assertEqual(cli(good())[0], 0)

    def test_findings_is_1(self):
        self.assertEqual(cli(bare())[0], 1)

    def test_bad_args_is_2_with_message_on_stderr(self):
        for a in ((), ("--no-such-flag", good()), (good(), "--fail-on", "bogus"), (good(), "--fail-on-grade", "Z")):
            rc, out, err = cli(*a)
            self.assertEqual(rc, 2, a)
            self.assertEqual(out, "", a)
            self.assertIn("usage:", err)

    def test_unreachable_target_keeps_documented_legacy_code_2(self):
        rc, out, err = cli(UNREACHABLE)
        self.assertEqual(rc, 2)
        self.assertIn("Could not fetch", out)

    def test_unexpected_error_is_3_on_stderr_not_a_traceback_exit_1(self):
        buf = io.StringIO()
        with mock.patch.object(tool, "_main", side_effect=RuntimeError("boom")), redirect_stderr(buf):
            self.assertEqual(tool.main([good()]), 3)
        self.assertIn("RuntimeError: boom", buf.getvalue())


class TestJson(unittest.TestCase):
    def check(self, args, code):
        rc, out, err = cli(*args, "--json")
        self.assertEqual(rc, code, err)
        doc = json.loads(out)  # exactly one JSON document, nothing else on stdout
        self.assertEqual(cs.validate(doc, SCHEMA), [])
        self.assertEqual(doc["exit_code"], rc)
        self.assertEqual(doc["schema_version"], 1)
        self.assertEqual(doc["tool"], "http-header-auditor")
        self.assertEqual(doc["version"], tool.__version__)
        return doc

    def test_clean(self):
        doc = self.check((good(),), 0)
        self.assertEqual(doc["results"][0]["grade"], "A+")

    def test_findings(self):
        doc = self.check((bare(),), 1)
        self.assertTrue(any(c["status"] == "MISSING" for c in doc["results"][0]["checks"]))

    def test_unreachable_target_has_an_error_entry(self):
        doc = self.check((UNREACHABLE,), 2)
        self.assertIn("error", doc["results"][0])

    def test_several_urls_are_several_results(self):
        self.assertEqual(len(self.check((good(), bare()), 1)["results"]), 2)

    def test_usage_error_leaves_stdout_empty(self):
        rc, out, err = cli("--json")
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("usage:", err)

    def test_schema_rejects_a_document_without_the_contract_keys(self):
        self.assertNotEqual(cs.validate({"results": []}, SCHEMA), [])
        good_doc = {"schema_version": 1, "tool": "http-header-auditor", "version": "1", "exit_code": 0, "results": []}
        self.assertEqual(cs.validate(good_doc, SCHEMA), [])
        self.assertNotEqual(cs.validate(dict(good_doc, exit_code=9), SCHEMA), [])


class TestQuiet(unittest.TestCase):
    def test_quiet_prints_nothing_but_keeps_exit_code(self):
        for url, code in ((good(), 0), (bare(), 1), (UNREACHABLE, 2)):
            for extra in ((), ("--json",)):
                for flag in ("--quiet", "-q"):
                    rc, out, err = cli(flag, url, *extra)
                    self.assertEqual((rc, out), (code, ""), (flag, extra, url))

    def test_without_quiet_the_report_is_printed(self):
        self.assertIn("A+", cli(good())[1])


if __name__ == "__main__":
    unittest.main()
