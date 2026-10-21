"""Standard-library tests for the fail-closed offline trust gate."""
import contextlib
import io
import pathlib
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

import check_emudhra_trust as check


class PythonDefaultPathsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.cafile = self.root / "roots.pem"
        self.cafile.write_text("nonempty bundle placeholder")
        self.capath = self.root / "certs"
        self.capath.mkdir()
        (self.capath / "12345678.0").write_text("nonempty root placeholder")

    def args(self, cafile, capath):
        paths = types.SimpleNamespace(cafile=cafile, capath=capath)
        with mock.patch.object(check.ssl, "get_default_verify_paths", return_value=paths):
            return check.python_default_ca_args()

    def test_both_paths_are_explicit(self):
        self.assertEqual(self.args(str(self.cafile), str(self.capath)), [
            "-CAfile", str(self.cafile), "-CApath", str(self.capath), "-no-CAstore",
        ])

    def test_missing_capath_disables_fallback(self):
        self.assertEqual(self.args(str(self.cafile), None), [
            "-CAfile", str(self.cafile), "-no-CApath", "-no-CAstore",
        ])

    def test_missing_cafile_disables_fallback(self):
        self.assertEqual(self.args(None, str(self.capath)), [
            "-no-CAfile", "-CApath", str(self.capath), "-no-CAstore",
        ])

    def test_no_paths_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "no usable default"):
            self.args(None, None)

    def test_empty_paths_fail_closed(self):
        self.cafile.write_bytes(b"")
        (self.capath / "12345678.0").unlink()
        with self.assertRaisesRegex(RuntimeError, "no usable default"):
            self.args(str(self.cafile), str(self.capath))

    def test_nonexistent_paths_fail_closed(self):
        with self.assertRaisesRegex(RuntimeError, "no usable default"):
            self.args(str(self.root / "missing.pem"), str(self.root / "missing"))


class VerifyCommandTests(unittest.TestCase):
    def command(self, **kwargs):
        with mock.patch.object(check.subprocess, "run") as run:
            check.verify_chain(pathlib.Path("example.test.pem"), **kwargs)
        return run.call_args.args[0]

    def test_bundle_has_no_system_fallback(self):
        command = self.command(bundle=pathlib.Path("roots.pem"))
        self.assertIn("-CAfile", command)
        self.assertIn("-no-CApath", command)
        self.assertIn("-no-CAstore", command)

    def test_python_paths_are_forwarded_exactly(self):
        args = ["-no-CAfile", "-CApath", "/example/certs", "-no-CAstore"]
        command = self.command(ca_args=args)
        self.assertEqual(command[8:12], args)

    def test_cli_default_remains_independent(self):
        command = self.command()
        self.assertNotIn("-CAfile", command)
        self.assertNotIn("-CApath", command)
        self.assertNotIn("-no-CAstore", command)


class FailClosedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.fixtures = self.root / "fixtures"
        shutil.copytree(check.FIXTURES, self.fixtures)
        self.bundle = self.root / "roots.pem"
        self.bundle.write_text("nonempty bundle placeholder")

    def run_main(self, outcome):
        with mock.patch.object(check, "FIXTURES", self.fixtures), \
                mock.patch.object(sys, "argv", ["check", "--bundle", str(self.bundle)]), \
                mock.patch.object(check.shutil, "which", return_value="/usr/bin/openssl"), \
                mock.patch.object(check, "verify_chain", return_value=outcome), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            return check.main()

    def result(self, code, stderr):
        return subprocess.CompletedProcess([], code, stdout="", stderr=stderr)

    def test_issuer_trust_rejection_passes(self):
        self.assertEqual(self.run_main(self.result(
            2, "error 20 at 1 depth lookup: unable to get local issuer certificate"
        )), 0)

    def test_accepted_chain_fails(self):
        self.assertEqual(self.run_main(self.result(0, "")), 1)

    def test_expiry_does_not_masquerade_as_distrust(self):
        self.assertEqual(self.run_main(self.result(
            2, "error 10 at 0 depth lookup: certificate has expired"
        )), 1)

    def test_mixed_expiry_and_issuer_errors_fail(self):
        self.assertEqual(self.run_main(self.result(
            2, "error 20 at 1 depth lookup: unable to get local issuer certificate\n"
            "error 10 at 0 depth lookup: certificate has expired"
        )), 1)

    def test_hostname_failure_does_not_pass(self):
        self.assertEqual(self.run_main(self.result(
            2, "error 62 at 0 depth lookup: hostname mismatch"
        )), 1)

    def test_malformed_bundle_or_unknown_failure_does_not_pass(self):
        self.assertEqual(self.run_main(self.result(1, "Error loading file roots.pem")), 1)

    def test_tampered_fixture_fails_before_verification(self):
        next(self.fixtures.glob("*.pem")).write_text("truncated chain")
        with self.assertRaisesRegex(RuntimeError, "do not match"):
            self.run_main(self.result(2, "issuer error"))

    def test_missing_fixture_fails_before_verification(self):
        next(self.fixtures.glob("*.pem")).unlink()
        with self.assertRaisesRegex(RuntimeError, "Expected 12"):
            self.run_main(self.result(2, "issuer error"))

    def test_missing_bundle_fails(self):
        self.bundle.unlink()
        with self.assertRaisesRegex(RuntimeError, "Missing CA bundle"):
            self.run_main(self.result(2, "issuer error"))

    def test_missing_openssl_fails(self):
        with mock.patch.object(sys, "argv", ["check"]), \
                mock.patch.object(check.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "openssl is required"):
                check.main()


if __name__ == "__main__":
    unittest.main()
