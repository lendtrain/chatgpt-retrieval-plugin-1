"""Standard-library tests for the fail-closed offline trust gate."""
import contextlib
import io
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

import check_emudhra_trust as check


def generate_test_pki(root):
    """Create an offline CA/leaf valid at the gate's fixed evaluation time.

    Keys exist only in this test's temporary directory. The bootstrap CA lets
    `openssl ca` set explicit historical validity without skipping time checks.
    """
    def openssl(*args):
        return subprocess.run(
            ["openssl", *map(str, args)], cwd=root, check=True,
            capture_output=True, text=True, timeout=30,
        ).stdout

    (root / "index.txt").write_text("")
    (root / "serial").write_text("1000\n")
    (root / "ca.cnf").write_text("""\
[ ca ]
default_ca = test_ca
[ test_ca ]
database = index.txt
serial = serial
new_certs_dir = .
certificate = ca.pem
private_key = ca.key
default_md = sha256
policy = test_policy
unique_subject = no
[ test_policy ]
commonName = supplied
[ ca_extensions ]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[ server_extensions ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:valid.security.invalid
authorityKeyIdentifier = keyid:always
""")
    openssl("req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", "ca.key", "-out", "ca.pem", "-days", "2",
            "-subj", "/CN=Offline security gate test CA",
            "-addext", "basicConstraints=critical,CA:true",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    openssl("req", "-new", "-key", "ca.key", "-out", "ca.csr",
            "-subj", "/CN=Offline security gate test CA")
    openssl("ca", "-batch", "-selfsign", "-config", "ca.cnf",
            "-in", "ca.csr", "-out", "dated-ca.pem", "-notext",
            "-extensions", "ca_extensions", "-startdate", "20261020000000Z",
            "-enddate", "20361021000000Z")
    (root / "ca.pem").write_bytes((root / "dated-ca.pem").read_bytes())
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", "leaf.key", "-out", "leaf.csr",
            "-subj", "/CN=valid.security.invalid")
    openssl("ca", "-batch", "-config", "ca.cnf", "-in", "leaf.csr",
            "-out", "leaf.pem", "-notext", "-extensions", "server_extensions",
            "-startdate", "20261020000000Z", "-enddate", "20361021000000Z")
    return openssl("x509", "-in", "ca.pem", "-subject_hash", "-noout").strip()


class PythonDefaultPathsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki_temp = tempfile.TemporaryDirectory(prefix="offline-test-pki-")
        cls.addClassCleanup(cls.pki_temp.cleanup)
        cls.pki = pathlib.Path(cls.pki_temp.name)
        cls.ca_hash = generate_test_pki(cls.pki)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.cafile = self.root / "roots.pem"
        self.cafile.write_bytes((self.pki / "ca.pem").read_bytes())
        self.capath = self.root / "certs"
        self.capath.mkdir()
        self.hashed_ca = self.capath / (self.ca_hash + ".0")
        self.hashed_ca.write_bytes(self.cafile.read_bytes())
        self.leaf = self.root / "valid.security.invalid.pem"
        self.leaf.write_bytes((self.pki / "leaf.pem").read_bytes())

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
        self.hashed_ca.unlink()
        with self.assertRaisesRegex(RuntimeError, "[Nn]o usable"):
            self.args(str(self.cafile), str(self.capath))

    def test_nonexistent_paths_fail_closed(self):
        with self.assertRaisesRegex(RuntimeError, "no usable default"):
            self.args(str(self.root / "missing.pem"), str(self.root / "missing"))

    def test_capath_arbitrary_nonempty_file_fails(self):
        self.hashed_ca.unlink()
        (self.capath / "README.txt").write_text("Not a trust store")
        with self.assertRaisesRegex(RuntimeError, "No usable CA trust anchor"):
            self.args(None, str(self.capath))

    def test_capath_unhashed_ca_fails(self):
        self.hashed_ca.rename(self.capath / "unhashed-root.pem")
        with self.assertRaisesRegex(RuntimeError, "No usable CA trust anchor"):
            self.args(None, str(self.capath))

    def test_capath_malformed_hashed_certificate_fails(self):
        self.hashed_ca.write_text("-----BEGIN CERTIFICATE-----\nbad\n-----END CERTIFICATE-----\n")
        with self.assertRaisesRegex(RuntimeError, "No usable CA trust anchor"):
            self.args(None, str(self.capath))

    def test_capath_wrong_hash_fails_actual_lookup(self):
        self.hashed_ca.rename(self.capath / "00000000.0")
        self.assertNotEqual(self.ca_hash, "00000000")
        with self.assertRaisesRegex(RuntimeError, "No usable CA trust anchor"):
            self.args(None, str(self.capath))

    def test_capath_missing_hash_zero_fails_actual_lookup(self):
        self.hashed_ca.rename(self.capath / (self.ca_hash + ".1"))
        with self.assertRaisesRegex(RuntimeError, "No usable CA trust anchor"):
            self.args(None, str(self.capath))

    def test_capath_dangling_symlink_fails(self):
        self.hashed_ca.unlink()
        self.hashed_ca.symlink_to(self.root / "missing-root.pem")
        with self.assertRaisesRegex(RuntimeError, "No usable CA trust anchor"):
            self.args(None, str(self.capath))

    def test_capath_hashed_symlink_works(self):
        self.hashed_ca.unlink()
        self.hashed_ca.symlink_to(self.cafile)
        args = self.args(None, str(self.capath))
        self.assertEqual(check.verify_chain(self.leaf, ca_args=args).returncode, 0)

    def test_malformed_cafile_fails(self):
        self.cafile.write_text("nonempty but not a CA bundle")
        with self.assertRaisesRegex(RuntimeError, "No usable CA trust anchor"):
            self.args(str(self.cafile), None)

    def test_leaf_only_cafile_is_not_a_usable_ca_store(self):
        self.cafile.write_bytes(self.leaf.read_bytes())
        with self.assertRaisesRegex(RuntimeError, "No usable CA trust anchor"):
            self.args(str(self.cafile), None)

    def test_combined_valid_file_and_unhashed_directory_works(self):
        self.hashed_ca.rename(self.capath / "unhashed-root.pem")
        args = self.args(str(self.cafile), str(self.capath))
        self.assertEqual(check.verify_chain(self.leaf, ca_args=args).returncode, 0)

    def test_combined_empty_file_and_valid_directory_works(self):
        self.cafile.write_bytes(b"")
        args = self.args(str(self.cafile), str(self.capath))
        self.assertEqual(check.verify_chain(self.leaf, ca_args=args).returncode, 0)

    def test_combined_valid_file_and_empty_directory_works(self):
        self.hashed_ca.unlink()
        args = self.args(str(self.cafile), str(self.capath))
        self.assertEqual(check.verify_chain(self.leaf, ca_args=args).returncode, 0)

    def test_real_trusted_leaf_succeeds_and_wrong_hostname_fails(self):
        wrong = self.root / "wrong.security.invalid.pem"
        wrong.write_bytes(self.leaf.read_bytes())
        for cafile, capath in [(str(self.cafile), None), (None, str(self.capath)),
                              (str(self.cafile), str(self.capath))]:
            with self.subTest(cafile=cafile, capath=capath):
                args = self.args(cafile, capath)
                good = check.verify_chain(self.leaf, ca_args=args)
                self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
                bad = check.verify_chain(wrong, ca_args=args)
                self.assertNotEqual(bad.returncode, 0)
                self.assertIn("hostname mismatch", bad.stdout + bad.stderr)

    def run_cli(self, cafile, capath, *args):
        env = os.environ.copy()
        env.update(SSL_CERT_FILE=str(cafile), SSL_CERT_DIR=str(capath))
        return subprocess.run(
            [sys.executable, str(pathlib.Path(check.__file__).resolve()), *args],
            env=env, capture_output=True, text=True, timeout=30,
        )

    def test_exact_reviewer_repro_fails(self):
        self.hashed_ca.unlink()
        (self.capath / "README.txt").write_text("nonempty")
        result = self.run_cli(self.root / "absent.pem", self.capath, "--system-only")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No usable CA trust anchor", result.stdout + result.stderr)
        self.assertNotIn("PASS", result.stdout)

    def test_real_custom_stores_pass_cli_gate(self):
        for cafile, capath in [(self.cafile, self.root / "absent-dir"),
                              (self.root / "absent.pem", self.capath),
                              (self.cafile, self.capath)]:
            with self.subTest(cafile=cafile, capath=capath):
                result = self.run_cli(cafile, capath, "--system-only")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("PASS python-default-paths", result.stdout)

    def test_explicit_valid_bundle_passes_cli_gate(self):
        result = self.run_cli(self.root / "absent.pem", self.root / "absent-dir",
                              "--bundle", str(self.cafile))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_explicit_leaf_only_bundle_fails_cli_gate(self):
        result = self.run_cli(self.root / "absent.pem", self.root / "absent-dir",
                              "--bundle", str(self.leaf))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No usable CA trust anchor", result.stdout + result.stderr)


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
                mock.patch.object(check, "require_usable_ca_store"), \
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
