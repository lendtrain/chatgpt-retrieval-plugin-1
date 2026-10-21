"""Offline October 2026 eMudhra regression; no network or application imports."""
import argparse
import hashlib
import importlib
import json
import pathlib
import re
import shutil
import ssl
import subprocess
import sys

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "emudhra"
# Fixed while the fixtures are valid, so future expiry cannot mask bad trust.
VERIFY_TIME = "1792540800"  # 2026-10-21 00:00:00 UTC
TRUST_FAILURE = re.compile(
    r"error (?:2|20|21) at \d+ depth lookup: "
    r"unable to (?:get issuer certificate|get local issuer certificate|verify the first certificate)"
)


def python_default_ca_args():
    """Use Python's resolved OpenSSL paths without any implicit fallback."""
    paths = ssl.get_default_verify_paths()
    cafile = pathlib.Path(paths.cafile) if paths.cafile else None
    capath = pathlib.Path(paths.capath) if paths.capath else None
    has_file = cafile is not None and cafile.is_file() and cafile.stat().st_size > 0
    has_path = capath is not None and capath.is_dir() and any(
        item.is_file() and item.stat().st_size > 0 for item in capath.iterdir()
    )
    if not has_file and not has_path:
        raise RuntimeError("Python has no usable default CAfile or nonempty CApath")
    return (
        (["-CAfile", str(cafile)] if has_file else ["-no-CAfile"])
        + (["-CApath", str(capath)] if has_path else ["-no-CApath"])
        + ["-no-CAstore"]
    )


def verify_chain(chain, bundle=None, ca_args=None):
    command = [
        "openssl", "verify", "-purpose", "sslserver",
        "-verify_hostname", chain.stem, "-attime", VERIFY_TIME,
    ]
    if bundle is not None:
        # Explicit bundle tests must not fall back to system CApath/CAstore.
        command += ["-CAfile", str(bundle), "-no-CApath", "-no-CAstore"]
    elif ca_args is not None:
        command += ca_args
    command += ["-untrusted", str(chain), str(chain)]
    return subprocess.run(command, capture_output=True, text=True, timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system-only", action="store_true")
    parser.add_argument("--bundle", type=pathlib.Path,
                        help="Check only this bundle, with no system fallback")
    args = parser.parse_args()
    if args.system_only and args.bundle:
        parser.error("--system-only and --bundle are mutually exclusive")
    if shutil.which("openssl") is None:
        raise RuntimeError("openssl is required; this check must not be skipped")
    chains = sorted(FIXTURES.glob("*.pem"))
    if len(chains) != 12:
        raise RuntimeError(f"Expected 12 public chains, found {len(chains)}")
    # Missing intermediates can also yield an issuer error, so require the
    # exact complete responder fixtures before interpreting a trust failure.
    expected = json.loads((FIXTURES / "SHA256SUMS.json").read_text())
    actual = {chain.name: hashlib.sha256(chain.read_bytes()).hexdigest()
              for chain in chains}
    if actual != expected or len(expected) != 12:
        raise RuntimeError("Incident fixture names/content do not match SHA256SUMS.json")
    if args.bundle:
        stores = [(str(args.bundle), args.bundle, None)]
    else:
        stores = [
            ("system-default", None, None),
            ("python-default-paths", None, python_default_ca_args()),
        ]
        if not args.system_only:
            for module_name in ("certifi", "pip._vendor.certifi"):
                module = importlib.import_module(module_name)
                stores.append((module_name, pathlib.Path(module.where()), None))
    failures = []
    for name, bundle, ca_args in stores:
        if bundle is not None and not bundle.is_file():
            raise RuntimeError(f"Missing CA bundle: {bundle}")
        for chain in chains:
            result = verify_chain(chain, bundle, ca_args)
            detail = result.stdout + result.stderr
            codes = {int(code) for code in re.findall(
                r"error (\d+) at \d+ depth lookup:", detail)}
            if result.returncode == 0:
                failures.append(f"{name}: still TRUSTS {chain.name}")
            elif not codes or not codes <= {2, 20, 21} or not TRUST_FAILURE.search(detail):
                failures.append(
                    f"{name}: inconclusive/non-trust failure for {chain.name}: {detail.strip()}"
                )
        if not any(item.startswith(name + ":") for item in failures):
            print(f"PASS {name}: all 12 chains rejected for issuer/trust reasons")
    if failures:
        for failure in failures:
            print("FAIL " + failure, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
