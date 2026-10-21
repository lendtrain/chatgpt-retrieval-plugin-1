# Offline eMudhra trust regression

Run with the Python executable used by the application:

    python tests/security/check_emudhra_trust.py

This checks the system-default OpenSSL store, Python's resolved default
CAfile/CApath, installed certifi and pip's vendored certifi independently
against all 12 public incident chains. The Python-path check explicitly
disables fallback for absent paths. Before interpreting negative chain tests,
it requires a CA certificate to verify through the configured CAfile/CApath.
CApath candidates must actually be found by OpenSSL's hashed lookup: a
nonempty directory, unhashed PEM, wrong hash or missing hash index is not
positive evidence. Combined stores may obtain the trust anchor from either
source, so an empty or ineffective CApath does not invalidate a usable CAfile.
Explicit --bundle checks use the same positive preflight with all other
stores disabled. No particular public root is required for this probe.
These are offline OpenSSL chain checks, not live Python SSLContext handshakes.
An accepted chain is a failure. Missing fixtures, malformed certificates,
missing OpenSSL, expiry and unrelated failures are not passes.
Certificate validity is evaluated at 2026-10-21 00:00:00 UTC.

To test a specific bundle without system fallback:

    python tests/security/check_emudhra_trust.py --bundle /path/to/cacert.pem

The Docker build checks system and Python default paths before dependency
downloads, then all four checks after the patched pip/certifi bootstrap and
after installing application dependencies. These are negative regression tests, not proof
that every library, override or deployed process uses these stores.

Run the standard-library-only regression tests without importing the app:

    python -m unittest discover -s tests/security -p 'test_*.py'

The suite uses the installed OpenSSL executable to generate a temporary
self-signed CA and CA-signed server certificate with explicit validity dates
covering the fixed evaluation time. It verifies real trusted-leaf success
and wrong-hostname failure with CAfile-only, CApath-only and combined stores,
as well as malformed/unhashed store failures. Temporary test keys are deleted
with their temporary directory; no external network, application credentials,
or changes to the host's trust stores are involved.

## Fixture provenance

Source: https://emudhra.we-have-a-problem.com/chains.zip
Captured by the incident responders on 20 October 2026.
Downloaded for this patch on 21 October 2026.
Archive SHA256: 8a2edc81b6c51e3ad27d45ca1e441ec84c961e2dee0fc547f2a02c0f74315f95

Unmodified public PEM files and original README.txt are in fixtures/emudhra.
These contain public certificates, not private keys. No test contacts the
example domains or uses application credentials.
The filename/SHA256 manifest is checked before verification, so a truncated
chain or renamed fixture cannot masquerade as an issuer-trust rejection.

## Deployment follow-through

- Rebuild with a fresh base and no cache: docker build --pull --no-cache .
  The build deliberately fails if the distribution's trust package still
  accepts an incident chain. Do not disable verification to get past it.
- Replace the running deployment, verify its actual image digest, Python,
  certifi and pip versions, and run this check inside that running image.
  A source patch or successful build does not update an existing deployment.
- For non-container environments, update the OS trust store, certifi to
  >=2026.10.19 and pip to >=26.2.2 using the PSF announcement. Bootstrap
  patched pip after every virtualenv/Poetry environment creation: old
  virtualenv/ensurepip seeds can reinstall an old pip.
- Review custom SSL_CERT_FILE, SSL_CERT_DIR, REQUESTS_CA_BUNDLE,
  CURL_CA_BUNDLE and client-specific CA settings, which can override the
  verified defaults. Check separate container/host TLS clients too.
- Python 3.10 has reached end of upstream support. This targeted fix does
  not migrate the legacy application to a new Python major/minor release;
  that requires a separate compatibility update.

Official guidance:
https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576
https://github.com/pypa/pip/releases/tag/26.2.2
https://github.com/certifi/python-certifi/releases/tag/2026.10.19
