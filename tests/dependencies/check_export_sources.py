"""Fail closed if a Poetry export expands the package-scoped Azure source."""
import pathlib
import re
import sys


AZURE_WHEEL = (
    "https://pkgs.dev.azure.com/azure-sdk/"
    "29ec6040-b234-4e31-b139-33dc4287b756/_packaging/"
    "3572dbf9-b5ef-433b-9137-fc4d7768e7cc/pypi/download/"
    "azure-search-documents/11.4a20230509004/"
    "azure_search_documents-11.4.0a20230509004-py3-none-any.whl"
    "#sha256=6215e9a4f9e935ff3eac1b7d5519c6c0789b4497eb11242d376911aaefbb0359"
)


def check_export(text):
    azure = []
    ordinary = 0
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Export uses --without-hashes; hash pinning for Azure stays in its URL.
        # Reject all global options, includes, URLs and unpinned dependencies.
        requirement = line.split(" ; ", 1)[0]
        if requirement.startswith("azure-search-documents @ "):
            azure.append(requirement)
        elif re.fullmatch(r"[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[A-Za-z0-9_.+!-]+", requirement):
            name = requirement.split("==", 1)[0].split("[", 1)[0]
            if re.sub(r"[-_.]+", "-", name).lower() == "azure-search-documents":
                raise ValueError("Azure package must use only its verified direct wheel")
            ordinary += 1
        else:
            raise ValueError(f"Unexpected source or requirement at export line {number}")
    if azure != ["azure-search-documents @ " + AZURE_WHEEL]:
        raise ValueError("Expected exactly the verified hash-pinned Azure wheel")
    if not ordinary:
        raise ValueError("Expected ordinary PyPI requirements in the export")
    return ordinary


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: check_export_sources.py requirements.txt")
    count = check_export(pathlib.Path(sys.argv[1]).read_text())
    print(f"PASS: {count} ordinary PyPI pins; one hash-pinned Azure wheel; no index overrides")
