#!/usr/bin/env python3
"""Verify release metadata is bound to the version and exact local artifacts."""
import hashlib
import json
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from read_version import read_version

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if len(sys.argv) != 6:
        raise SystemExit("CLI, JAR, SBOM, provenance, and archive paths are required")
    cli, jar, sbom_path, provenance_path, archive = map(Path, sys.argv[1:])
    version = read_version(ROOT / "VERSION")
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    if sbom["metadata"]["component"] != {"type": "application", "name": "agentshield", "version": version}:
        raise AssertionError("SBOM component version is inconsistent")
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    if provenance["predicate"]["version"] != version:
        raise AssertionError("provenance version is inconsistent")
    expected = {path.name: digest(path) for path in (cli, jar, sbom_path)}
    actual = {item["name"]: item["digest"]["sha256"] for item in provenance["subject"]}
    if actual != expected:
        raise AssertionError("provenance is not bound to the exact artifacts")
    expected_archive = f"agentshield-{version}-linux.tar.gz"
    if archive.name != expected_archive:
        raise AssertionError("archive filename is inconsistent")
    version_member = f"agentshield-{version}-linux/share/doc/agentshield/VERSION"
    with tarfile.open(archive, "r:gz") as package:
        extracted = package.extractfile(version_member)
        if extracted is None or extracted.read().decode("ascii").strip() != version:
            raise AssertionError("packaged VERSION is inconsistent")
    print("release version and artifact binding: OK")


if __name__ == "__main__":
    main()
