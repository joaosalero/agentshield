#!/usr/bin/env python3
"""Verify digest and reject unsafe or structurally invalid AgentShield archives."""
import hashlib
import re
import sys
import tarfile
from pathlib import Path, PurePosixPath


def fail(message):
    raise SystemExit(f"package verification failed: {message}")


def main():
    if len(sys.argv) != 3:
        fail("archive and checksum paths are required")
    archive = Path(sys.argv[1])
    checksum = Path(sys.argv[2])
    fields = checksum.read_text(encoding="ascii").strip().split()
    if len(fields) != 2 or not re.fullmatch(r"[0-9a-fA-F]{64}", fields[0]):
        fail("checksum manifest must contain exactly one SHA-256 entry")
    if fields[1].lstrip("*") != archive.name:
        fail("checksum manifest does not name the supplied archive")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest.lower() != fields[0].lower():
        fail("SHA-256 mismatch")
    expected_root = archive.name.removesuffix(".tar.gz")
    required = {
        f"{expected_root}/bin/agentshield": 0o755,
        f"{expected_root}/bin/agentshield-desktop": 0o755,
        f"{expected_root}/lib/agentshield/agentshield-desktop.jar": 0o644,
        f"{expected_root}/agentshield-source.cdx.json": 0o644,
        f"{expected_root}/agentshield-provenance.json": 0o644,
    }
    seen = set()
    with tarfile.open(archive, "r:gz") as package:
        for member in package.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != expected_root:
                fail(f"unsafe member path: {member.name}")
            if member.name in seen:
                fail(f"duplicate member: {member.name}")
            seen.add(member.name)
            if not (member.isfile() or member.isdir()):
                fail(f"links and special files are forbidden: {member.name}")
            if member.mode & 0o6000:
                fail(f"setuid/setgid mode is forbidden: {member.name}")
            if member.isdir() and member.mode != 0o755:
                fail(f"directory must have mode 0755: {member.name}")
            if member.name in required and not member.isfile():
                fail(f"required member must be a regular file: {member.name}")
            if member.name in required and member.mode != required[member.name]:
                fail(f"required member has unsafe mode: {member.name}")
            if member.isfile() and member.name not in required and member.mode != 0o644:
                fail(f"data file must have mode 0644: {member.name}")
    missing = set(required) - seen
    if missing:
        fail("missing required members: " + ", ".join(sorted(missing)))


if __name__ == "__main__":
    main()
