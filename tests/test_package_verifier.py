#!/usr/bin/env python3
"""Adversarial tests for the package trust-boundary verifier."""
import hashlib
import io
import subprocess
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "scripts" / "verify_archive.py"
PACKAGE_VERSION = "9.8.7"
PACKAGE_ROOT = f"agentshield-{PACKAGE_VERSION}-linux"
REQUIRED = [
    "bin/agentshield",
    "bin/agentshield-desktop",
    "lib/agentshield/agentshield-desktop.jar",
    "agentshield-source.cdx.json",
    "agentshield-provenance.json",
    "share/doc/agentshield/VERSION",
]


def add_file(package, name, mode=0o644, content=b"test"):
    entry = tarfile.TarInfo(f"{PACKAGE_ROOT}/{name}")
    entry.size = len(content)
    entry.mode = mode
    package.addfile(entry, io.BytesIO(content))


def build(path, extra=None):
    with tarfile.open(path, "w:gz") as package:
        for name in REQUIRED:
            content = (PACKAGE_VERSION + "\n").encode("ascii") if name.endswith("/VERSION") else b"test"
            add_file(package, name, 0o755 if name.startswith("bin/") else 0o644, content)
        if extra:
            extra(package)


def checksum(path, named=None):
    target = named or path.name
    value = hashlib.sha256(path.read_bytes()).hexdigest()
    output = path.with_name(path.name + ".sha256")
    output.write_text(f"{value}  {target}\n", encoding="ascii")
    return output


def verify(path, manifest):
    return subprocess.run(
        ["python3", str(VERIFY), str(path), str(manifest)],
        text=True, capture_output=True, check=False,
    )


def main():
    with tempfile.TemporaryDirectory() as temporary:
        archive = Path(temporary) / f"agentshield-{PACKAGE_VERSION}-linux.tar.gz"
        build(archive)
        manifest = checksum(archive)
        if verify(archive, manifest).returncode != 0:
            raise AssertionError("safe package rejected")
        if verify(archive, checksum(archive, "different.tar.gz")).returncode == 0:
            raise AssertionError("checksum confused-deputy package accepted")

        def traversal(package):
            entry = tarfile.TarInfo(f"{PACKAGE_ROOT}/../escape")
            entry.size = 1
            entry.mode = 0o644
            package.addfile(entry, io.BytesIO(b"x"))

        build(archive, traversal)
        if "unsafe member path" not in verify(archive, checksum(archive)).stderr:
            raise AssertionError("path traversal was not explicitly rejected")

        def symlink(package):
            entry = tarfile.TarInfo(f"{PACKAGE_ROOT}/unsafe-link")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "/etc/passwd"
            entry.mode = 0o777
            package.addfile(entry)

        build(archive, symlink)
        if "special files" not in verify(archive, checksum(archive)).stderr:
            raise AssertionError("symlink was not explicitly rejected")

        def setuid(package):
            add_file(package, "unsafe-setuid", 0o4755)

        build(archive, setuid)
        if "setuid/setgid" not in verify(archive, checksum(archive)).stderr:
            raise AssertionError("setuid content was not explicitly rejected")

        with tarfile.open(archive, "w:gz") as package:
            for name in REQUIRED[1:]:
                content = (PACKAGE_VERSION + "\n").encode("ascii") if name.endswith("/VERSION") else b"test"
                add_file(package, name, 0o755 if name.startswith("bin/") else 0o644, content)
            entry = tarfile.TarInfo(f"{PACKAGE_ROOT}/{REQUIRED[0]}")
            entry.type = tarfile.DIRTYPE
            entry.mode = 0o755
            package.addfile(entry)
        if "regular file" not in verify(archive, checksum(archive)).stderr:
            raise AssertionError("required path represented as a directory was accepted")

        def writable_directory(package):
            entry = tarfile.TarInfo(f"{PACKAGE_ROOT}/unsafe-directory")
            entry.type = tarfile.DIRTYPE
            entry.mode = 0o777
            package.addfile(entry)

        build(archive, writable_directory)
        if "directory must have mode 0755" not in verify(archive, checksum(archive)).stderr:
            raise AssertionError("world-writable directory was accepted")

        with tarfile.open(archive, "w:gz") as package:
            for name in REQUIRED:
                content = b"1.2.3\n" if name.endswith("/VERSION") else b"test"
                add_file(package, name, 0o755 if name.startswith("bin/") else 0o644, content)
        if "does not match archive name" not in verify(archive, checksum(archive)).stderr:
            raise AssertionError("mismatched packaged version was accepted")
    print("package verifier adversarial cases: OK")


if __name__ == "__main__":
    main()
