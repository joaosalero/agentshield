#!/usr/bin/env python3
"""Adversarial tests for canonical version parsing and Make parse-time safety."""
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
READER = ROOT / "scripts" / "read_version.py"


def read(path):
    return subprocess.run(["python3", str(READER), str(path)], text=True, capture_output=True, check=False)


def main():
    with tempfile.TemporaryDirectory() as temporary:
        temp = Path(temporary)
        version = temp / "VERSION"
        for value in (b"1.2.3", b"1.2.3\n"):
            version.write_bytes(value)
            result = read(version)
            if result.returncode != 0 or result.stdout.strip() != "1.2.3":
                raise AssertionError("canonical version rejected")
        for value in (b"1.2.3\nextra\n", b"1.2", b"v1.2.3\n", b"1.2.3 beta\n", b"\xff\n"):
            version.write_bytes(value)
            if read(version).returncode == 0:
                raise AssertionError(f"invalid version accepted: {value!r}")

        (temp / "scripts").mkdir()
        (temp / "Makefile").write_bytes((ROOT / "Makefile").read_bytes())
        (temp / "scripts" / "read_version.py").write_bytes(READER.read_bytes())
        marker = temp / "injection-marker"
        version.write_text(f"1.2.3$(touch {marker})\n", encoding="ascii")
        result = subprocess.run(
            ["make", "-j8", "all"], cwd=temp, text=True, capture_output=True, check=False
        )
        if result.returncode == 0 or marker.exists():
            raise AssertionError("invalid VERSION reached a parallel build command")
    print("canonical version and parallel Make safety: OK")


if __name__ == "__main__":
    main()
