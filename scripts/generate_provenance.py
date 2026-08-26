#!/usr/bin/env python3
"""Create an in-toto statement describing local build artifacts without overclaiming SLSA."""
import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path
from read_version import read_version

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def project_version():
    try:
        return read_version(ROOT / "VERSION")
    except ValueError as error:
        raise SystemExit(str(error)) from error


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("artifacts", nargs="+")
    args = parser.parse_args()
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, text=True, capture_output=True
    ).stdout.strip()
    dirty = bool(subprocess.run(
        ["git", "status", "--porcelain"], cwd=ROOT, check=True, text=True, capture_output=True
    ).stdout)
    subjects = []
    for value in args.artifacts:
        path = Path(value).resolve()
        subjects.append({"name": path.name, "digest": {"sha256": sha256(path)}})
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://agentshield.dev/attestation/build-metadata/v1",
        "predicate": {
            "buildType": "agentshield/make/v1",
            "version": project_version(),
            "source": {"revision": revision, "dirty": dirty},
            "environment": {"os": os.uname().sysname, "architecture": os.uname().machine},
        },
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(statement, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
