#!/usr/bin/env python3
"""Generate a deterministic CycloneDX SBOM from AgentShield's declared inputs."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ["CMakeLists.txt", "Makefile", "cli", "core", "desktop", "engine", "policies", "scripts", "tests"]


def files():
    for name in INPUTS:
        path = ROOT / name
        candidates = [path] if path.is_file() else path.rglob("*")
        for candidate in candidates:
            if candidate.is_file() and "__pycache__" not in candidate.parts:
                yield candidate


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    components = []
    for path in sorted(files()):
        relative = path.relative_to(ROOT).as_posix()
        components.append({
            "type": "file",
            "name": relative,
            "bom-ref": f"file:{relative}",
            "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(path.read_bytes()).hexdigest()}],
        })
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "agentshield", "version": "0.1.0"},
            "tools": {"components": [{"type": "application", "name": "agentshield-sbom-generator", "version": "1"}]},
        },
        "components": components + [
            {"type": "library", "name": "OpenSSL libcrypto", "version": ">=3.0", "scope": "required"},
            {"type": "platform", "name": "Java Runtime", "version": ">=17", "scope": "optional"},
        ],
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
