"""Run a synthetic supervised process and print only verified aggregate evidence."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def demonstrate(binary: Path) -> dict:
    binary = binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="agentshield-demo-") as directory:
        key = str(Path(directory) / "integrity.key")
        log = str(Path(directory) / "session.jsonl")
        environment = {"PATH": "/usr/bin:/bin", "DEMO_API_TOKEN": "synthetic-example"}

        def run(*arguments: str, check: bool = True) -> subprocess.CompletedProcess:
            return subprocess.run(
                [str(binary), *arguments], env=environment, check=check,
                cwd=directory, capture_output=True, text=True, timeout=15,
            )

        run("audit", "init-key", key)
        child = run("run", "--privacy", "strict", "--interval", "50",
                    "--audit", log, "--audit-key", key, "--", "/bin/sh", "-c",
                    "sleep 0.4; exit 7", check=False)
        if child.returncode != 7:
            raise RuntimeError(f"Expected child exit 7, received {child.returncode}")

        snapshots = [json.loads(line) for line in child.stdout.splitlines() if line]
        receipt = json.loads(run("audit", "verify", log, "--audit-key", key).stdout)
        if not snapshots or receipt["verified"] is not True or receipt["records"] != len(snapshots):
            raise RuntimeError("Emitted snapshot count and authenticated audit count disagree")
        if "DEMO_API_TOKEN" in child.stdout or "synthetic-example" in child.stdout:
            raise RuntimeError("A synthetic identifier or value appeared in strict telemetry")
        if not any(entry["name"] == "[credential name redacted]"
                   for snapshot in snapshots for entry in snapshot["credentials"]):
            raise RuntimeError("No redacted credential name was observed")

        return {"child_exit": child.returncode, "verified_records": receipt["records"],
                "audit_verified": receipt["verified"], "credential_name_redacted": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="Path to the Linux AgentShield binary")
    print(json.dumps(demonstrate(parser.parse_args().binary), sort_keys=True))
