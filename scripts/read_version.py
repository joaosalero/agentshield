#!/usr/bin/env python3
"""Read exactly one canonical AgentShield semantic version line."""
import re
from pathlib import Path


def read_version(path):
    try:
        data = Path(path).read_bytes()
        text = data.decode("ascii")
    except (OSError, UnicodeDecodeError) as error:
        raise ValueError("VERSION must be a readable ASCII file") from error
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\n?", text):
        raise ValueError("VERSION must contain exactly one semantic x.y.z line")
    return text.rstrip("\n")


if __name__ == "__main__":
    import sys
    try:
        if len(sys.argv) != 2:
            raise ValueError("one VERSION path is required")
        print(read_version(sys.argv[1]))
    except ValueError as error:
        raise SystemExit(str(error))
