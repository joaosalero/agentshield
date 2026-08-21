#!/usr/bin/env bash
set -euo pipefail
archive="${1:?package archive required}"
checksum="$archive.sha256"
test -f "$archive" && test -f "$checksum"
python3 "$(dirname "$0")/verify_archive.py" "$archive" "$checksum"
echo "package verification: OK"
