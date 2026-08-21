#!/usr/bin/env bash
set -euo pipefail
build=${1:?CMake build directory required}
original=$(mktemp)
cp VERSION "$original"
cleanup() {
  cp "$original" VERSION
  rm -f "$original"
}
trap cleanup EXIT INT TERM
printf '9.8.7\n' > VERSION
cmake --build "$build" --parallel
test "$("$build/agentshield" --version)" = "AgentShield 9.8.7"
echo "CMake VERSION reconfiguration: OK"
