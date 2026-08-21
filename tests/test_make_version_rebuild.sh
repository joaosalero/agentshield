#!/usr/bin/env bash
set -euo pipefail
original=$(mktemp)
cp VERSION "$original"
cleanup() {
  cp "$original" VERSION
  rm -f "$original"
  make all >/dev/null
}
trap cleanup EXIT INT TERM
printf '9.8.7\n' > VERSION
make -j8 all
test "$(./build/agentshield --version)" = "AgentShield 9.8.7"
echo "Make VERSION rebuild without clean: OK"
