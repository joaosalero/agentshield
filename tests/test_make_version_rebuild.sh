#!/usr/bin/env bash
set -euo pipefail
original=$(mktemp)
scratch=$(mktemp -d)
cp VERSION "$original"
cleanup() {
  trap - EXIT INT TERM
  cp "$original" VERSION
  rm -f "$original"
  case "$scratch" in /tmp/*) rm -rf "$scratch" ;; esac
}
trap cleanup EXIT INT TERM
make BUILD="$scratch" -j8 all
printf '9.8.7\n' > VERSION
make BUILD="$scratch" -j8 all
test "$("$scratch/agentshield" --version)" = "AgentShield 9.8.7"
echo "Make VERSION rebuild without clean: OK"
