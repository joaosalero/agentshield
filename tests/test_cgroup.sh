#!/usr/bin/env bash
set -euo pipefail

binary=$(realpath "${1:?binary required}")
script_dir=$(dirname "$(realpath "$0")")
membership=$(cut -d: -f3 /proc/self/cgroup)
parent="/sys/fs/cgroup$membership"

if test ! -w "$parent"; then
  if "$binary" run --cgroup -- true >/dev/null 2>&1; then
    echo "cgroup mode accepted without delegation" >&2
    exit 1
  fi
  echo "cgroup delegation fail-closed: OK"
fi

if ! command -v systemd-run >/dev/null 2>&1 || ! systemctl --user is-system-running >/dev/null 2>&1; then
  if test "${AGENTSHIELD_REQUIRE_CGROUP_TEST:-0}" = 1; then
    echo "cgroup delegated integration required but unavailable" >&2
    exit 1
  fi
  echo "cgroup delegated integration: SKIP (no user service manager)"
  exit 0
fi

systemd-run --user --wait --collect --quiet --pipe -p Delegate=yes \
  "$binary" run --cgroup --max-memory-mb 64 --max-processes 16 \
  --max-cpu-percent 50 --agent-output inherit -- sh -c '
    IFS=: read -r _ _ membership < /proc/self/cgroup
    case "$membership" in *agentshield-agent-*) ;; *) exit 21;; esac
    path="/sys/fs/cgroup$membership"
    IFS= read -r memory < "$path/memory.max"
    IFS= read -r pids < "$path/pids.max"
    IFS= read -r cpu < "$path/cpu.max"
    test "$memory" = 67108864
    test "$pids" = 16
    test "$cpu" = "50000 100000"
  ' >/dev/null

echo "delegated cgroup v2 limits and cleanup: OK"

escape_dir=$(mktemp -d)
trap 'rm -rf "$escape_dir"' EXIT
pid_file="$escape_dir/escaped.pid"
systemd-run --user --wait --collect --quiet --pipe -p Delegate=yes \
  "$binary" run --cgroup -- python3 "$script_dir/cgroup_escape.py" "$pid_file" >/dev/null
test -s "$pid_file"
escaped_pid=$(cat "$pid_file")
for _ in $(seq 1 100); do
  kill -0 "$escaped_pid" 2>/dev/null || break
  sleep 0.01
done
if kill -0 "$escaped_pid" 2>/dev/null; then
  echo "session-escaped descendant survived cgroup termination" >&2
  exit 1
fi

echo "cgroup termination contains session-escaped descendants: OK"
