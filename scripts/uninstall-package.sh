#!/usr/bin/env sh
set -eu
command -v apt-get >/dev/null 2>&1 || { echo "This uninstaller requires a Debian-compatible system." >&2; exit 1; }
echo "Removing AgentShield. User-created audit logs and policies are preserved."
sudo apt-get remove -- agentshield

