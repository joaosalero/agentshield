#!/usr/bin/env sh
set -eu
package=${1:-}
if [ -z "$package" ] || [ ! -f "$package" ]; then
  echo "Usage: $0 path/to/agentshield_VERSION_ARCH.deb" >&2
  exit 2
fi
case "$package" in *.deb) ;; *) echo "Refusing non-Debian package: $package" >&2; exit 2;; esac
command -v apt-get >/dev/null 2>&1 || { echo "This installer requires a Debian-compatible system." >&2; exit 1; }
echo "Installing AgentShield. Your package manager may request administrator approval."
sudo apt-get install -- "$package"
echo "AgentShield is installed. Open it from the application menu or run: agentshield-desktop"

