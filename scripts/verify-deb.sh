#!/usr/bin/env bash
set -euo pipefail
package="${1:?Debian package required}"
manifest="$package.sha256"
sha256sum --check "$manifest"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
dpkg-deb --info "$package" >/dev/null
dependencies="$(dpkg-deb --field "$package" Depends)"
case "$dependencies" in *openjdk-17-jre*|*default-jre*) ;; *) echo "Java runtime dependency missing" >&2; exit 1;; esac
case "$dependencies" in *libssl3*) ;; *) echo "OpenSSL runtime dependency missing" >&2; exit 1;; esac
dpkg-deb --extract "$package" "$work/root"
for file in \
  usr/bin/agentshield usr/bin/agentshield-desktop \
  usr/lib/agentshield/agentshield-desktop.jar \
  usr/share/applications/io.agentshield.AgentShield.desktop \
  usr/share/icons/hicolor/scalable/apps/io.agentshield.AgentShield.svg \
  usr/share/metainfo/io.agentshield.AgentShield.metainfo.xml \
  usr/share/doc/agentshield/LICENSE; do
  test -f "$work/root/$file" || { echo "missing package member: $file" >&2; exit 1; }
done
test -x "$work/root/usr/bin/agentshield"
test -x "$work/root/usr/bin/agentshield-desktop"
grep -q '^Exec=agentshield-desktop$' "$work/root/usr/share/applications/io.agentshield.AgentShield.desktop"
grep -q '^Icon=io.agentshield.AgentShield$' "$work/root/usr/share/applications/io.agentshield.AgentShield.desktop"
if find "$work/root" -type f -perm /6000 | grep -q .; then echo "setuid/setgid file found" >&2; exit 1; fi
echo "Debian installer verification: OK"
