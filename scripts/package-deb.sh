#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(python3 "$root/scripts/read_version.py" "$root/VERSION")"
architecture="${AGENTSHIELD_DEB_ARCH:-$(dpkg --print-architecture)}"
stage="$root/build/deb/agentshield-$version-$architecture"
output="$root/build/dist/agentshield_${version}_${architecture}.deb"
runtime_dependencies="$(ldd "$root/build/agentshield" | awk '{for(i=1;i<=NF;i++) if($i ~ /^\//){print $i; break}}' | while IFS= read -r library; do dpkg-query -S "$library" 2>/dev/null | awk -F: '$1 ~ /^[a-z0-9][a-z0-9+.-]*$/ {print $1; exit}'; done | sort -u | paste -sd, -)"
test -n "$runtime_dependencies" || { echo "unable to resolve native runtime dependencies" >&2; exit 1; }
case "$stage" in "$root"/build/deb/agentshield-*) ;; *) echo "refusing unsafe package path" >&2; exit 1;; esac
rm -rf "$stage"
mkdir -p "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/lib/agentshield" \
  "$stage/usr/share/agentshield/policies" "$stage/usr/share/doc/agentshield" \
  "$stage/usr/share/applications" "$stage/usr/share/icons/hicolor/scalable/apps" \
  "$stage/usr/share/metainfo" "$root/build/dist"
cat > "$stage/DEBIAN/control" <<EOF
Package: agentshield
Version: $version
Section: utils
Priority: optional
Architecture: $architecture
Depends: $runtime_dependencies, openjdk-17-jre | default-jre
Maintainer: AgentShield maintainers
Description: Runtime security for AI agents
 Privacy-first visibility, deterministic policy enforcement, and a guided Demo Lab.
EOF
install -m 0755 "$root/build/agentshield" "$stage/usr/bin/agentshield"
install -m 0755 "$root/scripts/agentshield-desktop" "$stage/usr/bin/agentshield-desktop"
install -m 0644 "$root/build/agentshield-desktop.jar" "$stage/usr/lib/agentshield/agentshield-desktop.jar"
install -m 0644 "$root"/policies/*.policy "$stage/usr/share/agentshield/policies/"
install -m 0644 "$root/README.md" "$root/SECURITY.md" "$root/LICENSE" "$root/VERSION" "$stage/usr/share/doc/agentshield/"
install -m 0644 "$root/packaging/linux/io.agentshield.AgentShield.desktop" "$stage/usr/share/applications/"
install -m 0644 "$root/packaging/linux/io.agentshield.AgentShield.svg" "$stage/usr/share/icons/hicolor/scalable/apps/"
install -m 0644 "$root/packaging/linux/io.agentshield.AgentShield.metainfo.xml" "$stage/usr/share/metainfo/"
find "$stage" -type d -exec chmod 0755 {} +
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" show -s --format=%ct HEAD)}"
export SOURCE_DATE_EPOCH
find "$stage" -print0 | xargs -0 touch --no-dereference --date="@$SOURCE_DATE_EPOCH"
dpkg-deb --root-owner-group --build "$stage" "$output"
sha256sum "$output" > "$output.sha256"
printf '%s\n' "$output"
