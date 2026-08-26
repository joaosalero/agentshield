#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(python3 "$root/scripts/read_version.py" "$root/VERSION")"
stage="$root/build/package/agentshield-$version-linux"
archive="$root/build/dist/agentshield-$version-linux.tar.gz"
case "$stage" in
  "$root"/build/package/agentshield-*-linux) ;;
  *) echo "refusing unsafe staging path: $stage" >&2; exit 1 ;;
esac
rm -rf "$stage"
mkdir -p "$stage/bin" "$stage/lib/agentshield" "$stage/share/agentshield/policies" "$stage/share/doc/agentshield" "$stage/share/applications" "$stage/share/icons/hicolor/scalable/apps" "$stage/share/metainfo" "$root/build/dist"
install -m 0755 "$root/build/agentshield" "$stage/bin/agentshield"
install -m 0755 "$root/scripts/agentshield-desktop" "$stage/bin/agentshield-desktop"
install -m 0644 "$root/build/agentshield-desktop.jar" "$stage/lib/agentshield/agentshield-desktop.jar"
install -m 0644 "$root/build/agentshield-source.cdx.json" "$stage/agentshield-source.cdx.json"
install -m 0644 "$root/build/agentshield-provenance.json" "$stage/agentshield-provenance.json"
install -m 0644 "$root"/policies/*.policy "$stage/share/agentshield/policies/"
install -m 0644 "$root/README.md" "$root/SECURITY.md" "$root/LICENSE" "$stage/share/doc/agentshield/"
install -m 0644 "$root"/docs/*.md "$stage/share/doc/agentshield/"
install -m 0644 "$root/VERSION" "$stage/share/doc/agentshield/VERSION"
install -m 0644 "$root/packaging/linux/io.agentshield.AgentShield.desktop" "$stage/share/applications/"
install -m 0644 "$root/packaging/linux/io.agentshield.AgentShield.svg" "$stage/share/icons/hicolor/scalable/apps/"
install -m 0644 "$root/packaging/linux/io.agentshield.AgentShield.metainfo.xml" "$stage/share/metainfo/"
find "$stage" -type d -exec chmod 0755 {} +
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" show -s --format=%ct HEAD)}"
export SOURCE_DATE_EPOCH
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -C "$root/build/package" -czf "$archive" "agentshield-$version-linux"
(cd "$(dirname "$archive")" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
