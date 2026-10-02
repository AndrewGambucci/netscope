#!/bin/sh
# Wrap dist/NetScope.app in a drag-to-Applications disk image: dist/NetScope-<version>-macos-<arch>.dmg
set -eu
cd "$(dirname "$0")/../.."
VERSION=$(python3 -c 'import re;print(re.search(r"__version__ = \"([^\"]+)\"", open("netscope/__init__.py").read()).group(1))')
ARCH=$(uname -m)
STAGE=$(mktemp -d)
cp -R dist/NetScope.app "$STAGE/"
ln -s /Applications "$STAGE/Applications"
OUT="dist/NetScope-${VERSION}-macos-${ARCH}.dmg"
rm -f "$OUT"
hdiutil create -volname "NetScope" -srcfolder "$STAGE" -ov -format UDZO "$OUT"
rm -rf "$STAGE"
echo "Built $OUT"
