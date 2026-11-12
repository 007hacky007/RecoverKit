#!/bin/sh
# Builds rknative for win-x64 and osx-arm64 with zig's bundled clang (cross-compiles from any host).
# Output: bin/win-x64/rknative.dll, bin/osx-arm64/librknative.dylib
set -eu
cd "$(dirname "$0")"
ZIG="${ZIG:-zig}"
ZIGVER="${ZIGVER:-0.15.2}"
# anyzig needs the version on the command line; a plain zig install ignores nothing, so try both.
if "$ZIG" "$ZIGVER" version >/dev/null 2>&1; then ZCC="$ZIG $ZIGVER cc"; else ZCC="$ZIG cc"; fi
CFLAGS="-O3 -std=c11 -Wall -Wextra -Wno-unused-function -Wno-unused-const-variable -fno-strict-aliasing"
mkdir -p bin/win-x64 bin/osx-arm64
$ZCC -target x86_64-windows-gnu $CFLAGS -shared -o bin/win-x64/rknative.dll rknative.c
rm -f bin/win-x64/rknative.lib bin/win-x64/rknative.pdb
$ZCC -target aarch64-macos $CFLAGS -shared -fvisibility=hidden -o bin/osx-arm64/librknative.dylib rknative.c
echo "built:"; ls -l bin/*/
