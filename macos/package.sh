#!/bin/sh
# Builds RecoverKit.app for Apple silicon (self-contained .NET, bundled hashcat with Metal, ad-hoc
# signed) and wraps it in a disk image with the install instructions as its background.
#
#   macos/package.sh [version]          -> macos/out/RecoverKit-<version>-macos-arm64.dmg
#
# Needs: .NET 10 SDK, the native kernels (native/build.sh), Xcode command line tools, and
# dmgbuild (pip install dmgbuild; PYTHON=... picks the interpreter). The hashcat runtime is built by build-hashcat.sh if missing.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(dirname "$here")"
version="${1:-1.0.0}"
out="$here/out"
app="$out/RecoverKit.app"
export AVALONIA_TELEMETRY_OPTOUT=1 DOTNET_CLI_TELEMETRY_OPTOUT=1

if [ ! -f "$repo/native/bin/osx-arm64/librknative.dylib" ]; then
  if [ "${ALLOW_MANAGED_ONLY:-0}" = 1 ]; then echo "warning: librknative.dylib missing, packaging without the native kernels" >&2
  else echo "error: native/bin/osx-arm64/librknative.dylib is missing; run native/build.sh (or set ALLOW_MANAGED_ONLY=1)" >&2; exit 1; fi
fi
[ -x "$out/hashcat/hashcat" ] || sh "$here/build-hashcat.sh"

echo "==> Publishing RecoverKit $version (osx-arm64, self-contained)"
rm -rf "$out/publish" "$app"
dotnet publish "$repo/src/RecoverKit.App" -c Release -r osx-arm64 --self-contained true \
  -p:PublishSingleFile=false -p:Version="$version" -p:FileVersion="$version.0" -o "$out/publish"

echo "==> Assembling $app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp -R "$out/publish/." "$app/Contents/MacOS/"
rm -f "$app/Contents/MacOS/"*.pdb "$app/Contents/MacOS/rknative.dll"
sed "s/__VERSION__/$version/g" "$here/Info.plist" > "$app/Contents/Info.plist"
printf 'APPL????' > "$app/Contents/PkgInfo"
cp "$here/RecoverKit.icns" "$app/Contents/Resources/"
cp -R "$out/hashcat" "$app/Contents/Resources/hashcat"
plutil -lint "$app/Contents/Info.plist" >/dev/null

echo "==> Signing (ad-hoc)"
# Every Mach-O file first, innermost out, then the bundle itself. No hardened runtime: an ad-hoc
# signature cannot carry the JIT entitlement .NET would need under it.
# codesign treats everything in Contents/MacOS as code, the .NET assemblies included; in Resources
# only the Mach-O files (hashcat and its modules) are.
find "$app/Contents/MacOS" -type f ! -name RecoverKit | while IFS= read -r f; do codesign --force --sign - --timestamp=none "$f"; done
find "$app/Contents/Resources" -type f | while IFS= read -r f; do
  if file -b "$f" | grep -q 'Mach-O'; then codesign --force --sign - --timestamp=none "$f"; fi
done
codesign --force --sign - --timestamp=none "$app"
codesign --verify --deep --strict --verbose=1 "$app"

echo "==> Building disk image"
dmg="$out/RecoverKit-$version-macos-arm64.dmg"
rm -f "$dmg"
"${PYTHON:-python3}" -m dmgbuild -s "$here/dmg/settings.py" -D app="$app" -D assets="$here/dmg" "RecoverKit $version" "$dmg"
(cd "$out" && shasum -a 256 "$(basename "$dmg")" > "$(basename "$dmg").sha256")
echo "==> Done: $dmg"
