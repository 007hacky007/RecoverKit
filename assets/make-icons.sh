#!/usr/bin/env bash
# Regenerate the app icon and installer artwork from recoverkit.svg.
# Requires: rsvg-convert and ImageMagick (magick). Run from the repo root or anywhere.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(dirname "$here")"
cd "$here"

sizes="16 20 24 32 40 48 64 128 256"
for s in $sizes; do rsvg-convert -w "$s" -h "$s" recoverkit.svg -o "icon_$s.png"; done

# Multi-resolution .ico for the exe and shortcuts.
magick $(for s in $sizes; do echo "icon_$s.png"; done) "$repo/src/RecoverKit.App/Resources/recoverkit.ico"
cp "$repo/src/RecoverKit.App/Resources/recoverkit.ico" "$repo/installer/recoverkit.ico"

# WiX UI banner (493x58) and dialog (493x312).
magick -size 493x58 gradient:'#FFFFFF-#EEF3FB' \
  \( icon_48.png -resize 44x44 \) -gravity east -geometry +12+0 -composite \
  -size 493x3 xc:'#1F5FBF' -gravity south -composite \
  BMP3:"$repo/installer/banner.bmp"
magick -size 493x312 gradient:'#F3F6FB-#FFFFFF' \
  \( icon_256.png -resize 150x150 -alpha set -channel A -evaluate multiply 0.16 +channel \) -gravity southwest -geometry +18+22 -composite \
  \( -size 6x312 xc:'#1F5FBF' \) -gravity west -geometry +0+0 -composite \
  BMP3:"$repo/installer/dialog.bmp"

rm -f icon_*.png
echo "Regenerated recoverkit.ico, banner.bmp, dialog.bmp"
