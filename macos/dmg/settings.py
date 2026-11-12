# dmgbuild settings for the RecoverKit disk image (see macos/package.sh).
#   dmgbuild -s macos/dmg/settings.py -D app=macos/out/RecoverKit.app -D assets=macos/dmg "RecoverKit <ver>" out.dmg
import os
import subprocess
import tempfile

here = os.path.abspath(defines.get("assets", "macos/dmg"))  # noqa: F821 - provided by dmgbuild
app = defines["app"]  # noqa: F821
app_name = os.path.basename(app.rstrip("/"))

# HiDPI background: the 1x and 2x PNGs combined into one multi-representation TIFF.
_tiff = os.path.join(tempfile.mkdtemp(prefix="recoverkit-dmg-"), "background.tiff")
subprocess.check_call(["tiffutil", "-cathidpicheck",
                       os.path.join(here, "background.png"), os.path.join(here, "background@2x.png"), "-out", _tiff])

format = "ULMO"   # LZMA: about a third smaller than zlib, readable since macOS 10.15
filesystem = "HFS+"
files = [app]
symlinks = {"Applications": "/Applications"}
icon = os.path.join(os.path.dirname(here), "RecoverKit.icns")
background = _tiff
show_status_bar = False
show_tab_view = False
show_toolbar = False
show_pathbar = False
show_sidebar = False
# 600 px background plus the 28 px title bar.
window_rect = ((200, 120), (760, 628))
default_view = "icon-view"
icon_size = 86
text_size = 12
# Icon centres, matching the loops drawn in background.html.
icon_locations = {app_name: (110, 92), "Applications": (330, 92)}
hide_extension = [app_name]
