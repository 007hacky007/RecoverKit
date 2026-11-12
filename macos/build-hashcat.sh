#!/bin/bash
# Builds hashcat from the official source release for macOS arm64 (Apple Silicon) with the Metal
# backend, and assembles a portable runtime folder for the RecoverKit app bundle:
#
#   macos/out/hashcat/   hashcat, modules/, bridges/, OpenCL/, charsets/, layouts/, masks/, rules/,
#                        tunings/, hashcat.hcstat2, docs/ (license texts), RECOVERKIT_BUNDLE
#
# Only hashcat's bundled dependencies (deps/) are used and nothing from Homebrew is linked; the
# result links against system libraries and frameworks only (checked with otool at the end).
#
# Portable mode: hashcat compares the folder of its own (resolved) executable with the install
# folder compiled in (PREFIX/bin, /usr/local/bin by default). When they differ it uses the
# executable's folder for everything (kernel sources, modules, kernel cache, sessions, dictstat),
# so the folder works from any location except /usr/local/bin.
#
# Usage: macos/build-hashcat.sh [--force] [--out DIR] [--jobs N]
# Needs: Xcode command line tools (clang, make), curl, shasum, tar. Runs on GitHub macos-15 arm64.
set -euo pipefail

HASHCAT_VERSION="7.1.2"
SOURCE_URL="https://hashcat.net/files/hashcat-${HASHCAT_VERSION}.tar.gz"
SOURCE_SHA256="9546a6326d747530b44fcc079babad40304a87f32d3c9080016d58b39cfc8b96"
# Bump when the build recipe or folder layout changes without a hashcat version change; the app
# re-copies its per-user engine copy whenever this stamp differs.
BUNDLE_REVISION="1"
STAMP="${HASHCAT_VERSION}-${BUNDLE_REVISION}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_ROOT="${HERE}/build"
OUT_PARENT="${HERE}/out"
FORCE=0
JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"

while [ $# -gt 0 ]; do
  case "$1" in
    --force) FORCE=1 ;;
    --out) OUT_PARENT="$2"; shift ;;
    --jobs) JOBS="$2"; shift ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

OUT="${OUT_PARENT}/hashcat"
STAMP_FILE="${OUT}/RECOVERKIT_BUNDLE"

if [ "$(uname -s)" != "Darwin" ] || [ "$(uname -m)" != "arm64" ]; then
  echo "This script builds the macOS arm64 hashcat and must run on an Apple Silicon Mac." >&2
  exit 1
fi

if [ "${FORCE}" = "0" ] && [ -x "${OUT}/hashcat" ] && [ "$(cat "${STAMP_FILE}" 2>/dev/null)" = "${STAMP}" ]; then
  echo "hashcat ${STAMP} already built in ${OUT} (use --force to rebuild)."
  exit 0
fi

mkdir -p "${BUILD_ROOT}"
TARBALL="${BUILD_ROOT}/hashcat-${HASHCAT_VERSION}.tar.gz"

verify() { [ "$(shasum -a 256 "$1" | awk '{print $1}')" = "${SOURCE_SHA256}" ]; }

if [ ! -f "${TARBALL}" ] || ! verify "${TARBALL}"; then
  echo "Downloading ${SOURCE_URL}"
  curl -fL --retry 3 -A "RecoverKit-build" -o "${TARBALL}.part" "${SOURCE_URL}"
  mv "${TARBALL}.part" "${TARBALL}"
fi
if ! verify "${TARBALL}"; then
  echo "SHA-256 mismatch for ${TARBALL} (expected ${SOURCE_SHA256})." >&2
  rm -f "${TARBALL}"
  exit 1
fi
echo "Source verified: sha256 ${SOURCE_SHA256}"

SRC="${BUILD_ROOT}/hashcat-${HASHCAT_VERSION}"
rm -rf "${SRC}"
tar -xzf "${TARBALL}" -C "${BUILD_ROOT}"

# The stock Makefile builds a universal (arm64 + x86_64) binary on Apple Silicon. Only arm64 is
# shipped, so drop the x86_64 slice (halves build time and size).
cp -p "${SRC}/src/Makefile" "${SRC}/src/Makefile.orig"
/usr/bin/sed -i '' '/-arch x86_64/d' "${SRC}/src/Makefile"

# A clean environment: no Homebrew include/library paths may leak into the build.
unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH LDFLAGS CFLAGS CPPFLAGS PKG_CONFIG_PATH || true
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
SDKROOT="$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
[ -n "${SDKROOT}" ] && export SDKROOT

# PRODUCTION=1: version from the release, not from "git describe" of an enclosing repository.
# USE_SYSTEM_*=0: hashcat's bundled zlib, LZMA, xxHash, OpenCL headers and unrar.
# The Python and Rust plugin bridges (-m 72000/73000/74000) are not shipped: they depend on
# whatever Python or Rust toolchain the build machine has (the clean PATH above hides cargo and
# Homebrew's python3-config), and RecoverKit does not use them.
# COMPTIME: the release date (mtime of the Makefile in the tarball) so rebuilds are reproducible.
MAKE_ARGS=(
  PRODUCTION=1
  SHARED=0
  USE_SYSTEM_LZMA=0 USE_SYSTEM_ZLIB=0 USE_SYSTEM_OPENCL=0 USE_SYSTEM_XXHASH=0 USE_SYSTEM_UNRAR=0
  ENABLE_UNRAR=1 ENABLE_BRAIN=1
  "COMPTIME=$(stat -f %m "${SRC}/src/Makefile.orig")"
)

echo "Building hashcat ${HASHCAT_VERSION} (arm64, Metal) with ${JOBS} jobs ..."
start=$(date +%s)
make -C "${SRC}" -j "${JOBS}" "${MAKE_ARGS[@]}" >"${BUILD_ROOT}/make.log" 2>&1 || {
  tail -50 "${BUILD_ROOT}/make.log" >&2
  echo "make failed, full log: ${BUILD_ROOT}/make.log" >&2
  exit 1
}
echo "Build finished in $(( $(date +%s) - start )) s."

# ---------------------------------------------------------------- assemble the portable folder
STAGE="${OUT}.partial"
rm -rf "${STAGE}"
mkdir -p "${STAGE}" "${STAGE}/docs"
install -m 755 "${SRC}/hashcat" "${STAGE}/hashcat"
mkdir -p "${STAGE}/bridges"
for b in argon2id_reference scrypt_jane scrypt_yescrypt; do
  install -m 644 "${SRC}/bridges/bridge_${b}.so" "${STAGE}/bridges/"
done
for d in modules OpenCL charsets layouts masks rules tunings; do
  cp -R "${SRC}/${d}" "${STAGE}/${d}"
done
install -m 644 "${SRC}/hashcat.hcstat2" "${STAGE}/"
for f in license.txt readme.txt changes.txt credits.txt; do
  install -m 644 "${SRC}/docs/${f}" "${STAGE}/docs/"
done
cp -R "${SRC}/docs/license_libs" "${STAGE}/docs/license_libs"
find "${STAGE}" -name '.gitkeep' -delete
find "${STAGE}" -type d -exec chmod 755 {} +
find "${STAGE}" -type f -exec chmod 644 {} +
chmod 755 "${STAGE}/hashcat"
echo "${STAMP}" > "${STAGE}/RECOVERKIT_BUNDLE"

# ---------------------------------------------------------------- checks
fail=0
check_links() {
  # Every dependency must be a system library or framework.
  local bad
  local id
  id="$(otool -D "$1" | tail -n +2)"
  bad="$(otool -L "$1" | tail -n +2 | awk '{print $1}' | grep -v -x -F "${id:-//none//}" | grep -v -E '^(/usr/lib/|/System/Library/)' || true)"
  if [ -n "${bad}" ]; then echo "Non-system dependency in $1: ${bad}" >&2; fail=1; fi
  if lipo -archs "$1" | grep -qv '^arm64$'; then echo "Not arm64-only: $1 ($(lipo -archs "$1"))" >&2; fail=1; fi
}
check_links "${STAGE}/hashcat"
for f in "${STAGE}"/modules/*.so "${STAGE}"/bridges/*.so; do
  [ -f "$f" ] && check_links "$f"
done
[ "${fail}" = "0" ] || { echo "Dependency check failed." >&2; exit 1; }
nmod=$(ls "${STAGE}"/modules/*.so | wc -l | tr -d ' ')
echo "Dependency check passed (hashcat + ${nmod} modules link only system libraries)."

"${STAGE}/hashcat" --version
rm -rf "${OUT}"
mv "${STAGE}" "${OUT}"
echo "Portable hashcat ${STAMP}: ${OUT} ($(du -sh "${OUT}" | awk '{print $1}'))"
