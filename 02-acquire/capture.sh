#!/usr/bin/env bash
# Logical acquisition harness for the burner-app action matrix.
# Usage:  ./tools/capture.sh <package> <action_tag>
# Example: ./tools/capture.sh com.hushed.release A10_burn
#
# Produces, under captures/<pkg>/<tag>_<timestamp>/ :
#   manifest.sha256    - per-file SHA-256 of /data/data/<pkg> (the "per-item manifest")
#   appdata.tar        - full logical acquisition (tar of the app data dir)
#   appdata.tar.sha256 - hash of the acquisition bundle (chain-of-custody)
#   meta.txt           - device, app version, timestamp
set -uo pipefail

# Git Bash rewrites /device/paths into Windows paths; disable that so
# adb pull's remote path (/data/local/tmp/...) is passed through verbatim.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

PKG="${1:?usage: capture.sh <package> <action_tag>}"
TAG="${2:?usage: capture.sh <package> <action_tag>}"
STAMP=$(date +%Y%m%d_%H%M%S)
OUT="captures/${PKG}/${TAG}_${STAMP}"
mkdir -p "$OUT"

# freeze app state before acquisition
adb shell am force-stop "$PKG" >/dev/null 2>&1

# provenance
{
  echo "package    : $PKG"
  echo "action_tag : $TAG"
  echo "timestamp  : $STAMP"
  echo "device     : $(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r') / android $(adb shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')"
  echo "app_version: $(adb shell dumpsys package "$PKG" 2>/dev/null | grep -m1 versionName | tr -d '\r' | sed 's/^ *//')"
} > "$OUT/meta.txt"

# per-file hash manifest, computed on-device (survives without extraction)
adb shell "su -c 'cd /data/data/$PKG 2>/dev/null && find . -type f -exec sha256sum {} \;'" \
  > "$OUT/manifest.sha256" 2>/dev/null

# full logical acquisition.
# NOTE: stream binary via 'adb pull' (sync protocol), NOT 'adb exec-out',
# because Windows adb corrupts binary stdout by injecting CR bytes.
DEVTMP="/data/local/tmp/appdata_${STAMP}.tar"
adb shell "su -c 'tar c -C /data/data/$PKG . > $DEVTMP 2>/dev/null; chmod 666 $DEVTMP'"
adb pull "$DEVTMP" "$OUT/appdata.tar" >/dev/null 2>&1
adb shell "su -c 'rm -f $DEVTMP'" >/dev/null 2>&1

# hash the bundle
( cd "$OUT" && sha256sum appdata.tar > appdata.tar.sha256 )

FILES=$(wc -l < "$OUT/manifest.sha256" | tr -d ' ')
SIZE=$(du -h "$OUT/appdata.tar" 2>/dev/null | cut -f1)
echo "[$PKG @ $TAG] captured -> $OUT   ($FILES files, tar $SIZE)"
