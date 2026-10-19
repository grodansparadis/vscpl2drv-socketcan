#!/usr/bin/env bash
#
# Bump the version in src/version.h (YEAR.MONTH.PATCH).
#
# If the current (UTC) year/month equals the one in version.h the patch
# number is incremented, otherwise year/month are updated and patch is
# reset to zero. Prints the new version on stdout.
#

set -euo pipefail

VERSION_FILE="${1:-$(dirname "$0")/../src/version.h}"

get() {
  sed -nE "s/^#define[[:space:]]+$1[[:space:]]+([0-9]+).*/\1/p" "$VERSION_FILE"
}

year=$(get MAJOR_VERSION)
month=$(get MINOR_VERSION)
patch=$(get PATCH_VERSION)

if [[ -z "$year" || -z "$month" || -z "$patch" ]]; then
  echo "Failed to parse version from $VERSION_FILE" >&2
  exit 1
fi

now_year=$(date -u +%Y)
now_month=$((10#$(date -u +%m)))

if [[ "$year" -eq "$now_year" && "$month" -eq "$now_month" ]]; then
  patch=$((patch + 1))
else
  year=$now_year
  month=$now_month
  patch=0
fi

sed -i -E \
  -e "s/^(#define[[:space:]]+MAJOR_VERSION[[:space:]]+)[0-9]+/\1${year}/" \
  -e "s/^(#define[[:space:]]+MINOR_VERSION[[:space:]]+)[0-9]+/\1${month}/" \
  -e "s/^(#define[[:space:]]+PATCH_VERSION[[:space:]]+)[0-9]+/\1${patch}/" \
  -e "s/^(#define[[:space:]]+DISPLAY_VERSION[[:space:]]+)\"[^\"]*\"/\1\"${year}.${month}.${patch}\"/" \
  "$VERSION_FILE"

echo "${year}.${month}.${patch}"
