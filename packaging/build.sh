#!/usr/bin/env bash
# Build a package using the same recipes as CI. Run from any directory.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
format=${1:-}
output=${2:-dist}
shift "$(( $# < 2 ? $# : 2 ))"
mkdir -p "$output"
output=$(cd "$output" && pwd)

case "$format" in
  rpm)
    version=${PACKAGE_VERSION:-$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["package"]["version"])')}
    mkdir -p "$root/dist"
    topdir=$(mktemp -d "$root/dist/rpmbuild.XXXXXXXX")
    trap 'rm -rf -- "$topdir"' EXIT
    mkdir -p "$topdir/SOURCES"
    git ls-files -z | tar --null --files-from=- \
      --transform "s,^,fidophir-${version}/," \
      -czf "$topdir/SOURCES/fidophir-${version}.tar.gz"
    rpm_mode=-ba
    [[ ${RPM_BINARY_ONLY:-0} != 1 ]] || rpm_mode=-bb
    rpmbuild "$rpm_mode" "$@" --define "_topdir $topdir" --define "fidophir_version $version" packaging/fidophir.spec
    find "$topdir/RPMS" -type f -name "fidophir-${version}-*.rpm" -exec cp -t "$output" -- {} +
    if [[ $rpm_mode == -ba ]]; then
      find "$topdir/SRPMS" -type f -name "fidophir-${version}-*.rpm" -exec cp -t "$output" -- {} +
    fi
    ;;
  deb)
    if [[ -n ${PACKAGE_VERSION:-} ]] && [[ $(dpkg-parsechangelog -S Version) != "$PACKAGE_VERSION" ]]; then
      dch --newversion "$PACKAGE_VERSION" --distribution unstable "Build commit ${SOURCE_SHA:-$(git rev-parse HEAD)}."
    fi
    # Set DEB_IGNORE_BUILD_DEPS=1 only when dependencies are supplied outside dpkg (as in CI).
    args=(--build=binary --no-sign)
    [[ ${DEB_IGNORE_BUILD_DEPS:-0} != 1 ]] || args+=(-d)
    dpkg-buildpackage "${args[@]}"
    version=$(dpkg-parsechangelog -S Version)
    find .. -maxdepth 1 -type f -name "fidophir_${version#*:}_*.deb" -exec cp -t "$output" -- {} +
    ;;
  *)
    echo "Usage: $0 {rpm|deb} [output-directory] [rpmbuild-options...]" >&2
    exit 2
    ;;
esac
