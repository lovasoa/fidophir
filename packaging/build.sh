#!/usr/bin/env bash
# Build a package using the same recipes as CI. Run from any directory.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
format=${1:-}
if [[ -z $format ]]; then
  . /etc/os-release
  case " $ID ${ID_LIKE:-} " in
    *debian*|*ubuntu*) format=deb ;;
    *fedora*|*rhel*|*suse*) format=rpm ;;
  esac
fi
output=${2:-dist}
shift "$(( $# < 2 ? $# : 2 ))"
mkdir -p "$output"
output=$(cd "$output" && pwd)
version=${PACKAGE_VERSION:-$(bash packaging/version.sh)}

case "$format" in
  rpm)
    # External toolchains (including rustup) are not represented in RPM's database.
    # Explicit rpmbuild options take precedence over automatic selection.
    if (( $# == 0 )) && ! rpm -qf "$(command -v rustc)" "$(command -v cargo)" >/dev/null 2>&1; then
      set -- --without system_rust
    fi
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
    if [[ $(dpkg-parsechangelog -S Version) != "$version" ]]; then
      dch --newversion "$version" --distribution unstable "Build commit ${SOURCE_SHA:-$(git rev-parse HEAD)}."
    fi
    # Set DEB_IGNORE_BUILD_DEPS=1 only when dependencies are supplied outside dpkg (as in CI).
    args=(--build=binary --no-sign)
    [[ ${DEB_IGNORE_BUILD_DEPS:-0} != 1 ]] || args+=(-d)
    dpkg-buildpackage "${args[@]}"
    version=$(dpkg-parsechangelog -S Version)
    find .. -maxdepth 1 -type f -name "fidophir_${version#*:}_*.deb" -exec cp -t "$output" -- {} +
    ;;
  *)
    echo "Usage: $0 [rpm|deb] [output-directory] [rpmbuild-options...]" >&2
    exit 2
    ;;
esac
