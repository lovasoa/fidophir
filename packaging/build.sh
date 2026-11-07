#!/usr/bin/env bash
# Build a package using the same recipes as CI. Run from any directory.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
format=${1:-}
output=${2:-dist}
mkdir -p "$output"
output=$(cd "$output" && pwd)

case "$format" in
  rpm)
    version=${PACKAGE_VERSION:-$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["package"]["version"])')}
    # Rust may come from rustup rather than RPM. Check the actual toolchain,
    # and retain RPM's checks for every other declared build dependency.
    requirements=$(rpmspec -q --buildrequires --define "fidophir_version $version" packaging/fidophir.spec)
    while IFS= read -r requirement; do
      read -r name operator minimum <<< "$requirement"
      case "$name" in
        rust) installed=$(rustc --version | cut -d ' ' -f 2) ;;
        cargo) installed=$(cargo --version | cut -d ' ' -f 2) ;;
        *)
          installed=$(rpm -q --whatprovides "$name" --qf '%{VERSION}\n') || {
            echo "Missing build dependency: $requirement" >&2
            exit 1
          }
          ;;
      esac
      if [[ -n $operator ]]; then
        [[ $operator == '>=' ]] || { echo "Unsupported dependency: $requirement" >&2; exit 1; }
        python3 - "$name" "$installed" "$minimum" <<'CHECK_VERSION'
import sys
name, installed, required = sys.argv[1:]
def version(value):
    parts = tuple(map(int, value.split("-", 1)[0].split(".")))
    return parts + (0,) * (3 - len(parts))
if not any(version(value) >= version(required) for value in installed.splitlines()):
    sys.exit(f"{name} {required} or newer is required; found {installed}")
CHECK_VERSION
      fi
    done <<< "$requirements"
    mkdir -p "$root/dist"
    topdir=$(mktemp -d "$root/dist/rpmbuild.XXXXXXXX")
    trap 'rm -rf -- "$topdir"' EXIT
    mkdir -p "$topdir/SOURCES"
    git ls-files -z | tar --null --files-from=- \
      --transform "s,^,fidophir-${version}/," \
      -czf "$topdir/SOURCES/fidophir-${version}.tar.gz"
    rpm_mode=-ba
    [[ ${RPM_BINARY_ONLY:-0} != 1 ]] || rpm_mode=-bb
    rpmbuild "$rpm_mode" --nodeps --define "_topdir $topdir" --define "fidophir_version $version" packaging/fidophir.spec
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
    echo "Usage: $0 {rpm|deb} [output-directory]" >&2
    exit 2
    ;;
esac
