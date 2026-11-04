#!/bin/sh
# Keep the pinned upstream checkout untouched; patched sources are build outputs.
set -eu
cd "$(dirname "$0")/.."
test -f vendor/OpenSK/libraries/opensk/Cargo.toml || {
    echo 'Run git submodule update --init (nested submodules are not needed).' >&2
    exit 1
}
mkdir -p build
for crate in opensk cbor; do
    rm -rf "build/$crate"
    cp -R "vendor/OpenSK/libraries/$crate" "build/$crate"
done
git apply --directory=build/opensk --check patches/opensk.patch
git apply --directory=build/opensk patches/opensk.patch
cp locks/opensk.Cargo.lock build/opensk/Cargo.lock
