#!/bin/sh
# Keep the pinned upstream checkout untouched; patched sources are build outputs.
set -eu
cd "$(dirname "$0")/.."
if [ -f BUNDLED-SOURCES ]; then
    test -f build/opensk/src/env/mod.rs
    test -f build/cbor/Cargo.toml
    test -f build/opensk-revision
    exit 0
fi
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
git -C vendor/OpenSK rev-parse HEAD > build/opensk-revision
