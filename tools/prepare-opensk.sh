#!/bin/sh
# Copy the pinned upstream libraries without changing their source files.
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
# The standalone upstream crate has no suitable deployment lockfile. Keep our
# audited dependency resolution separately; this is the only prepared-file change.
cp locks/opensk.Cargo.lock build/opensk/Cargo.lock
