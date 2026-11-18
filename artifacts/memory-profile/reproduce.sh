#!/bin/sh
set -eu
cd /home/ophir/dev/fidophir
profile_source=src/bin/memory_profile.rs
if test -e "$profile_source"; then
    echo 'Refusing to overwrite an existing profiling source' >&2
    exit 1
fi
trap 'rm -f "$profile_source"' EXIT
cp artifacts/memory-profile/memory_profile.rs "$profile_source"
cargo build --offline --release --features integration-tests --bin memory_profile
PROFILE_NATIVE=1 python3 artifacts/memory-profile/run.py
python3 artifacts/memory-profile/summarize.py
