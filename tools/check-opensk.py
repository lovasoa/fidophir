#!/usr/bin/env python3
"""Reject prepared OpenSK source changes, including added or removed files.

The only allowed difference is the standalone crate's deployment Cargo.lock.
Run after preparation, before Cargo creates any build outputs in these trees.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read_source_tree(directory):
    return {path.relative_to(directory): path.read_bytes()
            for path in directory.rglob('*') if path.is_file()}


for crate in ('opensk', 'cbor'):
    upstream = read_source_tree(ROOT / 'vendor/OpenSK/libraries' / crate)
    prepared = read_source_tree(ROOT / 'build' / crate)
    if not upstream:
        raise SystemExit(f'{crate}: upstream source tree is missing')
    if crate == 'opensk':
        lock = Path('Cargo.lock')
        if prepared.pop(lock, None) != (ROOT / 'locks/opensk.Cargo.lock').read_bytes():
            raise SystemExit('opensk: prepared deployment lockfile differs')
        upstream.pop(lock, None)
    changed = sorted(path for path in upstream.keys() | prepared.keys()
                     if upstream.get(path) != prepared.get(path))
    if changed:
        raise SystemExit(f'{crate}: prepared sources differ: {changed}')

print('PASS: prepared OpenSK and CBOR sources match the pinned upstream')
