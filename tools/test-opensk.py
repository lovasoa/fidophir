#!/usr/bin/env python3
"""Run the downloaded OpenSK release's tests with its publisher-supplied lockfile.

Cargo cannot enable test features for a dependency outside our workspace. Locate
its manifest through Cargo, without assuming the cache layout or copying source.
"""
import json
import subprocess
import sys

cargo, target_directory = sys.argv[1:]
metadata = json.loads(subprocess.check_output([
    cargo, "metadata", "--locked", "--format-version", "1",
]))
opensk = next(package for package in metadata["packages"] if package["name"] == "opensk")
subprocess.run([
    cargo, "test", "--locked", "--manifest-path", opensk["manifest_path"],
    "--no-default-features", "--features", "std", "--lib",
    "--target-dir", target_directory,
], check=True)
