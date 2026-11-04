#!/usr/bin/env python3
"""Collect license notices for the Rust dependencies linked into the package."""
import json
from pathlib import Path
import shutil
import subprocess

metadata = json.loads(subprocess.check_output([
    "cargo", "metadata", "--locked", "--format-version", "1",
]))
output = Path("build/licenses")
shutil.rmtree(output, ignore_errors=True)
output.mkdir(parents=True)
inventory = ["name\tversion\tlicense"]
for package in metadata["packages"]:
    if package["id"] == metadata["resolve"]["root"]:
        continue
    inventory.append("\t".join([
        package["name"], package["version"], package.get("license") or "SEE LICENSE",
    ]))
    root = Path(package["manifest_path"]).parent
    for source in root.rglob("*"):
        if source.is_file() and source.name.upper().startswith(("LICENSE", "COPYING", "NOTICE", "COPYRIGHT")):
            target = output / f'{package["name"]}-{package["version"]}' / source.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
(output / "DEPENDENCIES.tsv").write_text("\n".join(inventory) + "\n")
