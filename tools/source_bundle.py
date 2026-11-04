#!/usr/bin/env python3
"""Create a locked, offline-buildable source archive; never install or download."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    name = "fidophir-" + tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"]
    with tempfile.TemporaryDirectory(prefix="fidophir-bundle-") as temporary:
        stage = Path(temporary) / name
        shutil.copytree(root, stage, ignore=shutil.ignore_patterns(
            "target", "dist", ".cargo-home", "__pycache__", "*.pyc", ".git"))
        crates = stage / "vendor" / "crates"
        subprocess.run(["cargo", "vendor", "--frozen", "--versioned-dirs",
                        "--manifest-path", str(stage / "Cargo.toml"),
                        "--sync", str(stage / "vendor/opensk/Cargo.toml"), str(crates)],
                       check=True, stdout=subprocess.DEVNULL)
        (stage / ".cargo").mkdir(exist_ok=True)
        (stage / ".cargo/config.toml").write_text(
            '[source.crates-io]\nreplace-with = "vendored"\n'
            '[source.vendored]\ndirectory = "vendor/crates"\n')
        inventory = ["name\tversion\tlicense\tsource-checksum"]
        licenses = stage / "licenses"
        for crate in sorted(crates.iterdir()):
            package = tomllib.loads((crate / "Cargo.toml").read_text())["package"]
            checksum = json.loads((crate / ".cargo-checksum.json").read_text())["package"]
            inventory.append("\t".join([package["name"],package["version"],package.get("license", "SEE LICENSE"),checksum]))
            for path in crate.rglob("*"):
                if path.is_file() and path.name.upper().startswith(("LICENSE", "COPYING", "NOTICE", "COPYRIGHT")):
                    target = licenses / crate.name / path.relative_to(crate)
                    target.parent.mkdir(parents=True,exist_ok=True)
                    shutil.copyfile(path,target)
        for crate in ["opensk","cbor"]:
            target = licenses / crate
            target.mkdir(parents=True)
            shutil.copyfile(stage / "vendor" / crate / "LICENSE",target / "LICENSE")
        (stage / "DEPENDENCIES.tsv").write_text("\n".join(inventory)+"\n")
        hashes = []
        for path in sorted(stage.rglob("*")):
            if path.is_file():
                hashes.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(stage)}")
        (stage / "SHA256SUMS").write_text("\n".join(hashes)+"\n")
        archive = output / (name + ".tar.gz")
        with archive.open("wb") as raw, gzip.GzipFile(filename="",mode="wb",fileobj=raw,mtime=0) as compressed:
            with tarfile.open(fileobj=compressed,mode="w") as tar:
                for path in [stage,*sorted(stage.rglob("*"))]:
                    info = tar.gettarinfo(str(path),str(path.relative_to(stage.parent)))
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ""
                    if path.is_file():
                        with path.open("rb") as data:
                            tar.addfile(info,data)
                    else:
                        tar.addfile(info)
        print(archive)


if __name__ == "__main__":
    main()
