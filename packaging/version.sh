#!/usr/bin/env bash
# Print the package version for the checked-out commit.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ $(git rev-parse --is-shallow-repository) == true ]]; then
  echo 'A full Git history is required to calculate the package version.' >&2
  exit 1
fi
base=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["package"]["version"])')
# Commit count increases along main history, including when older builds are rerun.
commit_count=$(git rev-list --count HEAD)
sha=$(git rev-parse HEAD)
printf '%s+git%s.%s\n' "$base" "$commit_count" "${sha:0:12}"
