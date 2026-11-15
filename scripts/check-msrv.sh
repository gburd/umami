#!/usr/bin/env bash
set -euo pipefail

# A downstream crate checks the library without resolving CLI or test-only dependencies.
[[ $# == 1 && ($1 == library || $1 == cli) ]] || {
  echo 'Usage: check-msrv.sh {library|cli}' >&2
  exit 2
}
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/scratch/umami/target-ci}
if [[ $1 == cli ]]; then
  cd "$root"
  cargo +1.85.0 check -p umami-cli --locked
else
  scratch=${TMPDIR:-/scratch/umami}
  mkdir -p "$scratch"
  work=$(mktemp -d "$scratch/umami-msrv.XXXXXX")
  mkdir "$work/src"
  cat >"$work/Cargo.toml" <<EOF
[package]
name = "umami-msrv"
version = "0.0.0"
edition = "2021"
[dependencies]
umami = { package = "umami-log", path = "$root/umami", features = ["serde"] }
EOF
  printf 'pub use umami::*;\n' >"$work/src/lib.rs"
  cargo +1.74.0 check --manifest-path "$work/Cargo.toml"
fi
