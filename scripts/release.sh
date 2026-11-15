#!/usr/bin/env bash
set -euo pipefail

# Build from a committed tree, never from uncommitted worktree files.
usage() {
  echo 'Usage: release.sh {source|build|check} REF ABSOLUTE_OUTPUT_DIRECTORY' >&2
  exit 2
}

[[ $# == 3 ]] || usage
mode=$1
ref=$2
out=$3
[[ $mode == source || $mode == build || $mode == check ]] || usage
[[ $ref =~ ^[[:alnum:]][[:alnum:]._-]*$ && $out == /* ]] || usage
name="umami-${ref#v}"
target=x86_64-unknown-linux-musl
# Keep this compiler fixed so local and CI release builds use the same toolchain.
toolchain=1.88.0
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/scratch/umami/target-ci}
export RUSTDOCFLAGS='-D warnings'
scratch=${TMPDIR:-/scratch/umami}

# Refuse existing output rather than replacing a previous release's evidence.
source_archive() {
  local commit
  commit=$(git rev-parse --verify "$ref^{commit}")
  mkdir "$out"
  git archive --format=tar --prefix="$name/" "$commit" | gzip -n >"$out/$name.tar.gz"
  (cd "$out" && sha256sum "$name.tar.gz" >SHA256SUMS)
}

# Cargo always runs inside the extracted source, including its path dependency.
extract_source() {
  mkdir -p "$scratch"
  work=$(mktemp -d "$scratch/umami-release.XXXXXX")
  tar -xzf "$out/$name.tar.gz" -C "$work"
  source_dir="$work/$name"
  printf 'Extracted release work: %s\n' "$work"
}

# Reject dynamically linked binaries and exercise the installed command's parser.
check_binary() {
  local binary=$1
  if readelf -l "$binary" | grep INTERP >/dev/null ||
    readelf -d "$binary" | grep NEEDED >/dev/null; then
    echo "Release binary is not static: $binary" >&2
    exit 1
  fi
  "$binary" --version
  printf 'service started\n' | "$binary" tokenize >"$work/tokenized"
  test -s "$work/tokenized"
}

# Build and test before packing the standalone binary and generated API documentation.
build_artifacts() {
  export SOURCE_DATE_EPOCH
  SOURCE_DATE_EPOCH=$(git show -s --format=%ct "$ref^{commit}")
  extract_source
  mkdir -p "$CARGO_TARGET_DIR"
  docs_target=$(mktemp -d "$CARGO_TARGET_DIR/release-docs.XXXXXX")
  (
    cd "$source_dir"
    cargo +"$toolchain" test --workspace --all-features --locked
    cargo +"$toolchain" doc --workspace --all-features --no-deps --locked \
      --target-dir "$docs_target"
    cargo +"$toolchain" build -p umami-cli --release --locked --target "$target"
  )
  mkdir "$work/$name-$target" "$work/$name-docs"
  cp "$CARGO_TARGET_DIR/$target/release/umami" "$work/$name-$target/"
  cp "$source_dir"/LICENSE-* "$work/$name-$target/"
  check_binary "$work/$name-$target/umami"
  cp -R "$docs_target/doc" "$work/$name-docs/api"
  cp -R "$source_dir/man" "$work/$name-docs/man"
  cp "$source_dir"/LICENSE-* "$work/$name-docs/"
  test -s "$work/$name-docs/api/umami/index.html"
  for directory in "$name-$target" "$name-docs"; do
    tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
      -C "$work" -cf - "$directory" | gzip -n >"$out/$directory.tar.gz"
  done
  (cd "$out" && sha256sum ./*.tar.gz >SHA256SUMS)
}

# Verify all checksums and rebuild/install from source without a crates.io publication.
check_artifacts() {
  (cd "$out" && sha256sum --check SHA256SUMS)
  extract_source
  (
    cd "$source_dir"
    cargo +"$toolchain" test --workspace --all-features --locked
    PATH="$work/install/bin:$PATH" \
      cargo +"$toolchain" install --path umami-cli --locked --root "$work/install"
  )
  "$work/install/bin/umami" --version
  tar -xzf "$out/$name-$target.tar.gz" -C "$work"
  check_binary "$work/$name-$target/umami"
  tar -xzf "$out/$name-docs.tar.gz" -C "$work"
  test -s "$work/$name-docs/api/umami/index.html"
  test -s "$work/$name-docs/man/umami.1"
}

case $mode in
source) source_archive ;;
build)
  source_archive
  build_artifacts
  ;;
check) check_artifacts ;;
esac
