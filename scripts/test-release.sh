#!/usr/bin/env bash
set -euo pipefail

# Exercise the source archive contract without compiling Rust or publishing anything.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
scratch=${TMPDIR:-/scratch/umami}
mkdir -p "$scratch"
work=$(mktemp -d "$scratch/umami-release-test.XXXXXX")
mkdir "$work/repo"
git -C "$work/repo" init --quiet
git -C "$work/repo" config user.name 'Release test'
git -C "$work/repo" config user.email 'release-test@example.invalid'
printf 'committed\n' >"$work/repo/fixture"
git -C "$work/repo" add fixture
git -C "$work/repo" -c commit.gpgsign=false commit --quiet -m 'Add fixture'
ref=$(git -C "$work/repo" rev-parse HEAD)
printf 'uncommitted\n' >"$work/repo/fixture"
printf 'untracked\n' >"$work/repo/untracked"

if [[ ! -x "$script_dir/release.sh" ]]; then
  echo 'FAIL: release.sh is missing or not executable' >&2
  exit 1
fi
(cd "$work/repo" && "$script_dir/release.sh" source "$ref" "$work/first")
(cd "$work/repo" && "$script_dir/release.sh" source "$ref" "$work/second")
cmp "$work/first/umami-$ref.tar.gz" "$work/second/umami-$ref.tar.gz"
mkdir "$work/extracted"
tar -xzf "$work/first/umami-$ref.tar.gz" -C "$work/extracted"
[[ $(cat "$work/extracted/umami-$ref/fixture") == committed ]]
[[ ! -e "$work/extracted/umami-$ref/untracked" ]]
(cd "$work/first" && sha256sum --check SHA256SUMS)
if (cd "$work/repo" && "$script_dir/release.sh" source "$ref" "$work/first") \
  >"$work/existing-output.log" 2>&1; then
  echo 'FAIL: overwrote existing output directory' >&2
  exit 1
fi
if (cd "$work/repo" && "$script_dir/release.sh" source missing-ref "$work/missing") \
  >"$work/missing-ref.log" 2>&1; then
  echo 'FAIL: accepted a missing commit' >&2
  exit 1
fi
printf 'corrupt\n' >>"$work/first/umami-$ref.tar.gz"
if (cd "$work/first" && sha256sum --check SHA256SUMS) >"$work/corruption.log" 2>&1; then
  echo 'FAIL: checksum accepted corruption' >&2
  exit 1
fi
printf 'Release source self-check passed.  Evidence: %s\n' "$work"
