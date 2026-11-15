#!/usr/bin/env bash
set -euo pipefail

# Read both tag forms in one remote query and prefer an annotated tag's peeled commit.
[[ $# == 3 ]] || {
  echo 'Usage: check-release-ref.sh REMOTE TAG EXPECTED_COMMIT' >&2
  exit 2
}
remote=$1
tag=$2
expected=$3
git check-ref-format "refs/tags/$tag"
refs=$(git ls-remote --exit-code "$remote" "refs/tags/$tag" "refs/tags/$tag^{}")
commit=$(awk -v tag="refs/tags/$tag" '
  $2 == tag { direct = $1 }
  $2 == tag "^{}" { peeled = $1 }
  END { print peeled ? peeled : direct }
' <<<"$refs")
if [[ $commit != "$expected" ]]; then
  printf 'Release tag %s points to %s, expected %s; refusing publication.\n' \
    "$tag" "$commit" "$expected" >&2
  exit 1
fi
