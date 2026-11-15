#!/usr/bin/env bash
set -euo pipefail

# Inspect successfully before executing; an unreadable or non-ELF input fails closed.
[[ $# == 2 ]] || {
  echo 'Usage: check-release-binary.sh BINARY EXPECTED_VERSION' >&2
  exit 2
}
binary=$1
version=$2
export LC_ALL=C
header=$(readelf --file-header "$binary" 2>&1) || {
  echo "$header" >&2
  exit 1
}
programs=$(readelf --program-headers "$binary" 2>&1) || {
  echo "$programs" >&2
  exit 1
}
dynamic=$(readelf --dynamic "$binary" 2>&1) || {
  echo "$dynamic" >&2
  exit 1
}
# GNU readelf can report corrupt headers but still return success.
if grep -Eq 'Error:|Warning:' <<<"$header $programs $dynamic"; then
  echo "ELF inspection reported malformed input: $binary" >&2
  exit 1
fi
grep -Eq 'Class:[[:space:]]+ELF64$' <<<"$header"
grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64$' <<<"$header"
grep -Eq 'Type:[[:space:]]+(EXEC|DYN)[[:space:]]' <<<"$header"
grep -Eq '^[[:space:]]+LOAD[[:space:]]' <<<"$programs"
if grep -Eq 'INTERP|NEEDED' <<<"$programs $dynamic"; then
  echo "Release binary is not static: $binary" >&2
  exit 1
fi
[[ $("$binary" --version) == "umami $version" ]]
[[ $(printf 'service started\n' | "$binary" tokenize) == '0{service} 1{ } 0{started}' ]]
