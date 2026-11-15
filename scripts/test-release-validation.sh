#!/usr/bin/env bash
set -euo pipefail

# Use real ELF binaries and a local Git remote to exercise both release gates.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
scratch=${TMPDIR:-/scratch/umami}
mkdir -p "$scratch"
work=$(mktemp -d "$scratch/umami-validation-test.XXXXXX")

# A shell script must never reach its payload, even if it prints plausible output.
printf '#!/bin/sh\ntouch "%s/executed"\necho arbitrary\n' "$work" >"$work/nonelf"
chmod +x "$work/nonelf"
if "$script_dir/check-release-binary.sh" "$work/nonelf" 0.2.0; then
  echo 'FAIL: accepted a non-ELF executable' >&2
  exit 1
fi
test ! -e "$work/executed"
printf 'int main(void) { return 0; }\n' >"$work/dynamic.c"
cc "$work/dynamic.c" -o "$work/dynamic"
if "$script_dir/check-release-binary.sh" "$work/dynamic" 0.2.0; then
  echo 'FAIL: accepted a dynamic executable' >&2
  exit 1
fi
cat >"$work/static.rs" <<'EOF'
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("umami 0.2.0");
    } else {
        println!("0{{service}} 1{{ }} 0{{started}}");
    }
}
EOF
rustc +1.88.0 --target x86_64-unknown-linux-musl "$work/static.rs" -o "$work/static"
"$script_dir/check-release-binary.sh" "$work/static" 0.2.0
head -c 64 "$work/static" >"$work/truncated"
if "$script_dir/check-release-binary.sh" "$work/truncated" 0.2.0; then
  echo 'FAIL: accepted truncated ELF program headers' >&2
  exit 1
fi
if "$script_dir/check-release-binary.sh" "$work/static" 0.1.0; then
  echo 'FAIL: accepted the wrong version' >&2
  exit 1
fi
sed -i 's/0{{service}} 1{{ }} 0{{started}}/arbitrary/' "$work/static.rs"
rustc +1.88.0 --target x86_64-unknown-linux-musl "$work/static.rs" -o "$work/bad-smoke"
if "$script_dir/check-release-binary.sh" "$work/bad-smoke" 0.2.0; then
  echo 'FAIL: accepted incorrect tokenization' >&2
  exit 1
fi

mkdir "$work/remote"
git -C "$work/remote" init --quiet
git -C "$work/remote" config user.name 'Release test'
git -C "$work/remote" config user.email 'release-test@example.invalid'
git -C "$work/remote" -c commit.gpgsign=false commit --quiet --allow-empty -m 'First commit'
commit=$(git -C "$work/remote" rev-parse HEAD)
git -C "$work/remote" -c tag.gpgsign=false tag lightweight
git -C "$work/remote" -c tag.gpgsign=false tag -a annotated -m 'Annotated tag'
"$script_dir/check-release-ref.sh" "$work/remote" lightweight "$commit"
"$script_dir/check-release-ref.sh" "$work/remote" annotated "$commit"
git -C "$work/remote" -c commit.gpgsign=false commit --quiet --allow-empty -m 'Second commit'
other=$(git -C "$work/remote" rev-parse HEAD)
if "$script_dir/check-release-ref.sh" "$work/remote" annotated "$other"; then
  echo 'FAIL: accepted a tag pointing to another commit' >&2
  exit 1
fi
if "$script_dir/check-release-ref.sh" "$work/remote" missing "$commit"; then
  echo 'FAIL: accepted a missing tag' >&2
  exit 1
fi
printf 'Release validation self-check passed.  Evidence: %s\n' "$work"
