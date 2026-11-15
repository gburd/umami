# Release artifacts

GitHub Actions runs formatting, clippy, workspace tests, rustdoc, release-tool
self-checks, and separate MSRV checks.  Codeberg Actions stays disabled; this
repository has no Codeberg workflow.  Only the final GitHub publishing job gets
contents-write permission.  Checkout does not retain credentials.  The three
GitHub actions use full commit IDs checked against their public release tags.

## Supported artifacts

For tag vVERSION, the release workflow builds these files:

| File | Contents |
| --- | --- |
| umami-VERSION.tar.gz | Canonical source from the tagged Git commit, including Cargo.lock. |
| umami-VERSION-docs.tar.gz | Generated Rust API documentation and both manual formats. |
| umami-VERSION-x86_64-unknown-linux-musl.tar.gz | Static Linux x86_64 executable and licenses. |
| SHA256SUMS | SHA-256 hashes of the three archives. |

The Cargo packages use version 0.2.0.  The library package umami-log exports the
Rust crate umami; umami-cli installs the executable umami.  Calendar release tags
need not equal the Cargo version.  No crates.io publication happens here.

Only Linux x86_64-musl receives a prebuilt binary.  There are no distribution
packages, macOS binaries, container images, or WASM artifacts.  The unsigned
workflow outputs need the maintainer's detached signatures before a signed
release.  The maintainer also uploads these exact files to Codeberg; this workflow
does not obtain Codeberg credentials or enable Codeberg Actions.

## Build and verify locally

Use Linux x86_64 with Bash, Git, GNU tar, gzip, coreutils, binutils, Rustup, and a
C linker.  Debian's musl-tools provides the musl linker.  The release compiler
stays pinned to Rust 1.88.0.  The library supports 1.74, and the CLI supports 1.85;
those minimum versions do not promise that the test and benchmark dependencies
build on the same compiler.

From the repository, with the desired tag already present:

```sh
rustup toolchain install 1.88.0 --profile minimal --target x86_64-unknown-linux-musl
export CARGO_TARGET_DIR=/scratch/umami/target-ci
export TMPDIR=/scratch/umami/tmp
mkdir -p "$TMPDIR"
scripts/test-release.sh
scripts/test-release-validation.sh
scripts/release.sh build vVERSION /scratch/umami/dist-VERSION
scripts/release.sh check vVERSION /scratch/umami/dist-VERSION
```

The output directory must not exist before build.  The script archives the
specified commit, ignoring dirty and untracked files, and compiles the extracted
source with Cargo.lock enforced.  Source archives reproduce byte for byte.
Generated archives normalize ordering, ownership, timestamps, and gzip headers;
this does not claim bit-identical compiler output across different hosts.  Builds
need access to the dependencies in Cargo.lock, either cached locally or available
from crates.io.  The archive does not vendor third-party dependencies.

The check command validates checksums, reruns extracted workspace tests, installs
the CLI using its workspace path dependency, requires successful ELF inspection,
checks for x86_64 and absence of an interpreter or dynamic dependencies, verifies
the exact source-package version and tokenization output, and checks the generated
docs.  Fresh scratch directories retain evidence and avoid overwriting earlier
runs.  Remove those task-owned directories with trash when finished.

To install from an extracted source archive rather than crates.io:

```sh
cargo install --path umami-cli --locked
```

Run this inside the extracted workspace.  A standalone registry install of
umami-cli cannot resolve an unpublished umami-log package.

For source-only checks, release.sh source REF OUTPUT builds the canonical source
archive and SHA256SUMS without invoking Rust.  REF may also name a commit hash.
The self-check creates a temporary Git repository and exercises committed-only
contents, deterministic bytes, corruption detection, and refusal to overwrite.

The validation self-check uses a compiled static fixture, rejects non-ELF and
dynamic executables, truncated headers, incorrect versions, and incorrect smoke
output, and checks lightweight and annotated tags against a local Git remote.
It requires a C compiler and the pinned Rust toolchain with its musl target.

## Minimum supported Rust versions

```sh
rustup toolchain install 1.74.0 1.85.0 --profile minimal
scripts/check-msrv.sh library
scripts/check-msrv.sh cli
```

The library check builds a fresh downstream crate with the serde feature.  This
avoids resolving CLI and development dependencies on Cargo 1.74, which cannot
parse edition-2024 manifests.  It deliberately resolves the library's supported
dependency ranges rather than pretending that a workspace-wide lockfile tests a
standalone library consumer.  The CLI check uses the workspace lockfile.

## Workflow changes

```sh
shellcheck scripts/*.sh
shfmt -i 2 -d scripts/*.sh
actionlint
```

The tag workflow runs CI before building, checks the artifacts before uploading,
and publishes only the successful build's outputs.  Immediately before publication,
it resolves the remote tag, peeling annotated tags, and requires the result to equal
the workflow's triggering commit.  Tags must still remain immutable: GitHub offers
no atomic compare-and-create-release operation to close the interval between that
check and publication.  A pre-existing GitHub release
causes publication to fail rather than replacing its assets.  Remote publication
and download verification still require a real authorized tag push; local checks
do not prove those operations succeeded.
