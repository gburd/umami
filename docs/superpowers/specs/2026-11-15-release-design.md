# Umami release design

Status: approved by the maintainer on 2026-11-15.  Implementation and qualification pending.

## Goal

Address all fourteen findings from the November 14 review, independently review the resulting
branch, fix the review findings, qualify the release, and publish its artifacts.  Preserve the
current source and October history throughout.

## Approved decisions

1. Make umami an independent detector, rather than a compatible implementation of unomalycli.
2. Rename the registry package to umami-log, retaining the Rust library name and executable
   name umami.  Use package version 0.2.0 for the incompatible API and state changes, and an
   annotated calendar tag dated when qualification finishes.
3. Use AWS profile chorus for a dedicated Debian EC2 qualification instance, then terminate
   the resources created for this task.  Never substitute the host instance role.
4. Use GitHub Actions for hosted CI.  GitHub and Codeberg release credentials and the configured
   signing key received explicit approval.  Keep Codeberg Actions disabled.

## Approaches

Preserving reference compatibility would retain the legacy tokenizer and restore the original
structure expectations.  That conflicts with several proposed grouping improvements and keeps
two implementations to maintain.

An independent detector preserves exact structure matching while improving variable recognition.
This approach best fits the requested filter behavior and permits removing the quadratic legacy
implementation.  The maintainer approved this approach.

Replacing exact matching with learned wildcard clustering risks suppressing new structures.
The prior audit measured that tradeoff; this release will not introduce it.

## Scope and acceptance

| Finding | Change | Acceptance evidence |
| --- | --- | --- |
| 1. Uncommitted October work | Base an isolated release branch on the preserved 18 commits; leave the user's dirty checkout intact. | Tree comparison against current source; review commit attribution without rewriting existing commits. |
| 2. Stuck event clock | Separate initial year inference from chronological continuation; validate future input before mutating state. | Multi-day gaps, New Year, historical replay, tagged clocks, and rejected future input preserving saved state. |
| 3. Golden provenance | Document the reference origin; keep an original reference fixture distinct from independent regression expectations. | Reviewed expected differences, never a blanket regeneration to pass tests. |
| 4. Repeated alerts | Persist separate rolling 24-hour cooldowns per system, structure, and stop/spike kind; preserve episode latches. | Same-day suppression, next-day recurrence, independent systems, and restart persistence. |
| 5. Incorrect statistics | Compare current minute counts against completed-minute statistics; retain interval regularity only for stops and learn return gaps. | Quantized heartbeat, irregular arrivals, empty minutes, late events, and a same-second flood. |
| 6. Parameter floods | Exclude timestamp tokens from tracking; learn stable low-cardinality slots before reporting new values; identify changed slots. | Varying timestamps and IDs stay quiet; stable-value change reports the correct slot. |
| 7. Shutdown loses learning | Wake the input loop on SIGINT/SIGTERM and monotonic checkpoint deadlines; save on the main thread. | Real subprocess signals with idle stdin, continuous input, reloadable state, and save failures. |
| 8. Multiline events | Add explicit indentation-based multiline mode; preserve content, bound buffered bytes, and flush on EOF or an idle deadline. | One stack trace yields one event; orphans, limits, EOF, and delayed continuation behavior documented and tested. |
| 9. Timestamp formats | Add CLI --time-format using a standard date-format parser; normalize the parsed prefix to a timestamp token. | Unsupported default formats work explicitly; offsets, invalid formats, and mismatches fail clearly. |
| 10. Package cannot ship | Rename package, include licenses and corpus, and remove package-external doctest dependencies. | Package archive extracted outside the workspace builds and passes tests/doctests. |
| 11. No CI | Add lint/test/MSRV and artifact workflows without activating hosted execution prematurely. | Workflow validation plus actual authorized CI run before tagging. |
| 12. Quadratic legacy tokenizer | Remove legacy implementation and its options if independence is approved. | Callers/docs updated; quote-heavy regression on retained tokenizer. |
| 13. Variable shapes | Improve host:port, email, hex, URL-query, and grouped-number recognition. | Focused token and signature tests, reviewed golden changes, and grouping evaluation. |
| 14. Unused parameter tracking | Gate extraction and tracking before allocations when disabled. | Empty default trackers, unchanged classifications, and measured resource use. |

Also fix concurrent state writers with a lifetime lock and unique atomic-save temporary files.
Reject malformed or incompatible state without replacing it.  New tokenization changes hashes:
increment the state format, report incompatibility, and never silently reset learned profiles.

## Behavioral contracts

Yearless auto-parsing assumes substantially ordered input.  Initial inference keeps the existing
historical bootstrap rule.  Continuing inference permits forward calendar movement and treats
large backward movement as New Year rollover.  Arbitrarily reordered yearless logs remain
ambiguous; explicit years are required for those replays.  Reject real-future timestamps beyond
the documented allowance instead of quietly poisoning the clock.

Minute-count thresholds require calibration, not just a successful unit test.  Proposed starting
values: thirty completed minutes of learning and a variance floor of max(variance, mean, 1).
Keep structural novelty immediate.  A stop requires enough low-variance intervals; learning an
outage gap can delay subsequent stop eligibility.  Document that tradeoff.

Multiline assembly remains opt-in to preserve existing per-line behavior.  The first version
uses indentation, not a new regex language.  Specify a byte bound and idle flush deadline in
the implementation plan.  Do not silently combine different tagged systems.  The event's first
physical line supplies its timestamp.  Continuation timestamps cannot advance the clock.

Signal handling must not perform file I/O in a signal handler.  Check blocked-output behavior
explicitly: waking idle input alone does not guarantee a checkpoint while stdout is blocked.
Do not claim universal shutdown safety without a passing backpressure test.

## Qualification and release

Use failing regression tests before each behavioral fix.  Keep changes in reviewable commits,
run an independent whole-branch review, then independently verify its corrections.

Qualify formatting, warnings-as-errors clippy, release build, workspace tests, doctests, library
without default features, library with serde, advertised library/CLI MSRVs, extracted packages,
state failure cases, shutdown, synthetic detector workloads, and labelled grouping samples.
Record toolchains, commands, results, and deviations.  Run the requested Debian EC2 qualification
only after an account and credential grant; local tests are not a substitute.

Release artifacts: canonical source tarball, SHA256 checksums, documentation archive, CLI binary
archives for qualified targets, and a detached signature when an authorized signing key is
available.  Publish matching artifacts to the existing forges.  Crates.io upload requires a
separate explicit credential grant.  Never tag before qualification and artifact verification.

No speculative clustering, profile eviction, semantic incident classifier, or fabricated
performance guarantee belongs in this release.
