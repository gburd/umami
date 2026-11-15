# umami CLI

Umami reads logs from stdin and reports novel structures, rate changes, missing periodic
messages, and changes in stable parameters.  The executable name is `umami`.

Build from the workspace checkout without requiring registry publication:

```sh
export CARGO_TARGET_DIR=/scratch/umami/build
cargo build --release --locked -p umami-cli
export PATH="$CARGO_TARGET_DIR/release:$PATH"
umami pipeline --state learned.json < application.log
umami ingest --parameters < application.log
umami sim < application.log
```

`pipeline` prints anomalies, `pipeline --show-all` prints every event, `ingest` writes JSON
anomalies, and `sim` summarizes the input.  `tokenize` shows the tokenizer's output.  Run
`umami <command> --help` for options.

## Input and timestamps

By default, each physical line supplies one event.  Input events cannot exceed 1 MiB.
Invalid UTF-8 becomes replacement characters.  `--tagged` accepts `system<TAB>line` and tracks
systems independently; lines without a tab use `--system` (default `stdin`).

`--multiline` joins indented continuation lines, preserving newlines and indentation.  It flushes
on a new unindented line, EOF, or one second without input, including a partial physical line.
An indented orphan starts an event of its own.  Continuations arriving after an idle flush
start another event.  The 1 MiB limit includes joined newlines.  Combining `--multiline` with
`--tagged` is not supported.

The first physical line supplies the event timestamp.  Automatic parsing recognizes ISO 8601,
CLF, and syslog headers.  Zone-less timestamps use UTC.  Initial yearless input uses historical
year inference.  Following input uses each system's last timestamp: forward gaps retain the
year, and a backward jump exceeding 183 days means New Year rollover.  Arbitrarily reordered
yearless logs require explicit years.  Input more than one day beyond the real wall clock fails
before changing learned state.  Idle input does not advance the event clock or emit silence alerts.

Use `--time-format` to parse a leading timestamp with chrono's strftime syntax:

```sh
umami pipeline --time-format '%d %B %Y %H:%M:%S %z' < application.log
```

Formats must include a full year.  Numeric timezone offsets work; named zones (`%Z`) do not.
Omitted offsets use UTC.  Every event must match.  The whole consumed prefix becomes one timestamp
token, so month names and other date text do not create different structures.

## Checkpoints and shutdown

`--state` takes a lifetime advisory lock through a persistent `.lock` sidecar.  Do not delete that
sidecar while a process owns the state.  Saves use unique same-directory files and atomic
replacement.  State format 2 rejects older or malformed files without replacing them.  Start
with a new file to relearn after upgrading from format 1.  Resume with the same tokenizer,
preprocessing options, system name, and parameter-tracking setting.

The CLI checkpoints changed learning every sixty monotonic seconds and on EOF, output errors,
SIGINT, or SIGTERM.  Bounded input and output queues let it checkpoint while input runs continuously
or stdout stops draining.  On a signal, accepted learning is saved, but buffered input not yet
observed and queued output may be discarded.  Slow or failed checkpoint storage can still delay
or prevent saving; SIGKILL cannot save.  A save failure exits with a diagnostic.

Parameter-change JSON records include `changed_params`, the zero-based dynamic parameter
ordinals that changed.  Timestamp tokens occupy ordinals but never trigger parameter changes.
