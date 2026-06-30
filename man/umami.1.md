% UMAMI(1) umami 0.1.0 | User Commands
% umami contributors
% 2024

# NAME

umami — log anomaly detection and structural tokenization

# SYNOPSIS

**umami** *SUBCOMMAND* [*OPTIONS*] [*ARGS*...]

# DESCRIPTION

**umami** learns the *structure* of streaming log events and surfaces only the
new, changed, and anomalous lines, filtering out repetitive, already-seen traffic.

The detection pipeline has four stages:

1. **Tokenize** — split each line into typed tokens (literals, delimiters,
   timestamps, IP addresses, quoted strings, numbers, JSON keys).
2. **Structure signature** — hash the static tokens (literals and keys) with
   FNV-1a into a stable 64-bit fingerprint. Lines that differ only in dynamic
   values (numbers, timestamps, IPs) share the same signature.
3. **Profile** — look up the (system, signature) pair in the in-memory store.
   Track event counts, first/last seen times, per-position parameter values
   (up to 100 distinct values), and inter-arrival statistics.
4. **Classify** — compare the new event against the learned profile and emit an
   anomaly kind, or suppress the event if it matches normal behavior.

Anomaly kinds:

**never_before_seen**
:   The structure has not been seen on any system.

**new_in_system**
:   The structure has been seen on other systems but not this one.

**parameter_change**
:   The structure is known but a dynamic parameter has a new value.

**frequency_spike**
:   Events are arriving significantly faster than the learned baseline
    (graded small, medium, or large by z-score magnitude).

**event_stop**
:   A periodic structure has gone silent beyond a stop threshold.

**system_away**
:   A system has stopped sending events entirely.

# SUBCOMMANDS

## tokenize

**umami tokenize** [**--tokenizer** *NAME*] [**--pretty** *STYLE*] [**--color**]
[**--test** *FILE* [**--fix**] [**--verbose**]] [*LINE*...]

Tokenize one or more log lines and print the result.  If no *LINE* arguments
are given, lines are read from standard input.

**--tokenizer** *structure*|*legacy*
:   Select the tokenizer variant.
    **structure** (default) — the modern tokenizer that understands
    **key=value** pairs (promoting the key to a **JsonKey** token), quoted
    strings, and JSON key/value contexts.
    **legacy** — the original whitespace-oriented tokenizer; splits on
    whitespace, peels leading/trailing punctuation, and recognizes IPv4
    addresses. Does not detect ISO 8601 timestamps.

**--pretty** *test*|*colors*|*params*|*delimiters*|*static*
:   Output format (default: **test**).
    **test** — reference format: **T{text}** tokens joined by spaces, where T
    is the numeric token type (0=literal, 1=delimiter, 2=timestamp, …).
    **colors** — original line text with ANSI color highlighting per token type
    (use with **--color** to activate).
    **params** — original line followed by a **\^\~\~\~** marker row marking
    each dynamic (parameter) token.
    **delimiters** — original line followed by a **\^** marker row marking
    each delimiter.
    **static** — structural tokens (literals and keys) joined by spaces; the
    structure-signature text.

**--color**
:   Enable ANSI coloring (only meaningful with **--pretty colors**).

**--test** *FILE*
:   Run a golden test file instead of tokenizing input. The file format is TSV:
    *input*\t*expected*, where expected is the **test**-format output. Failures
    are printed to standard output.

**--fix**
:   When used with **--test**, rewrite the file with the tokenizer's current
    output, updating any mismatched expected values in-place.

**--verbose**
:   With **--test**, also print passing cases.

### Examples

    # Tokenize a single line
    umami tokenize "Jan 23 10:23:45 web01 sshd[1234]: ok"

    # Show dynamic-parameter positions
    umami tokenize --pretty params "level=info duration=3.14 status=ok"

    # Colorized output
    umami tokenize --pretty colors --color "disk full on /dev/sda1"

    # Read from stdin; show only structural tokens
    journalctl -n 500 | umami tokenize --pretty static

    # Check a corpus file
    umami tokenize --test corpus/structure.tsv

## pipeline

**umami pipeline** [**--system** *NAME*] [**--tokenizer** *NAME*]
[**--parameters**] [**--show-all**]

Read log lines from standard input, run each through the detector, and print
anomalous lines to standard output. Each output line is prefixed with the anomaly
kind padded to 18 characters, then the original line.

Without **--show-all**, normal (non-anomalous) lines are suppressed.

**--system** *NAME*
:   Attribute events to this system name (default: **stdin**).

**--tokenizer** *structure*|*legacy*
:   Tokenizer variant (default: **structure**).

**--parameters**
:   Also emit **parameter_change** anomalies when a known structure receives a
    previously-unseen parameter value.

**--show-all**
:   Print every line; prefix normal lines with **ok** instead of suppressing them.

### Examples

    cat /var/log/syslog | umami pipeline --system web01

    # Show all lines annotated
    cat syslog | umami pipeline --show-all

    # Detect parameter changes too
    cat access.log | umami pipeline --parameters

## sim

**umami sim** [**--system** *NAME*] [**--tokenizer** *NAME*] [**--parameters**]

Consume all of standard input and print a summary of anomaly counts, total event
count, and the noise-reduction percentage (fraction of events filtered as normal).

**--system** *NAME*
:   System name (default: **stdin**).

**--tokenizer** *structure*|*legacy*
:   Tokenizer variant (default: **structure**).

**--parameters**
:   Include parameter-change anomalies in the count.

### Example

    cat /var/log/syslog | umami sim --system prod-web01

    events:    10000
    anomalies: 47
    reduction: 99.5%
    profiles:  312
      never_before_seen  31
      new_in_system      12
      parameter_change    4

## ingest

**umami ingest** [**--system** *NAME*] [**--tagged**] [**--tokenizer** *NAME*]
[**--parameters**]

Read log lines from standard input and emit one JSON object per anomalous event
to standard output (newline-delimited JSON).  Each JSON object has the fields:
**system**, **kind**, **score** (float 0–1), **signature** (structural tokens),
**line** (original log line).

**--system** *NAME*
:   Default system name when input is not tagged (default: **stdin**).

**--tagged**
:   Treat each input line as *system*\t*logline*. This allows multiple systems
    to be multiplexed on one input stream. Lines without a tab are attributed to
    **--system**.

**--tokenizer** *structure*|*legacy*
:   Tokenizer variant (default: **structure**).

**--parameters**
:   Emit parameter-change events.

### Examples

    cat /var/log/syslog | umami ingest --system web01 | jq .

    # Multi-system input
    paste -d'\t' systems.txt lines.txt | umami ingest --tagged

    # Example output line
    {"system":"web01","kind":"never_before_seen","score":1.00,
     "signature":"disk full on","line":"disk full on /dev/sda1"}

## load

**umami load** [**--count** *N*] [**--tokenizer** *NAME*] [**--stdin**]

Throughput benchmark. By default generates *N* synthetic log lines and measures
how fast the detector processes them. With **--stdin**, reads from standard input
instead.

**--count** *N*
:   Number of synthetic events to generate (default: **1000000**).

**--tokenizer** *structure*|*legacy*
:   Tokenizer variant (default: **structure**).

**--stdin**
:   Read lines from standard input instead of generating synthetic data.

### Example

    umami load
    umami load --count 500000
    cat big.log | umami load --stdin

# EXIT STATUS

**0**
:   Success.

**1**
:   An error occurred (bad argument, I/O error, test failure).

# FILES

**corpus/structure.tsv**, **corpus/legacy.tsv**
:   Golden test corpora in *input*\t*expected* TSV format, used by the
    integration tests.

# SEE ALSO

**umami**(3)

Crate documentation: run **cargo doc --open -p umami** in the workspace.
