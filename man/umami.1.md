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
2. **Structure signature** — hash the static tokens (literals and keys), plus a
   placeholder for each dynamic value, with FNV-1a into a stable 64-bit
   fingerprint. Dynamic values are numbers, timestamps, IPs, and any word that
   contains a digit or a **/** (hostnames like *web01*, ids, paths, URLs).
   Lines that differ only in dynamic values share the same signature.
3. **Profile** — look up the (system, signature) pair in the store.
   Track event counts, first/last seen times, the values seen in each
   parameter slot (up to 100 distinct values; past that the slot is treated
   as free-form and ignored), and inter-arrival statistics.
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
:   A structure that arrives at a steady rate has been silent for more than
    three of its mean intervals. Reported once, until it is seen again.

**system_away**
:   A system has sent nothing for ten minutes. Reported once, until it sends
    again.

**pipeline**, **sim** and **ingest** run the detector on *event time*: each
line is observed at its own timestamp (ISO 8601, Apache CLF, or syslog; a
syslog timestamp's year is inferred), and a line without one at the latest
timestamp seen so far. Silences are looked for once per minute of event time,
and each system is judged on its own clock, so with **--tagged** a system
whose timestamps lag the others' is not reported for the lag.
Replaying an old log therefore reports the stops and absences it contains.
Input is processed line by line, so these commands work on live streams
(**tail -f**, **journalctl -f**); invalid UTF-8 is replaced, not fatal.

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
    **static** — the structure signature: structural tokens joined by spaces,
    with **<\*>** for each parameter.

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

**umami pipeline** [*DETECT OPTIONS*] [**--show-all**]

Read log lines from standard input, run each through the detector, and print
anomalous lines to standard output. Each output line is prefixed with the anomaly
kind padded to 18 characters, then the original line. **event_stop** and
**system_away**, which have no line, print **[***system***]** and the
signature instead.

Without **--show-all**, normal (non-anomalous) lines are suppressed.

### Detect options

These apply to **pipeline**, **sim** and **ingest**.

**--system** *NAME*
:   Attribute events to this system name (default: **stdin**).

**--tagged**
:   Treat each input line as *system*\t*logline*, so several systems can be
    multiplexed on one stream. Lines without a tab are attributed to
    **--system**.

**--tokenizer** *structure*|*legacy*
:   Tokenizer variant (default: **structure**).

**--parameters**
:   Also emit **parameter_change** anomalies when a known structure receives a
    previously-unseen parameter value.

**--state** *FILE*
:   Load learned profiles from *FILE* if it exists, and save them back at the
    end of input and at most once a minute while input is idle, so learning
    carries over between runs. The file is replaced atomically (via
    *FILE***.tmp**), and is created before input is read, so an unwritable
    path fails at once. A file saved with a different **--tokenizer**, or by
    an incompatible version, is an error. A state learned from timestamped
    input resumes its clock, so a replay's untimed first line is not judged
    against the wall clock; one learned from untimed input keeps using the
    wall clock.

### Pipeline options

**--show-all**
:   Print every line; prefix normal lines with **ok** instead of suppressing them.

### Examples

    cat /var/log/syslog | umami pipeline --system web01

    # Show all lines annotated
    cat syslog | umami pipeline --show-all

    # Detect parameter changes too
    cat access.log | umami pipeline --parameters

    # Follow the journal, remembering what was learned last time
    journalctl -f | umami pipeline --state ~/.cache/umami.json

## sim

**umami sim** [*DETECT OPTIONS*]

Consume all of standard input and print a summary of anomaly counts, total event
count, and the noise-reduction percentage (fraction of lines filtered as
normal). Takes the detect options described under **pipeline**.

### Example

    cat /var/log/syslog | umami sim --system prod-web01

    events:    50000
    anomalies: 222
    reduction: 99.6%
    profiles:  210
      event_stop         9
      frequency_spike    12
      never_before_seen  210

## ingest

**umami ingest** [*DETECT OPTIONS*]

Read log lines from standard input and emit one JSON object per anomaly to
standard output (newline-delimited JSON).  Each JSON object has the fields:
**system**, **kind**, **score** (float 0–1), **hash** (the 16-hex-digit
structure hash, or **null** for **system_away**), **signature** (the
structure, with **<\*>** for each parameter), **line** (original log line;
empty for **event_stop** and **system_away**). Takes the detect options
described under **pipeline**.

### Examples

    cat /var/log/syslog | umami ingest --system web01 | jq .

    # Multi-system input
    paste -d'\t' systems.txt lines.txt | umami ingest --tagged

    # Example output line
    {"system":"web01","kind":"never_before_seen","score":1.00,
     "hash":"96a870bdc586e53c","signature":"disk full on <*>",
     "line":"disk full on /dev/sda1"}

## load

**umami load** [**--count** *N*] [**--tokenizer** *NAME*] [**--stdin**]

Throughput benchmark. By default generates *N* synthetic log lines from four
templates and measures how fast the detector filters them. With **--stdin**,
reads from standard input instead.

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
:   An error occurred (bad argument, I/O error, unreadable **--state** file,
    test failure). A closed output pipe (**| head**) is not an error.

# FILES

**corpus/structure.tsv**, **corpus/legacy.tsv**
:   Golden test corpora in *input*\t*expected* TSV format, used by the
    integration tests.

# SEE ALSO

**umami**(3)

Crate documentation: run **cargo doc --open -p umami** in the workspace.
