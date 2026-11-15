% UMAMI(1) umami 0.2.0 | User Commands
% umami contributors
% 2026

# NAME

umami - filter repetitive log events by structure

# SYNOPSIS

**umami** *SUBCOMMAND* [*OPTIONS*] [*ARGS*...]

# DESCRIPTION

umami groups events by fixed words and parameter positions.  It reports new structures,
unusual minute counts, stable-parameter changes, and silence.  A previously learned error
can recur without an alert; use explicit rules for known failures.

The independent tokenizer recognizes timestamps, numbers, IP addresses, quoted contents,
JSON keys, and key=value pairs.  Variable-looking text includes digits, paths, URLs, email
addresses, long hexadecimal identifiers, and dotted host:port values.  Exact signatures
retain parameter positions.  The Legacy tokenizer and compatibility claim have been removed.

# SUBCOMMANDS

## tokenize

**umami tokenize** [**--pretty** *STYLE*] [**--color**]
[**--test** *FILE* [**--fix**] [**--verbose**]] [*LINE*...]

Inspect arguments or standard input.  Styles are **test**, **colors**, **params**,
**delimiters**, and **static**.  The default test style renders typed tokens; static
renders fixed text with **<*>** for parameters.  Use --color with colors for ANSI output.

--test reads input/expected TSV pairs.  --verbose also prints passing cases.
--fix rewrites expectations in the supplied file.  Never use it on original reference
captures; review changes on a copy of an independent regression fixture instead.

    umami tokenize --pretty static 'request id=42 took 3 ms'
    umami tokenize --test umami/corpus/structure.tsv

## pipeline

**umami pipeline** [*DETECT OPTIONS*] [**--show-all**]

Print each anomaly kind followed by its original event.  With --show-all, print normal
events as **ok**.  Synthetic stop and away alerts print the system and structure instead
of a source line.  A multiline event retains embedded newlines.

## sim

**umami sim** [*DETECT OPTIONS*]

Print event count, anomaly count, suppression percentage, profile count, and counts by
kind.  Synthetic sweep alerts do not count as input events.  In multiline mode, events
are assembled messages rather than physical lines.

## ingest

**umami ingest** [*DETECT OPTIONS*]

Print one JSON object per anomaly, with **system**, **kind**, **score**, **hash**,
**signature**, **line**, and **changed_params**.  The hash is null for system-away events;
stop and away events have empty source lines.  Changed parameters use zero-based dynamic
slot ordinals, including positions occupied by excluded timestamps.  Scores are fixed
values by kind, not probabilities.

## load

**umami load** [**--count** *N*] [**--stdin**]

Run a throughput probe.  Default input contains one million synthetic events from four
templates; --stdin reads actual input.  This measures filtering speed, not detection quality.

# DETECT OPTIONS

The following apply to pipeline, sim, and ingest.

**--system** *NAME*
:   Attribute untagged input to this system (default: stdin).

**--tagged**
:   Read system, tab, and message per physical line.  A line without a tab uses --system.
    Cannot be combined with --multiline.

**--parameters**
:   Report new values in stable parameter slots.  Requires twenty preceding observations
    and at most one distinct value per ten observations.  Timestamp tokens are excluded;
    slots exceeding 100 distinct values become permanently free-form.  Without this option,
    no parameter-value tracking occurs.

**--multiline**
:   Join indented continuations to the preceding event.  Flush at EOF or after one second
    without input.  Events are limited to 1 MiB; exceeding the bound fails instead of silently
    dropping content.  Late continuations can form separate events.  Only the first physical
    line supplies the timestamp.

**--time-format** *FORMAT*
:   Parse a leading strftime-style timestamp with an explicit year, date, and time.
    Numeric offsets are supported; zone-less input uses UTC.  The parsed prefix becomes a
    timestamp token.  Invalid formats or mismatching input fail rather than falling back
    silently to automatic recognition.

**--state** *FILE*
:   Resume learned profiles and save accepted learning on completion, interruption, and
    periodic checkpoints.  A lifetime lock excludes another writer.  Atomic replacement
    uses a unique temporary file in the same directory.  Incompatible settings, malformed
    state, and old format versions fail without replacing existing state.  Keep the file
    in a trusted directory.  Version 0.1 state requires relearning under a new path.

# TIME AND ALERTS

Automatic recognition supports ISO, Apache CLF, and syslog headers.  Yearless syslog input
assumes substantially chronological order, with a separate initial reference-date rule and
continuing New Year inference.  Arbitrary reordering without years remains ambiguous.
Timestamped replay does not advance just because real time passes.  Untimed input uses wall
time until event-time history supplies an anchor.

Timestamps more than one day ahead of real time fail before changing learned state.  This
allowance does not make zone-less timestamps timezone-aware.

Frequency detection waits for thirty completed minute buckets.  Its threshold compares
current count to the historical mean with a variance floor.  A frequency_spike reports the
first crossing, not the eventual size of a flood.

Event-stop detection requires twenty regular intervals, a standard deviation no greater
than one fifth of the mean, and silence beyond three mean intervals.  Return gaps train the
baseline.  Stop and spike alerts have independent rolling 24-hour cooldowns.  Continuous
silence is one episode.  System-away defaults to ten minutes of absence.

# SHUTDOWN AND INPUT

Invalid UTF-8 is replaced.  SIGINT and SIGTERM request a checkpoint of accepted learning.
A blocked output pipe must not prevent saving; shutdown may discard queued output that
cannot drain.  SIGKILL and power loss cannot trigger a final save, so they can lose learning
since the last checkpoint.  Neither a checkpoint nor input buffering guarantees downstream
delivery of every emitted alert.

# EXAMPLES

    umami pipeline --system web < syslog
    journalctl -f | umami pipeline --state ~/.cache/umami.json
    umami ingest --parameters < syslog
    umami ingest --multiline < stacktraces.log
    umami sim --time-format '%Y/%m/%d %H:%M:%S' < custom.log

# FILES

**umami/corpus/structure.tsv**
:   Independent tokenizer regression expectations.

**umami/corpus/reference/**
:   Original unomalycli reference captures, retained for provenance rather than rewritten.

# SEE ALSO

**umami**(3), command help, and the repository README.
