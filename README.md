<p align="center">
  <img src="assets/logo.png" width="160" alt="logwatch logo">
</p>

<h1 align="center">logwatch</h1>

<p align="center">
  Fast, bounded-memory analysis for application, server, system, and developer logs.
</p>

<p align="center">
  <a href="https://github.com/yoshiii-xyz/logwatch/actions/workflows/ci.yml"><img src="https://github.com/yoshiii-xyz/logwatch/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT license"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.85%2B-orange.svg" alt="Rust 1.85 or newer"></a>
</p>

`logwatch` turns large, messy log files into a compact diagnostic report. It streams input one
record at a time, recognizes common structured and semi-structured formats, aggregates recurring
messages, analyzes severity and HTTP status data, and emits either a readable terminal report or
stable JSON for automation.

It is intentionally a local analysis tool. It does not send logs anywhere, execute commands found
in log content, or attempt to replace a metrics, tracing, or observability platform.

## Why logwatch

Manual log inspection is often a sequence of guesses: find a timestamp, search for a severity word,
count a status code, then repeat the work for every new incident. `logwatch` gives that workflow a
single deterministic entry point while keeping the important details visible:

| Capability | Behavior |
| --- | --- |
| Streaming input | Reads files and stdin incrementally with a reusable bounded line buffer. |
| Tolerant parsing | Supports plain text, JSON Lines, common or Nginx-style access logs, and syslog-like records. |
| Useful defaults | Reports line counts, time coverage, severity counts, recurring patterns, and HTTP metrics when present. |
| Practical filters | Filter by severity, exact text, safe regular expression, status code, or timezone-aware time bounds. |
| Bounded aggregation | Heavy hitters use a configurable Space-Saving table instead of an unbounded unique-message map. |
| Safe rendering | Control characters and terminal escape sequences are escaped before human-readable output. |
| Automation | JSON output has a versioned schema and never contains terminal formatting. |
| Live analysis | Follow one regular file with a low-frequency polling loop and clean refreshes on an interactive terminal. |

## Install

`logwatch` is distributed from source while the first public release is being established. Install
from a checkout with Rust 1.85 or newer:

```console
cargo install --path . --locked
logwatch --help
```

Install directly from the public repository after it is available:

```console
cargo install --git https://github.com/yoshiii-xyz/logwatch.git logwatch
```

Build an optimized binary without installing it:

```console
cargo build --release --locked
```

The binary is written to `target/release/logwatch` on Unix-like systems and
`target\release\logwatch.exe` on Windows.

## Quick start

Analyze one file:

```console
logwatch server.log
```

Read from a pipeline:

```console
cat server.log | logwatch -
```

The same command works with PowerShell and other shells because `logwatch` reads stdin directly:

```powershell
Get-Content .\server.log | logwatch -
```

Use JSON in a script:

```console
logwatch --json server.log
```

Analyze several files in one pass:

```console
logwatch app.log worker.log proxy.log
```

The human renderer displays a compact report similar to this abbreviated layout:

```text
logwatch 0.1.0

INPUT
  sources                 1
  bytes read              18.4 KiB
  lines read              412
  records                 412 parsed, 412 matched, 0 filtered

TIME
  range                   2026-08-14T12:00:00Z to 2026-08-14T12:42:00Z
  timestamps              412 known, 412 with timezone

SEVERITY
  error                  17
  warn                   33
  info                  362

TOP MESSAGE PATTERNS
       12  database timeout for user <num>
        7  upstream request failed with status <num>
```

The exact report depends on the input and configured filters.

## Command reference

```text
logwatch [OPTIONS] [INPUT]...
```

If no input is supplied, `logwatch` reads stdin. Use `-` explicitly when composing a pipeline.

| Option | Description |
| --- | --- |
| `--format auto\|plain\|jsonl\|nginx\|syslog` | Select the input parser. The default is `auto`. |
| `-j`, `--json` | Emit the versioned JSON report. |
| `--follow` | Follow one regular file and refresh the human report. Requires an interactive stdout terminal. |
| `--interval DURATION` | Follow polling interval, such as `250ms`, `1s`, or `2m`. |
| `--min-severity LEVEL` | Keep `trace`, `debug`, `info`, `notice`, `warn`, `error`, `critical`, or `fatal` and higher. |
| `--errors` | Keep errors, critical records, and fatal records. |
| `--warnings` | Keep warnings and more severe records. |
| `--grep TEXT` | Keep records containing an exact, case-sensitive substring. |
| `--regex REGEX` | Keep records matching a Rust regular expression. Matching is linear-time. |
| `--status CODE` | Keep an HTTP status code. Repeat for multiple codes. |
| `--since TIME` | Keep records after an RFC 3339 timestamp or within a duration such as `2h`. |
| `--until TIME` | Keep records before an RFC 3339 timestamp or a duration measured back from now. |
| `--top N` | Display at most `N` patterns and endpoints. Default: `10`. |
| `--max-patterns N` | Bound tracked message patterns and endpoints. Default: `4096`. |
| `--max-time-buckets N` | Bound temporal buckets while the interval adapts. Default: `4096`. |
| `--max-line-bytes N` | Skip lines larger than `N` bytes. Default: `1048576`. |
| `--allow-binary` | Decode binary-looking input as lossy UTF-8 instead of skipping it. |
| `-h`, `--help` | Show help. |
| `-V`, `--version` | Show the version. |

Argument errors return exit code `2`. Runtime input or output errors return exit code `1`.

## Format detection and parsing

Automatic detection is deliberately conservative. It evaluates each non-empty record and chooses a
parser when the record has a recognizable shape:

| Format | Detection and extracted fields |
| --- | --- |
| Plain text | Fallback for any line. Extracts common ISO-like timestamps and contextual severity markers. |
| JSON Lines | An object beginning with `{`. Reads common timestamp, level, message, HTTP, and duration fields. |
| Common or Nginx access log | Recognizes the remote address, bracketed timestamp, quoted request, status, size, and optional duration. |
| Syslog-like | Recognizes optional priority, `Mon day time`, host, tag, optional PID, and message. |

Use an explicit format when a mixed file contains misleading prefixes or when a parser should be
validated strictly. A malformed structured record is retained as text and reported as a warning;
`logwatch` does not silently discard it.

### Plain text

The plain parser recognizes timestamps such as:

```text
2026-08-14T12:30:00Z ERROR request failed for user 42
2026-08-14 12:30:00 [WARN] cache is stale
```

Timestamp extraction is limited to a short prefix so a huge message does not cause a full-line
search. Severity detection prioritizes bracketed, prefix, and `level=ERROR` forms. Ordinary words
such as `error` in the middle of a sentence are not treated as a severity marker.

### Timestamps and time zones

Timestamps with an offset or `Z` are timezone-aware and can participate in absolute time filters.
Timestamps without a zone are retained as wall-clock timestamps. `logwatch` does not silently
assign the local timezone or UTC to them. The report shows whether the time axis is `zoned` or
`wallClock` and counts records that have no timezone.

Syslog month-day timestamps are represented as partial timestamps because assigning a year would be
an invention. They remain visible through parser and record counts but are not placed into a
chronological series.

### Message patterns

The pattern fingerprint is intentionally conservative. It redacts common secret assignments, then
replaces UUIDs, IPv4 addresses, hexadecimal values, and numeric values with placeholders. The
original message remains available to filters, while the rendered and JSON pattern report contains
the normalized value.

Aggregation is bounded by `--max-patterns`. Once the table is full, a Space-Saving heavy-hitter
table replaces low-frequency entries as needed. A report with evictions marks pattern counts as
approximate and includes an error estimate for each retained entry.

## Filtering

Filters run after parsing and before aggregation. This keeps the summary focused without retaining
all input records in memory:

```console
logwatch app.log --errors
logwatch app.log --min-severity warn --grep database
logwatch proxy.log --status 500 --status 503
logwatch app.log --regex "timeout|connection refused"
logwatch app.log --since 2h
```

The regular expression implementation is the Rust `regex` engine. It intentionally omits
backreferences and look-around constructs that can create unpredictable matching cost.

Absolute `--since` and `--until` comparisons require a timezone-aware timestamp. A timezone-less
record is excluded from a time-bound query and summarized once in the warnings section.

## HTTP analysis

Access logs and structured records with HTTP fields produce an HTTP section containing:

- request count and responses with status `400` or higher
- status-code distribution
- bounded method distribution
- bounded top endpoints with query strings removed
- average and maximum duration when a duration is available
- the slowest observed request

The parser accepts common access-log durations as seconds and structured `duration_ms` values as
milliseconds. It does not claim to understand arbitrary custom access-log formats.

## Follow mode

Follow mode is a focused live workflow for one regular file:

```console
logwatch server.log --follow --interval 1s
```

It waits between polls instead of spinning at end of file, processes complete newline-terminated
records, and redraws the current human report. Truncation is treated as a new file and starts a
fresh report. Length-changing replacement is detected by the next metadata check. A replacement
with exactly the same length cannot be identified portably by the Rust standard library and should
be followed after restarting the command. Ctrl+C is handled by the host process and leaves no raw
terminal mode enabled.

Follow mode is intentionally incompatible with JSON output and redirected stdout. Use a normal
snapshot for automation.

## JSON output

JSON output is a schema, not a serialization of terminal strings. It includes `schemaVersion` so
automation can reject incompatible changes deliberately:

```json
{
  "schemaVersion": 1,
  "version": "0.1.0",
  "inputs": [
    {
      "path": "server.log",
      "status": "processed",
      "error": null,
      "statistics": {
        "bytesRead": 1024,
        "linesRead": 20,
        "recordsParsed": 20,
        "recordsMatched": 20,
        "recordsFiltered": 0,
        "malformedRecords": 0,
        "invalidUtf8Lines": 0,
        "truncatedLines": 0,
        "recordsWithTimestamps": 20,
        "recordsWithTimezone": 20,
        "recordsWithoutTimezoneForFilter": 0
      },
      "parsers": {"plain": 20},
      "warnings": []
    }
  ],
  "statistics": {},
  "time": {},
  "severity": {},
  "patterns": {},
  "http": null,
  "parsers": {},
  "warnings": []
}
```

The abbreviated `statistics` and `time` objects in this example are expanded in actual output.
Fields use camelCase. Consumers should tolerate compatible additional fields and use
`schemaVersion` for breaking changes.

## Performance and memory

The default scan path is:

```text
Input source -> bounded decoder -> complete-line reader -> parser -> filter -> aggregators -> renderer
```

Important bounds and tradeoffs:

- Input is buffered with a 64 KiB reader and a line buffer capped by `--max-line-bytes`.
- Invalid UTF-8 is replaced per line. A line over the cap is counted and skipped, so an adversarial
  line cannot grow memory without limit.
- The analyzer retains counters, bounded heavy-hitter tables, status maps, and adaptive time buckets.
  It never retains the input file or a vector of all records.
- JSON parsing allocates only for the current capped line and its decoded object.
- Time buckets begin at one minute and double their interval when the configured capacity is full.
- The regex engine has predictable linear-time behavior for supported filters.

Run the benchmark suite on representative filesystems and input shapes:

```console
cargo bench --bench analysis --locked
```

The benchmarks are observational. They intentionally do not enforce a machine-specific timing
threshold. Benchmark methodology and environment should accompany any performance claim.

## Encoding and malformed input

UTF-8 is the primary input encoding. ASCII is naturally supported. UTF-8 with a byte-order mark and
UTF-16 with a little-endian or big-endian byte-order mark are recognized. Invalid UTF-8 is decoded
lossily and counted. Binary-looking input containing NUL bytes is skipped with a warning unless
`--allow-binary` is supplied.

Malformed timestamps, unknown levels, unexpected fields, invalid JSON records, and custom formats
are non-fatal whenever the line can still be retained as text. Warning categories are aggregated
so a noisy file does not flood the terminal.

## Security considerations

Log content is untrusted input. `logwatch`:

- does not execute shell commands or invoke `grep`, `awk`, `sed`, `tail`, or other external tools
- does not fetch URLs or make network requests
- escapes terminal control characters before rendering content in the human report
- uses JSON serialization for machine output, preserving valid escaping
- removes query strings from endpoint summaries and redacts common secret assignments in pattern fingerprints
- caps line length, pattern tables, endpoint tables, time buckets, and warning categories

The tool reads the paths explicitly supplied by the user. It does not recursively walk directories
or follow links as an implicit side effect. Treat report files and JSON output as potentially
sensitive because log analysis can reveal operational details even when common secrets are redacted.

See [SECURITY.md](SECURITY.md) for vulnerability reporting guidance.

## Platform support

The core application uses Rust standard-library file and stdin APIs and is designed for Windows,
Linux, and macOS. The CI matrix covers all three platforms. Platform-specific filesystem behavior
can still affect locked files, rotation timing, permissions, path spelling, and console interruption.

The tool does not depend on Unix command-line utilities, shell path syntax, or a particular line
ending convention. Windows users can pass paths normally and can use PowerShell pipelines for stdin.

## Architecture

The implementation is separated into small Rust modules:

| Module | Responsibility |
| --- | --- |
| `cli` | Clap argument model, validation, duration parsing, and command orchestration. |
| `scanner` | File and stdin sources, BOM detection, bounded line reading, and follow polling. |
| `parser` | Format strategies and the shared `Event` representation. |
| `aggregate` | Filters, counters, bounded heavy hitters, HTTP metrics, and adaptive time buckets. |
| `render` | Terminal-safe human output. JSON uses the serializable report model directly. |
| `model` | Stable domain and JSON report types. |

See [docs/architecture.md](docs/architecture.md) for the data flow, memory invariants, and design
tradeoffs.

## Development

The project needs Rust 1.85 or newer. From a checkout:

```console
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
cargo build --release --locked
cargo package --locked
```

Run the CLI directly during development:

```console
cargo run -- --help
cargo run -- --json fixtures/example.log
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for parser changes, fixture guidance, and pull request
expectations.

## Changelog and release policy

Release notes are kept in [CHANGELOG.md](CHANGELOG.md). The project follows Semantic Versioning
once the public compatibility boundary is established. The JSON schema version and documented CLI
behavior are the important automation interfaces.

## License

Distributed under the [MIT License](LICENSE).
