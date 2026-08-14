# Contributing

Thank you for improving `logwatch`. Changes should preserve the tool's bounded-memory behavior,
cross-platform operation, safe rendering, and stable JSON contract.

## Development setup

Install Rust 1.85 or newer, clone the repository, and run the normal checks from the repository
root:

```console
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
cargo build --release --locked
```

Run the observational benchmarks when a change affects parsing, aggregation, or rendering:

```console
cargo bench --bench analysis --locked
```

Benchmark results depend on input shape, filesystem, operating system, and build profile. Do not add
machine-specific timing thresholds to tests or CI.

## Parser changes

Keep parser code independent from rendering. A parser should produce the shared `Event` type and
leave absent fields as `None`. Prefer conservative extraction over a broad regular expression that
misclassifies ordinary text.

When adding or changing a parser:

1. Add focused parser tests for valid, malformed, timezone-less, and unexpected records.
2. Add at least one CLI integration test for the user-visible behavior.
3. Update the format table and architecture notes in `README.md` and `docs/architecture.md`.
4. Consider the line-size cap, invalid encoding, terminal sanitization, and high-cardinality behavior.

## Test fixtures

Use temporary files and generated input rather than real system logs. Tests should be deterministic,
small by default, and independent of the host's local timezone or locale. Avoid process-environment
mutation where a direct argument or fixture can express the behavior.

Security-sensitive tests should include terminal control characters, secret-like query strings, long
lines, invalid UTF-8, and binary-looking data. A malformed record should not fail the complete scan
when the record can be retained safely.

## Pull requests

Keep changes focused and describe the user-visible behavior. Include:

- a summary of the design and any compatibility impact
- test commands and relevant output
- documentation updates for new flags, formats, or JSON fields
- memory and performance considerations for new retained state
- security considerations when output or input handling changes

Do not commit `target/`, generated benchmark data, local editor settings, credentials, or private log
files. Human-readable repository content must not contain emojis or em dash characters.

## Release notes

Add unreleased changes to `CHANGELOG.md` without fabricating release dates or benchmark claims. A
maintainer handles version changes, packaging publication, and GitHub release metadata.
