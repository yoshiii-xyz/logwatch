# Security Policy

## Scope

`logwatch` is a local, read-only log analysis utility. It treats log content as untrusted input and
does not execute content, follow URLs, make network requests, or invoke shell commands.

The most important security properties are terminal-output safety, bounded memory, predictable regex
matching, safe path handling, and graceful decoding of malformed input.

## Supported versions

The latest release and the default branch receive security fixes during initial development. Older
unreleased snapshots may not receive backported fixes.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability
reporting flow for the repository when it is enabled, or contact the repository maintainers through
the private channel configured in the repository settings.

Include:

- the affected version or commit
- operating system and Rust version
- a minimal reproduction or sanitized input fixture
- expected and observed behavior
- whether terminal output, memory use, file handling, or JSON output is affected

Do not include real credentials, tokens, private log contents, or customer data in a report.

## Design notes

Human-readable dynamic content is sanitized before it reaches the terminal. Pattern fingerprints
redact common secret assignments and endpoint summaries remove query strings. These measures reduce
accidental disclosure but do not make logs or reports safe for public distribution.
