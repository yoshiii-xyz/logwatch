use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use clap::{Parser, ValueEnum};
use regex::Regex;

use crate::aggregate::{AnalyzerConfig, Filter};
use crate::model::Severity;
use crate::render::render_human;
use crate::scanner::{follow_file, scan_sources};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum InputFormat {
    Auto,
    Plain,
    Jsonl,
    Nginx,
    Syslog,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum SeverityArg {
    Trace,
    Debug,
    Info,
    Notice,
    Warn,
    Error,
    Critical,
    Fatal,
}

impl From<SeverityArg> for Severity {
    fn from(value: SeverityArg) -> Self {
        match value {
            SeverityArg::Trace => Self::Trace,
            SeverityArg::Debug => Self::Debug,
            SeverityArg::Info => Self::Info,
            SeverityArg::Notice => Self::Notice,
            SeverityArg::Warn => Self::Warn,
            SeverityArg::Error => Self::Error,
            SeverityArg::Critical => Self::Critical,
            SeverityArg::Fatal => Self::Fatal,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "logwatch",
    version,
    about = "Analyze application, server, system, and developer logs",
    long_about = "Analyze large logs with bounded memory, tolerant parsing, useful summaries, and script-friendly JSON output."
)]
pub struct Cli {
    /// Log file paths. Use - for stdin. If omitted, stdin is used.
    #[arg(value_name = "INPUT", value_hint = clap::ValueHint::FilePath)]
    pub inputs: Vec<PathBuf>,

    /// Select the input parser. Auto detects JSON Lines, access logs, syslog-like records, and plain text.
    #[arg(long, value_enum, default_value_t = InputFormat::Auto)]
    pub format: InputFormat,

    /// Emit a stable JSON document instead of the human-readable report.
    #[arg(short = 'j', long)]
    pub json: bool,

    /// Follow one regular file and refresh the report as complete lines are appended.
    #[arg(long)]
    pub follow: bool,

    /// Follow-mode polling interval, such as 250ms, 1s, or 2m.
    #[arg(long, default_value = "1s", value_parser = parse_duration)]
    pub interval: Duration,

    /// Keep records at this severity or above.
    #[arg(long, value_enum, conflicts_with_all = ["errors", "warnings"])]
    pub min_severity: Option<SeverityArg>,

    /// Keep errors, critical records, and fatal records.
    #[arg(long, conflicts_with_all = ["warnings", "min_severity"])]
    pub errors: bool,

    /// Keep warnings, errors, critical records, and fatal records.
    #[arg(long, conflicts_with_all = ["errors", "min_severity"])]
    pub warnings: bool,

    /// Keep records containing this exact, case-sensitive substring.
    #[arg(long, value_name = "TEXT")]
    pub grep: Option<String>,

    /// Keep records matching this Rust regex. The regex engine guarantees linear-time matching.
    #[arg(long, value_name = "REGEX")]
    pub regex: Option<String>,

    /// Keep only these HTTP status codes. Repeat the option for multiple codes.
    #[arg(long, value_name = "CODE")]
    pub status: Vec<u16>,

    /// Keep records at or after an RFC 3339 timestamp or within the last duration, such as 2h.
    #[arg(long, value_name = "TIME")]
    pub since: Option<String>,

    /// Keep records at or before an RFC 3339 timestamp or a duration measured back from now.
    #[arg(long, value_name = "TIME")]
    pub until: Option<String>,

    /// Number of top patterns and endpoints to display.
    #[arg(long, default_value_t = 10, value_parser = parse_positive_usize)]
    pub top: usize,

    /// Maximum number of tracked message patterns and endpoints.
    #[arg(long, default_value_t = 4096, value_parser = parse_positive_usize)]
    pub max_patterns: usize,

    /// Maximum number of time buckets retained while choosing an adaptive interval.
    #[arg(long, default_value_t = 4096, value_parser = parse_positive_usize)]
    pub max_time_buckets: usize,

    /// Maximum bytes retained for one input line. Longer records are skipped.
    #[arg(long, default_value_t = 1024 * 1024, value_parser = parse_positive_usize)]
    pub max_line_bytes: usize,

    /// Process binary-looking input with lossy UTF-8 decoding instead of skipping it.
    #[arg(long)]
    pub allow_binary: bool,
}

pub fn run(cli: Cli) -> Result<u8, String> {
    validate(&cli)?;
    let filter = build_filter(&cli)?;
    let config = AnalyzerConfig {
        filter,
        max_patterns: cli.max_patterns,
        max_time_buckets: cli.max_time_buckets,
        top: cli.top,
    };

    if cli.follow {
        let path = cli.inputs.first().ok_or_else(|| "--follow requires one input path".to_owned())?;
        return follow_file(path, cli.format, cli.max_line_bytes, cli.allow_binary, config, cli.interval);
    }

    let inputs = if cli.inputs.is_empty() { vec![PathBuf::from("-")] } else { cli.inputs.clone() };
    let result = scan_sources(&inputs, cli.format, cli.max_line_bytes, cli.allow_binary, config);
    let report = result.report;
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    if cli.json {
        serde_json::to_writer_pretty(&mut stdout, &report)
            .map_err(|error| format!("could not write JSON: {error}"))?;
        writeln!(stdout).map_err(|error| format!("could not finish output: {error}"))?;
    } else {
        stdout
            .write_all(render_human(&report).as_bytes())
            .map_err(|error| format!("could not write report: {error}"))?;
    }
    stdout.flush().map_err(|error| format!("could not flush report: {error}"))?;
    Ok(u8::from(result.had_errors))
}

fn validate(cli: &Cli) -> Result<(), String> {
    if cli.json && cli.follow {
        return Err("--json and --follow cannot be combined".to_owned());
    }
    if cli.follow {
        if cli.inputs.len() != 1 || cli.inputs.first().is_some_and(|path| path.as_os_str() == "-") {
            return Err("--follow requires exactly one regular file path".to_owned());
        }
        if !io::stdout().is_terminal() {
            return Err("--follow requires an interactive stdout terminal".to_owned());
        }
        if cli.interval.is_zero() {
            return Err("--interval must be greater than zero".to_owned());
        }
    }
    if cli.status.iter().any(|status| *status > 999) {
        return Err("HTTP status codes must be between 0 and 999".to_owned());
    }
    if cli.regex.as_deref().is_some_and(|pattern| Regex::new(pattern).is_err()) {
        let pattern = cli.regex.as_deref().unwrap_or_default();
        return Err(format!("invalid regex {pattern:?}"));
    }
    Ok(())
}

fn build_filter(cli: &Cli) -> Result<Filter, String> {
    let min_severity = if cli.errors {
        Severity::Error
    } else if cli.warnings {
        Severity::Warn
    } else {
        cli.min_severity.map_or(Severity::Unknown, Into::into)
    };
    let regex = cli
        .regex
        .as_deref()
        .map(Regex::new)
        .transpose()
        .map_err(|error| format!("invalid regex: {error}"))?;
    let now = Utc::now().timestamp();
    let since = cli.since.as_deref().map(|value| parse_time_bound(value, now)).transpose()?;
    let until = cli.until.as_deref().map(|value| parse_time_bound(value, now)).transpose()?;
    if let (Some(since), Some(until)) = (since, until) {
        if since > until {
            return Err("--since must not be later than --until".to_owned());
        }
    }
    Ok(Filter {
        min_severity,
        grep: cli.grep.clone(),
        regex,
        statuses: cli.status.iter().copied().collect(),
        since,
        until,
    })
}

pub fn parse_duration(input: &str) -> Result<Duration, String> {
    let normalized = input.trim().to_ascii_lowercase();
    let split = normalized.find(|character: char| !character.is_ascii_digit()).unwrap_or(normalized.len());
    let (number, unit) = normalized.split_at(split);
    if number.is_empty() {
        return Err(format!("invalid duration {input:?}; use values such as 250ms, 1s, or 2h"));
    }
    let value: u128 = number.parse().map_err(|_| format!("invalid duration {input:?}"))?;
    let multiplier: u128 = match unit {
        "ms" => 1_000_000,
        "s" => 1_000_000_000,
        "m" => 60 * 1_000_000_000,
        "h" => 60 * 60 * 1_000_000_000,
        "d" => 24 * 60 * 60 * 1_000_000_000,
        _ => return Err(format!("unknown duration unit in {input:?}; use ms, s, m, h, or d")),
    };
    let nanos = value
        .checked_mul(multiplier)
        .and_then(|nanos| u64::try_from(nanos).ok())
        .ok_or_else(|| format!("duration {input:?} is too large"))?;
    Ok(Duration::from_nanos(nanos))
}

fn parse_positive_usize(input: &str) -> Result<usize, String> {
    let value: usize = input.parse().map_err(|_| format!("expected a positive integer, got {input:?}"))?;
    if value == 0 {
        return Err("value must be greater than zero".to_owned());
    }
    Ok(value)
}

fn parse_time_bound(input: &str, now: i64) -> Result<i64, String> {
    let normalized = input.trim().to_ascii_lowercase();
    let split = normalized.find(|character: char| !character.is_ascii_digit()).unwrap_or(normalized.len());
    let (number, unit) = normalized.split_at(split);
    if !number.is_empty() && !unit.is_empty() && ["ms", "s", "m", "h", "d"].contains(&unit) {
        let duration = parse_duration(input)?;
        let seconds = i64::try_from(duration.as_secs()).map_err(|_| "duration is too large".to_owned())?;
        return now.checked_sub(seconds).ok_or_else(|| "time bound is too old".to_owned());
    }
    let timestamp = DateTime::parse_from_rfc3339(input)
        .map_err(|_| format!("invalid time {input:?}; use RFC 3339 or a duration such as 2h"))?;
    Ok(timestamp.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_durations_without_float_rounding() {
        assert_eq!(parse_duration("250ms").expect("duration").as_millis(), 250);
        assert_eq!(parse_duration("2h").expect("duration").as_secs(), 7200);
    }

    #[test]
    fn rejects_invalid_duration_units() {
        assert!(parse_duration("2w").is_err());
    }

    #[test]
    fn parses_rfc3339_bounds() {
        let expected = DateTime::parse_from_rfc3339("2026-08-14T00:00:00Z").expect("timestamp").timestamp();
        assert_eq!(parse_time_bound("2026-08-14T00:00:00Z", 0).expect("timestamp"), expected);
    }
}
