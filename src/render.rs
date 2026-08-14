use std::fmt::Write as _;

use crate::VERSION;
use crate::model::{PatternReport, Report};

pub fn render_human(report: &Report) -> String {
    let mut output = String::new();
    writeln!(output, "logwatch {VERSION}").expect("String cannot fail");
    writeln!(output).expect("String cannot fail");
    writeln!(output, "INPUT").expect("String cannot fail");
    writeln!(output, "  sources                 {}", report.inputs.len()).expect("String cannot fail");
    writeln!(output, "  bytes read              {}", format_bytes(report.statistics.bytes_read))
        .expect("String cannot fail");
    writeln!(output, "  lines read              {}", report.statistics.lines_read)
        .expect("String cannot fail");
    writeln!(
        output,
        "  records                 {} parsed, {} matched, {} filtered",
        report.statistics.records_parsed,
        report.statistics.records_matched,
        report.statistics.records_filtered
    )
    .expect("String cannot fail");
    writeln!(
        output,
        "  malformed               {} records, {} truncated lines",
        report.statistics.malformed_records, report.statistics.truncated_lines
    )
    .expect("String cannot fail");
    writeln!(output, "  invalid UTF-8           {} lines", report.statistics.invalid_utf8_lines)
        .expect("String cannot fail");

    writeln!(output).expect("String cannot fail");
    writeln!(output, "TIME").expect("String cannot fail");
    match (&report.time.start, &report.time.end) {
        (Some(start), Some(end)) => {
            writeln!(
                output,
                "  range                   {} to {}",
                sanitize_terminal(start),
                sanitize_terminal(end)
            )
            .expect("String cannot fail");
        }
        _ => writeln!(output, "  range                   unavailable").expect("String cannot fail"),
    }
    writeln!(
        output,
        "  timestamps              {} known, {} with timezone",
        report.time.records_with_timestamps, report.time.records_with_timezone
    )
    .expect("String cannot fail");
    if let Some(series) = &report.time.zoned {
        render_time_series(&mut output, "  zoned", series);
    }
    if let Some(series) = &report.time.wall_clock {
        render_time_series(&mut output, "  wall-clock", series);
    }

    writeln!(output).expect("String cannot fail");
    writeln!(output, "SEVERITY").expect("String cannot fail");
    for (level, count) in &report.severity {
        writeln!(output, "  {level:<22} {count}").expect("String cannot fail");
    }

    writeln!(output).expect("String cannot fail");
    writeln!(output, "PARSERS").expect("String cannot fail");
    if report.parsers.is_empty() {
        writeln!(output, "  none").expect("String cannot fail");
    } else {
        for (parser, count) in &report.parsers {
            writeln!(output, "  {parser:<22} {count}").expect("String cannot fail");
        }
    }

    writeln!(output).expect("String cannot fail");
    writeln!(output, "TOP MESSAGE PATTERNS").expect("String cannot fail");
    render_patterns(&mut output, &report.patterns);

    if let Some(http) = &report.http {
        writeln!(output).expect("String cannot fail");
        writeln!(output, "HTTP").expect("String cannot fail");
        writeln!(output, "  requests                {}", http.requests).expect("String cannot fail");
        writeln!(output, "  error responses         {}", http.error_responses).expect("String cannot fail");
        if !http.status_codes.is_empty() {
            writeln!(output, "  status codes").expect("String cannot fail");
            for (status, count) in &http.status_codes {
                writeln!(output, "    {status:<20} {count}").expect("String cannot fail");
            }
        }
        if !http.methods.is_empty() {
            writeln!(output, "  methods").expect("String cannot fail");
            for (method, count) in &http.methods {
                writeln!(output, "    {:<20} {}", sanitize_terminal(method), count)
                    .expect("String cannot fail");
            }
            if http.method_evictions > 0 {
                writeln!(
                    output,
                    "    note: {} additional method values were not retained",
                    http.method_evictions
                )
                .expect("String cannot fail");
            }
        }
        if let Some(average) = http.average_duration_ms {
            writeln!(output, "  average duration        {:.2} ms", average).expect("String cannot fail");
        }
        if let Some(maximum) = http.max_duration_ms {
            writeln!(output, "  maximum duration        {:.2} ms", maximum).expect("String cannot fail");
        }
        if let Some(slowest) = &http.slowest {
            writeln!(output, "  slowest request         {:.2} ms", slowest.duration_ms)
                .expect("String cannot fail");
            if let (Some(method), Some(path)) = (&slowest.method, &slowest.path) {
                writeln!(output, "    {} {}", sanitize_terminal(method), sanitize_terminal(path))
                    .expect("String cannot fail");
            }
        }
        writeln!(output, "  top endpoints").expect("String cannot fail");
        render_patterns(&mut output, &http.endpoints);
    }

    if !report.warnings.is_empty() {
        writeln!(output).expect("String cannot fail");
        writeln!(output, "WARNINGS").expect("String cannot fail");
        for warning in &report.warnings {
            writeln!(
                output,
                "  {:<28} {} ({})",
                warning.code,
                sanitize_terminal(&warning.message),
                warning.count
            )
            .expect("String cannot fail");
        }
    }

    output
}

fn render_time_series(output: &mut String, label: &str, series: &crate::model::TimeSeriesReport) {
    writeln!(
        output,
        "  {label:<22} interval {} seconds, {} buckets{}",
        series.interval_seconds,
        series.buckets.len(),
        if series.approximate { ", adaptively rebucketed" } else { "" }
    )
    .expect("String cannot fail");
    for bucket in series.buckets.iter().take(12) {
        writeln!(
            output,
            "    {:<20} {} events, {} errors",
            sanitize_terminal(&bucket.start),
            bucket.events,
            bucket.errors
        )
        .expect("String cannot fail");
    }
    if series.buckets.len() > 12 {
        writeln!(output, "    ... {} more buckets", series.buckets.len() - 12).expect("String cannot fail");
    }
}

fn render_patterns(output: &mut String, report: &PatternReport) {
    if report.entries.is_empty() {
        writeln!(output, "  none").expect("String cannot fail");
        return;
    }
    for entry in &report.entries {
        writeln!(output, "  {:>8}  {}", entry.count, sanitize_terminal(&entry.pattern))
            .expect("String cannot fail");
    }
    if report.approximate {
        writeln!(
            output,
            "  note: bounded aggregation evicted {} entries; counts are approximate",
            report.evictions
        )
        .expect("String cannot fail");
    }
}

pub fn sanitize_terminal(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\t' => sanitized.push_str("\\t"),
            '\r' => sanitized.push_str("\\r"),
            '\n' => sanitized.push_str("\\n"),
            character if character.is_control() => {
                write!(sanitized, "\\u{{{:04x}}}", character as u32).expect("String cannot fail");
            }
            character => sanitized.push(character),
        }
    }
    sanitized
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut index = 0;
    while value >= 1024.0 && index < UNITS.len() - 1 {
        value /= 1024.0;
        index += 1;
    }
    if index == 0 { format!("{bytes} B") } else { format!("{value:.1} {}", UNITS[index]) }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::model::{PatternEntryReport, PatternReport, Report, StatisticsReport, TimeReport};

    #[test]
    fn terminal_control_sequences_are_escaped() {
        assert_eq!(sanitize_terminal("ok\u{1b}[31mred"), "ok\\u{001b}[31mred");
    }

    #[test]
    fn human_report_contains_safe_patterns() {
        let report = Report {
            schema_version: 1,
            version: "0.1.0".to_owned(),
            inputs: Vec::new(),
            statistics: StatisticsReport::default(),
            time: TimeReport::default(),
            severity: BTreeMap::new(),
            patterns: PatternReport {
                entries: vec![PatternEntryReport {
                    pattern: "bad\u{1b}[2J".to_owned(),
                    count: 1,
                    error_estimate: 0,
                }],
                capacity: 1,
                evictions: 0,
                approximate: false,
            },
            http: None,
            parsers: BTreeMap::new(),
            warnings: Vec::new(),
        };
        let output = render_human(&report);
        assert!(output.contains("\\u{001b}"));
        assert!(!output.contains('\u{1b}'));
    }
}
