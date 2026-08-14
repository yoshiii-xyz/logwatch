use std::sync::OnceLock;

use chrono::{DateTime, NaiveDateTime};
use regex::Regex;
use serde_json::Value;

use crate::cli::InputFormat;
use crate::model::{Event, HttpEvent, ParserKind, Severity, Timestamp};

#[derive(Clone, Copy, Debug)]
pub struct ParseWarning {
    pub code: &'static str,
    pub message: &'static str,
    pub malformed: bool,
}

#[derive(Debug)]
pub struct ParseOutcome {
    pub event: Option<Event>,
    pub parser: ParserKind,
    pub warning: Option<ParseWarning>,
}

pub fn parse_line(line: &str, format: InputFormat) -> ParseOutcome {
    if line.trim().is_empty() {
        return ParseOutcome { event: None, parser: ParserKind::Plain, warning: None };
    }

    match format {
        InputFormat::Auto => parse_auto(line),
        InputFormat::Plain => parse_plain(line, ParserKind::Plain),
        InputFormat::Jsonl => parse_json(line),
        InputFormat::Nginx => parse_access(line),
        InputFormat::Syslog => parse_syslog(line),
    }
}

fn parse_auto(line: &str) -> ParseOutcome {
    let trimmed = line.trim_start();
    if trimmed.starts_with('{') {
        return parse_json(line);
    }
    if access_regex().is_match(line) {
        return parse_access(line);
    }
    if syslog_regex().is_match(line) {
        return parse_syslog(line);
    }
    parse_plain(line, ParserKind::Plain)
}

fn parse_plain(line: &str, parser: ParserKind) -> ParseOutcome {
    let (timestamp, span, timestamp_failed) = extract_timestamp(line);
    let severity = extract_severity(line).unwrap_or(Severity::Unknown);
    let message = clean_plain_message(line, span);
    let warning = timestamp_failed.then_some(ParseWarning {
        code: "invalid_timestamp",
        message: "a timestamp-like prefix could not be parsed",
        malformed: false,
    });

    ParseOutcome { event: Some(Event { timestamp, severity, message, parser, http: None }), parser, warning }
}

fn parse_json(line: &str) -> ParseOutcome {
    let value = match serde_json::from_str::<Value>(line) {
        Ok(value) => value,
        Err(_) => {
            let mut fallback = parse_plain(line, ParserKind::JsonLines);
            fallback.parser = ParserKind::JsonLines;
            fallback.warning = Some(ParseWarning {
                code: "invalid_json",
                message: "a JSON Lines record could not be decoded; the line was retained as text",
                malformed: true,
            });
            return fallback;
        }
    };

    let Some(object) = value.as_object() else {
        let mut fallback = parse_plain(line, ParserKind::JsonLines);
        fallback.parser = ParserKind::JsonLines;
        fallback.warning = Some(ParseWarning {
            code: "json_not_object",
            message: "a JSON Lines record was valid JSON but not an object; the line was retained as text",
            malformed: true,
        });
        return fallback;
    };

    let timestamp = first_value(object, &["timestamp", "time", "ts", "@timestamp", "datetime", "date"])
        .and_then(json_timestamp);
    let severity = first_value(object, &["level", "severity", "log.level"])
        .and_then(value_as_string)
        .and_then(|value| Severity::from_token(&value))
        .or_else(|| {
            first_value(object, &["message", "msg", "error"])
                .and_then(value_as_string)
                .and_then(|value| extract_severity(&value))
        })
        .unwrap_or(Severity::Unknown);
    let message = first_value(object, &["message", "msg", "error"])
        .and_then(value_as_string)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| line.trim().to_owned());

    ParseOutcome {
        event: Some(Event {
            timestamp,
            severity,
            message,
            parser: ParserKind::JsonLines,
            http: json_http(object),
        }),
        parser: ParserKind::JsonLines,
        warning: None,
    }
}

fn parse_access(line: &str) -> ParseOutcome {
    let Some(captures) = access_regex().captures(line) else {
        let mut fallback = parse_plain(line, ParserKind::Nginx);
        fallback.parser = ParserKind::Nginx;
        fallback.warning = Some(ParseWarning {
            code: "invalid_access_log",
            message: "the line did not match the selected access-log format; it was retained as text",
            malformed: true,
        });
        return fallback;
    };

    let request = captures.name("request").map_or("", |value| value.as_str());
    let (method, path) = parse_request_target(request);
    let status = captures.name("status").and_then(|value| value.as_str().parse::<u16>().ok());
    let response_bytes = captures
        .name("size")
        .and_then(|value| (value.as_str() != "-").then(|| value.as_str().parse::<u64>().ok()))
        .flatten();
    let duration_ms = captures.name("duration").and_then(|value| parse_duration_token(value.as_str(), true));
    let timestamp = captures.name("time").and_then(|value| parse_access_timestamp(value.as_str()));
    let severity = status.map_or(Severity::Info, severity_for_status);
    let message = match (&method, &path, status) {
        (Some(method), Some(path), Some(status)) => format!("{method} {path} -> {status}"),
        _ => request.to_owned(),
    };

    ParseOutcome {
        event: Some(Event {
            timestamp,
            severity,
            message,
            parser: ParserKind::Nginx,
            http: Some(HttpEvent { method, path, status, response_bytes, duration_ms }),
        }),
        parser: ParserKind::Nginx,
        warning: None,
    }
}

fn parse_syslog(line: &str) -> ParseOutcome {
    let Some(captures) = syslog_regex().captures(line) else {
        let mut fallback = parse_plain(line, ParserKind::Syslog);
        fallback.parser = ParserKind::Syslog;
        fallback.warning = Some(ParseWarning {
            code: "invalid_syslog",
            message: "the line did not match the selected syslog-like format; it was retained as text",
            malformed: true,
        });
        return fallback;
    };

    let message = captures
        .name("message")
        .map_or_else(|| line.trim().to_owned(), |value| value.as_str().trim().to_owned());
    let severity = captures
        .name("pri")
        .and_then(|value| value.as_str().parse::<u16>().ok())
        .map(|priority| severity_for_syslog_priority(priority & 7))
        .or_else(|| extract_severity(&message))
        .unwrap_or(Severity::Unknown);
    let timestamp =
        captures.name("time").map(|value| Timestamp::Partial { display: value.as_str().to_owned() });

    ParseOutcome {
        event: Some(Event { timestamp, severity, message, parser: ParserKind::Syslog, http: None }),
        parser: ParserKind::Syslog,
        warning: None,
    }
}

fn extract_timestamp(line: &str) -> (Option<Timestamp>, Option<(usize, usize)>, bool) {
    let prefix = scan_prefix(line);
    if let Some(captures) = zoned_space_regex().captures(prefix) {
        let value = captures.name("value").expect("timestamp capture exists");
        if let Some(timestamp) = parse_timestamp_value(value.as_str()) {
            return (Some(timestamp), Some((value.start(), value.end())), false);
        }
        return (None, Some((value.start(), value.end())), true);
    }
    if let Some(captures) = iso_regex().captures(prefix) {
        let value = captures.name("value").expect("timestamp capture exists");
        if let Some(timestamp) = parse_timestamp_value(value.as_str()) {
            return (Some(timestamp), Some((value.start(), value.end())), false);
        }
        return (None, Some((value.start(), value.end())), true);
    }
    (None, None, false)
}

fn clean_plain_message(line: &str, timestamp_span: Option<(usize, usize)>) -> String {
    let mut message = timestamp_span.map_or(line, |(_, end)| &line[end..]).trim_start();
    if message.starts_with(']') {
        message = message[1..].trim_start();
    }
    message = message.trim_start_matches([':', '|', '-']).trim_start();

    if let Some(captures) = severity_prefix_regex().captures(message) {
        message = &message[captures.get(0).expect("severity prefix capture exists").end()..];
    }
    let message = message.trim();
    if message.is_empty() { line.trim().to_owned() } else { message.to_owned() }
}

fn extract_severity(line: &str) -> Option<Severity> {
    let mut candidate = line;
    if let Some((_, end)) = extract_timestamp(line).1 {
        candidate = &line[end..];
    }
    candidate = candidate.trim_start().trim_start_matches([']', ':', '|', '-']).trim_start();
    let prefix = scan_prefix(candidate);
    if let Some(captures) = severity_prefix_regex().captures(prefix) {
        let level =
            captures.name("bracket").or_else(|| captures.name("bare")).expect("severity capture exists");
        return Severity::from_token(level.as_str());
    }
    severity_field_regex()
        .captures(prefix)
        .and_then(|captures| captures.name("level"))
        .and_then(|level| Severity::from_token(level.as_str()))
}

fn parse_timestamp_value(value: &str) -> Option<Timestamp> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    let normalized = value.replace(',', ".");
    if let Some(timestamp) = parse_zoned(&normalized) {
        return Some(Timestamp::Zoned { seconds: timestamp.timestamp(), display: value.to_owned() });
    }
    parse_wall(&normalized).map(|timestamp| Timestamp::Wall {
        seconds: timestamp.and_utc().timestamp(),
        display: value.to_owned(),
    })
}

fn parse_zoned(value: &str) -> Option<DateTime<chrono::FixedOffset>> {
    let rfc3339 = value.replacen(' ', "T", 1);
    DateTime::parse_from_rfc3339(&rfc3339)
        .ok()
        .or_else(|| DateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S %z").ok())
        .or_else(|| DateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f %z").ok())
}

fn parse_wall(value: &str) -> Option<NaiveDateTime> {
    NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f")
        .ok()
        .or_else(|| NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S").ok())
        .or_else(|| NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f").ok())
        .or_else(|| NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S").ok())
}

fn parse_access_timestamp(value: &str) -> Option<Timestamp> {
    DateTime::parse_from_str(value, "%d/%b/%Y:%H:%M:%S %z")
        .ok()
        .map(|timestamp| Timestamp::Zoned { seconds: timestamp.timestamp(), display: value.to_owned() })
}

fn json_timestamp(value: &Value) -> Option<Timestamp> {
    if let Some(value) = value.as_str() {
        return parse_timestamp_value(value);
    }
    let number = value.as_i64().or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))?;
    let seconds = if number.unsigned_abs() > 100_000_000_000 { number / 1_000 } else { number };
    Some(Timestamp::Zoned { seconds, display: number.to_string() })
}

fn json_http(object: &serde_json::Map<String, Value>) -> Option<HttpEvent> {
    let nested = object
        .get("http")
        .and_then(Value::as_object)
        .or_else(|| object.get("request").and_then(Value::as_object));
    let get = |keys: &[&str]| -> Option<&Value> {
        first_value(object, keys).or_else(|| nested.and_then(|nested| first_value(nested, keys)))
    };

    let method = get(&["method", "http_method"]).and_then(value_as_string);
    let path = get(&["path", "uri", "url", "request_uri"])
        .and_then(value_as_string)
        .map(|value| normalize_path(&value));
    let status = get(&["status", "status_code", "statusCode", "http.status_code"]).and_then(parse_u16_value);
    let response_bytes =
        get(&["response_bytes", "response_size", "bytes", "body_bytes"]).and_then(parse_u64_value);
    let duration_ms = get(&["duration_ms", "response_time_ms", "latency_ms"])
        .and_then(parse_f64_value)
        .or_else(|| get(&["duration_seconds", "duration_s"]).and_then(parse_f64_value).map(|v| v * 1000.0));

    (method.is_some() || path.is_some() || status.is_some() || duration_ms.is_some()).then_some(HttpEvent {
        method,
        path,
        status,
        response_bytes,
        duration_ms,
    })
}

fn parse_request_target(request: &str) -> (Option<String>, Option<String>) {
    let mut parts = request.split_whitespace();
    let method = parts.next().map(str::to_owned);
    let path = parts.next().map(normalize_path);
    (method, path)
}

pub fn normalize_path(path: &str) -> String {
    path.split('?').next().unwrap_or(path).to_owned()
}

fn parse_duration_token(value: &str, seconds_without_unit: bool) -> Option<f64> {
    let value = value.trim();
    let lower = value.to_ascii_lowercase();
    if let Some(number) = lower.strip_suffix("ms") {
        return number.trim().parse().ok();
    }
    if let Some(number) = lower.strip_suffix("us") {
        return number.trim().parse::<f64>().ok().map(|value| value / 1000.0);
    }
    if let Some(number) = lower.strip_suffix('s') {
        return number.trim().parse::<f64>().ok().map(|value| value * 1000.0);
    }
    lower.parse::<f64>().ok().map(|value| if seconds_without_unit { value * 1000.0 } else { value })
}

fn parse_u16_value(value: &Value) -> Option<u16> {
    value
        .as_u64()
        .and_then(|value| u16::try_from(value).ok())
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn parse_u64_value(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn parse_f64_value(value: &Value) -> Option<f64> {
    value.as_f64().or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn first_value<'a>(object: &'a serde_json::Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}

fn severity_for_status(status: u16) -> Severity {
    match status {
        500..=599 => Severity::Error,
        400..=499 => Severity::Warn,
        _ => Severity::Info,
    }
}

fn severity_for_syslog_priority(level: u16) -> Severity {
    match level {
        0..=2 => Severity::Critical,
        3 => Severity::Error,
        4 => Severity::Warn,
        5 => Severity::Notice,
        6 => Severity::Info,
        _ => Severity::Debug,
    }
}

fn scan_prefix(line: &str) -> &str {
    line.char_indices().nth(192).map_or(line, |(index, _)| &line[..index])
}

fn access_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"^(?P<remote>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"[^"]*"\s+"[^"]*")?(?:\s+(?P<duration>\S+))?\s*$"#,
        )
        .expect("access log regex is valid")
    })
}

fn syslog_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r"^\s*(?:<(?P<pri>\d{1,3})>)?(?P<time>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+(?P<tag>[A-Za-z0-9_.:/-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$",
        )
        .expect("syslog regex is valid")
    })
}

fn iso_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?P<value>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
            .expect("ISO timestamp regex is valid")
    })
}

fn zoned_space_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?P<value>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\s+[+-]\d{4})")
            .expect("space-separated timestamp regex is valid")
    })
}

fn severity_prefix_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r"(?i)^\s*(?:\[(?P<bracket>trace|debug|info|notice|warn(?:ing)?|error|err|critical|crit|fatal|panic)\]|(?P<bare>trace|debug|info|notice|warn(?:ing)?|error|err|critical|crit|fatal|panic))(?:\s*[:|\-])?\s*",
        )
        .expect("severity prefix regex is valid")
    })
}

fn severity_field_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r"(?i)(?:^|[\s,])(?:level|severity|log\.level)\s*[:=]\s*(?P<level>trace|debug|info|notice|warn(?:ing)?|error|err|critical|crit|fatal|panic)(?:$|[\s,\]])",
        )
        .expect("severity field regex is valid")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_timestamp_and_severity() {
        let result = parse_line("2026-08-14T12:30:00Z [ERROR] failed request 42", InputFormat::Auto);
        let event = result.event.expect("event");
        assert_eq!(event.severity, Severity::Error);
        assert_eq!(event.message, "failed request 42");
        assert!(matches!(event.timestamp, Some(Timestamp::Zoned { .. })));
    }

    #[test]
    fn parses_json_lines_and_http_fields() {
        let result = parse_line(
            r#"{"timestamp":"2026-08-14T12:30:00Z","level":"error","message":"request failed","method":"GET","path":"/users/12?token=secret","status":500,"duration_ms":42}"#,
            InputFormat::Jsonl,
        );
        let event = result.event.expect("event");
        assert_eq!(event.severity, Severity::Error);
        let http = event.http.expect("http fields");
        assert_eq!(http.path.as_deref(), Some("/users/12"));
        assert_eq!(http.status, Some(500));
    }

    #[test]
    fn parses_access_log() {
        let result = parse_line(
            r#"127.0.0.1 - - [14/Aug/2026:12:30:00 +0000] "GET /api/items/12?token=secret HTTP/1.1" 500 123 "-" "curl" 0.250"#,
            InputFormat::Auto,
        );
        let event = result.event.expect("event");
        assert_eq!(event.parser, ParserKind::Nginx);
        assert_eq!(event.severity, Severity::Error);
        assert_eq!(event.http.as_ref().and_then(|http| http.duration_ms), Some(250.0));
    }

    #[test]
    fn ordinary_words_are_not_severity_markers() {
        let result = parse_line("the error value was written to the file", InputFormat::Plain);
        let event = result.event.expect("event");
        assert_eq!(event.severity, Severity::Unknown);
    }

    #[test]
    fn parses_syslog_priority_without_inventing_a_year() {
        let result = parse_line("<131>Aug 14 12:30:00 host sshd[123]: failed login", InputFormat::Auto);
        let event = result.event.expect("event");
        assert_eq!(event.parser, ParserKind::Syslog);
        assert_eq!(event.severity, Severity::Error);
        assert!(matches!(event.timestamp, Some(Timestamp::Partial { .. })));
    }

    #[test]
    fn invalid_json_is_retained_as_a_warning_and_event() {
        let result = parse_line("{not-json", InputFormat::Jsonl);
        assert!(result.event.is_some());
        assert_eq!(result.warning.expect("warning").code, "invalid_json");
    }
}
