use std::collections::BTreeMap;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Trace,
    Debug,
    Info,
    Notice,
    Warn,
    Error,
    Critical,
    Fatal,
    Unknown,
}

impl Severity {
    pub const ALL: [Self; 9] = [
        Self::Trace,
        Self::Debug,
        Self::Info,
        Self::Notice,
        Self::Warn,
        Self::Error,
        Self::Critical,
        Self::Fatal,
        Self::Unknown,
    ];

    pub fn from_token(token: &str) -> Option<Self> {
        match token.to_ascii_lowercase().as_str() {
            "trace" => Some(Self::Trace),
            "debug" => Some(Self::Debug),
            "info" | "information" => Some(Self::Info),
            "notice" => Some(Self::Notice),
            "warn" | "warning" => Some(Self::Warn),
            "error" | "err" => Some(Self::Error),
            "critical" | "crit" | "emerg" | "emergency" | "alert" => Some(Self::Critical),
            "fatal" | "panic" => Some(Self::Fatal),
            _ => None,
        }
    }

    pub const fn rank(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Trace => 1,
            Self::Debug => 2,
            Self::Info => 3,
            Self::Notice => 4,
            Self::Warn => 5,
            Self::Error => 6,
            Self::Critical => 7,
            Self::Fatal => 8,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Critical => "critical",
            Self::Fatal => "fatal",
            Self::Unknown => "unknown",
        }
    }

    pub const fn is_error(self) -> bool {
        matches!(self, Self::Error | Self::Critical | Self::Fatal)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ParserKind {
    Plain,
    JsonLines,
    Nginx,
    Syslog,
}

impl ParserKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::JsonLines => "jsonl",
            Self::Nginx => "nginx",
            Self::Syslog => "syslog",
        }
    }
}

#[derive(Clone, Debug)]
pub enum Timestamp {
    Zoned { seconds: i64, display: String },
    Wall { seconds: i64, display: String },
    Partial { display: String },
}

impl Timestamp {
    pub fn display(&self) -> &str {
        match self {
            Self::Zoned { display, .. } | Self::Wall { display, .. } | Self::Partial { display } => display,
        }
    }

    pub const fn zoned_seconds(&self) -> Option<i64> {
        match self {
            Self::Zoned { seconds, .. } => Some(*seconds),
            Self::Wall { .. } | Self::Partial { .. } => None,
        }
    }

    pub const fn wall_seconds(&self) -> Option<i64> {
        match self {
            Self::Zoned { seconds, .. } | Self::Wall { seconds, .. } => Some(*seconds),
            Self::Partial { .. } => None,
        }
    }

    pub const fn timezone_known(&self) -> bool {
        matches!(self, Self::Zoned { .. })
    }
}

#[derive(Clone, Debug)]
pub struct HttpEvent {
    pub method: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
    pub response_bytes: Option<u64>,
    pub duration_ms: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct Event {
    pub timestamp: Option<Timestamp>,
    pub severity: Severity,
    pub message: String,
    pub parser: ParserKind,
    pub http: Option<HttpEvent>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatisticsReport {
    pub bytes_read: u64,
    pub lines_read: u64,
    pub records_parsed: u64,
    pub records_matched: u64,
    pub records_filtered: u64,
    pub malformed_records: u64,
    pub invalid_utf8_lines: u64,
    pub truncated_lines: u64,
    pub records_with_timestamps: u64,
    pub records_with_timezone: u64,
    pub records_without_timezone_for_filter: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InputReport {
    pub path: String,
    pub status: String,
    pub error: Option<String>,
    pub statistics: StatisticsReport,
    pub parsers: BTreeMap<String, u64>,
    pub warnings: Vec<WarningReport>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WarningReport {
    pub code: String,
    pub message: String,
    pub count: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PatternReport {
    pub entries: Vec<PatternEntryReport>,
    pub capacity: usize,
    pub evictions: u64,
    pub approximate: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PatternEntryReport {
    pub pattern: String,
    pub count: u64,
    pub error_estimate: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpReport {
    pub requests: u64,
    pub error_responses: u64,
    pub status_codes: BTreeMap<String, u64>,
    pub methods: BTreeMap<String, u64>,
    pub method_evictions: u64,
    pub endpoints: PatternReport,
    pub duration_count: u64,
    pub average_duration_ms: Option<f64>,
    pub max_duration_ms: Option<f64>,
    pub slowest: Option<SlowRequestReport>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlowRequestReport {
    pub duration_ms: f64,
    pub method: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeReport {
    pub start: Option<String>,
    pub end: Option<String>,
    pub records_with_timestamps: u64,
    pub records_with_timezone: u64,
    pub zoned: Option<TimeSeriesReport>,
    pub wall_clock: Option<TimeSeriesReport>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeSeriesReport {
    pub axis: String,
    pub interval_seconds: u64,
    pub buckets: Vec<TimeBucketReport>,
    pub approximate: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeBucketReport {
    pub start: String,
    pub events: u64,
    pub errors: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub schema_version: u32,
    pub version: String,
    pub inputs: Vec<InputReport>,
    pub statistics: StatisticsReport,
    pub time: TimeReport,
    pub severity: BTreeMap<String, u64>,
    pub patterns: PatternReport,
    pub http: Option<HttpReport>,
    pub parsers: BTreeMap<String, u64>,
    pub warnings: Vec<WarningReport>,
}

pub fn format_zoned_seconds(seconds: i64) -> String {
    DateTime::<Utc>::from_timestamp(seconds, 0)
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_else(|| seconds.to_string())
}

pub fn format_wall_seconds(seconds: i64) -> String {
    DateTime::<Utc>::from_timestamp(seconds, 0)
        .map(|timestamp| timestamp.naive_utc().format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| seconds.to_string())
}
