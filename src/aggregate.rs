use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::OnceLock;

use regex::Regex;

use crate::VERSION;
use crate::model::{
    Event, HttpReport, InputReport, ParserKind, PatternEntryReport, PatternReport, Report, SCHEMA_VERSION,
    Severity, SlowRequestReport, StatisticsReport, TimeBucketReport, TimeReport, TimeSeriesReport, Timestamp,
    WarningReport, format_wall_seconds, format_zoned_seconds,
};
use crate::parser::ParseWarning;

#[derive(Clone, Debug)]
pub struct Filter {
    pub min_severity: Severity,
    pub grep: Option<String>,
    pub regex: Option<Regex>,
    pub statuses: BTreeSet<u16>,
    pub since: Option<i64>,
    pub until: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilterResult {
    pub accepted: bool,
    pub missing_timezone: bool,
}

impl Filter {
    pub fn matches(&self, event: &Event) -> FilterResult {
        if event.severity.rank() < self.min_severity.rank() {
            return FilterResult { accepted: false, missing_timezone: false };
        }
        if let Some(grep) = &self.grep {
            if !event.message.contains(grep) {
                return FilterResult { accepted: false, missing_timezone: false };
            }
        }
        if let Some(regex) = &self.regex {
            if !regex.is_match(&event.message) {
                return FilterResult { accepted: false, missing_timezone: false };
            }
        }
        if !self.statuses.is_empty()
            && !event
                .http
                .as_ref()
                .and_then(|http| http.status)
                .is_some_and(|status| self.statuses.contains(&status))
        {
            return FilterResult { accepted: false, missing_timezone: false };
        }

        if self.since.is_some() || self.until.is_some() {
            let Some(seconds) = event.timestamp.as_ref().and_then(Timestamp::zoned_seconds) else {
                return FilterResult { accepted: false, missing_timezone: true };
            };
            if self.since.is_some_and(|since| seconds < since)
                || self.until.is_some_and(|until| seconds > until)
            {
                return FilterResult { accepted: false, missing_timezone: false };
            }
        }

        FilterResult { accepted: true, missing_timezone: false }
    }
}

#[derive(Clone, Debug)]
pub struct AnalyzerConfig {
    pub filter: Filter,
    pub max_patterns: usize,
    pub max_time_buckets: usize,
    pub top: usize,
}

#[derive(Debug)]
pub struct Analyzer {
    config: AnalyzerConfig,
    statistics: Counters,
    parsers: BTreeMap<String, u64>,
    warnings: WarningTable,
    severity: BTreeMap<Severity, u64>,
    patterns: SpaceSavingTable,
    time: TimeAccumulator,
    http: HttpAccumulator,
    inputs: Vec<InputState>,
}

impl Analyzer {
    pub fn new(config: AnalyzerConfig) -> Self {
        let max_patterns = config.max_patterns.max(1);
        let max_time_buckets = config.max_time_buckets.max(1);
        Self {
            statistics: Counters::default(),
            parsers: BTreeMap::new(),
            warnings: WarningTable::new(64),
            severity: BTreeMap::new(),
            patterns: SpaceSavingTable::new(max_patterns),
            time: TimeAccumulator::new(max_time_buckets),
            http: HttpAccumulator::new(max_patterns),
            inputs: Vec::new(),
            config,
        }
    }

    pub fn begin_input(&mut self, path: String) -> usize {
        let index = self.inputs.len();
        self.inputs.push(InputState::new(path));
        index
    }

    pub fn record_line(&mut self, input: usize, bytes: usize, invalid_utf8: bool, truncated: bool) {
        let bytes = bytes as u64;
        self.statistics.bytes_read = self.statistics.bytes_read.saturating_add(bytes);
        self.statistics.lines_read = self.statistics.lines_read.saturating_add(1);
        if invalid_utf8 {
            self.statistics.invalid_utf8_lines = self.statistics.invalid_utf8_lines.saturating_add(1);
        }
        if truncated {
            self.statistics.truncated_lines = self.statistics.truncated_lines.saturating_add(1);
        }

        {
            let counters = &mut self.inputs[input].statistics;
            counters.bytes_read = counters.bytes_read.saturating_add(bytes);
            counters.lines_read = counters.lines_read.saturating_add(1);
            if invalid_utf8 {
                counters.invalid_utf8_lines = counters.invalid_utf8_lines.saturating_add(1);
            }
            if truncated {
                counters.truncated_lines = counters.truncated_lines.saturating_add(1);
            }
        }
        if invalid_utf8 {
            self.record_warning(
                input,
                ParseWarning {
                    code: "invalid_utf8",
                    message: "invalid UTF-8 was replaced with the Unicode replacement character",
                    malformed: false,
                },
            );
        }
        if truncated {
            self.record_warning(
                input,
                ParseWarning {
                    code: "line_truncated",
                    message: "a line exceeded --max-line-bytes and was skipped",
                    malformed: true,
                },
            );
        }
    }

    pub fn record_parser(&mut self, input: usize, parser: ParserKind) {
        increment(&mut self.parsers, parser.label().to_owned());
        increment(&mut self.inputs[input].parsers, parser.label().to_owned());
    }

    pub fn record_warning(&mut self, input: usize, warning: ParseWarning) {
        if warning.malformed {
            self.statistics.malformed_records = self.statistics.malformed_records.saturating_add(1);
            self.inputs[input].statistics.malformed_records =
                self.inputs[input].statistics.malformed_records.saturating_add(1);
        }
        self.warnings.add(warning.code, warning.message);
        self.inputs[input].warnings.add(warning.code, warning.message);
    }

    pub fn record_input_error(&mut self, input: usize, message: String) {
        self.inputs[input].status = "error".to_owned();
        self.inputs[input].error = Some(message.clone());
        self.warnings.add("input_error", &message);
    }

    pub fn record_event(&mut self, input: usize, event: Event) {
        self.statistics.records_parsed = self.statistics.records_parsed.saturating_add(1);
        self.inputs[input].statistics.records_parsed =
            self.inputs[input].statistics.records_parsed.saturating_add(1);

        let filter_result = self.config.filter.matches(&event);
        if !filter_result.accepted {
            self.statistics.records_filtered = self.statistics.records_filtered.saturating_add(1);
            self.inputs[input].statistics.records_filtered =
                self.inputs[input].statistics.records_filtered.saturating_add(1);
            if filter_result.missing_timezone {
                self.statistics.records_without_timezone_for_filter =
                    self.statistics.records_without_timezone_for_filter.saturating_add(1);
                self.inputs[input].statistics.records_without_timezone_for_filter =
                    self.inputs[input].statistics.records_without_timezone_for_filter.saturating_add(1);
                self.warnings.add(
                    "time_filter_missing_timezone",
                    "a record without a timezone was excluded by --since or --until",
                );
                self.inputs[input].warnings.add(
                    "time_filter_missing_timezone",
                    "a record without a timezone was excluded by --since or --until",
                );
            }
            return;
        }

        self.statistics.records_matched = self.statistics.records_matched.saturating_add(1);
        self.inputs[input].statistics.records_matched =
            self.inputs[input].statistics.records_matched.saturating_add(1);
        increment(&mut self.severity, event.severity);
        self.patterns.add(normalize_message(&event.message));
        if let Some(timestamp) = &event.timestamp {
            self.statistics.records_with_timestamps =
                self.statistics.records_with_timestamps.saturating_add(1);
            self.inputs[input].statistics.records_with_timestamps =
                self.inputs[input].statistics.records_with_timestamps.saturating_add(1);
            if timestamp.timezone_known() {
                self.statistics.records_with_timezone =
                    self.statistics.records_with_timezone.saturating_add(1);
                self.inputs[input].statistics.records_with_timezone =
                    self.inputs[input].statistics.records_with_timezone.saturating_add(1);
            }
            self.time.observe(timestamp, event.severity.is_error());
        }
        if let Some(http) = &event.http {
            self.http.observe(http);
        }
    }

    pub fn report(&self) -> Report {
        let mut severity = BTreeMap::new();
        for level in Severity::ALL {
            severity.insert(level.label().to_owned(), self.severity.get(&level).copied().unwrap_or(0));
        }
        Report {
            schema_version: SCHEMA_VERSION,
            version: VERSION.to_owned(),
            inputs: self.inputs.iter().map(InputState::report).collect(),
            statistics: self.statistics.report(),
            time: self.time.report(),
            severity,
            patterns: self.patterns.report(self.config.top),
            http: self.http.report(),
            parsers: self.parsers.clone(),
            warnings: self.warnings.reports(),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Counters {
    bytes_read: u64,
    lines_read: u64,
    records_parsed: u64,
    records_matched: u64,
    records_filtered: u64,
    malformed_records: u64,
    invalid_utf8_lines: u64,
    truncated_lines: u64,
    records_with_timestamps: u64,
    records_with_timezone: u64,
    records_without_timezone_for_filter: u64,
}

impl Counters {
    fn report(&self) -> StatisticsReport {
        StatisticsReport {
            bytes_read: self.bytes_read,
            lines_read: self.lines_read,
            records_parsed: self.records_parsed,
            records_matched: self.records_matched,
            records_filtered: self.records_filtered,
            malformed_records: self.malformed_records,
            invalid_utf8_lines: self.invalid_utf8_lines,
            truncated_lines: self.truncated_lines,
            records_with_timestamps: self.records_with_timestamps,
            records_with_timezone: self.records_with_timezone,
            records_without_timezone_for_filter: self.records_without_timezone_for_filter,
        }
    }
}

#[derive(Debug)]
struct InputState {
    path: String,
    status: String,
    error: Option<String>,
    statistics: Counters,
    parsers: BTreeMap<String, u64>,
    warnings: WarningTable,
}

impl InputState {
    fn new(path: String) -> Self {
        Self {
            path,
            status: "processed".to_owned(),
            error: None,
            statistics: Counters::default(),
            parsers: BTreeMap::new(),
            warnings: WarningTable::new(32),
        }
    }

    fn report(&self) -> InputReport {
        InputReport {
            path: self.path.clone(),
            status: self.status.clone(),
            error: self.error.clone(),
            statistics: self.statistics.report(),
            parsers: self.parsers.clone(),
            warnings: self.warnings.reports(),
        }
    }
}

#[derive(Debug)]
struct WarningTable {
    entries: BTreeMap<String, WarningReport>,
    capacity: usize,
    dropped: u64,
}

impl WarningTable {
    fn new(capacity: usize) -> Self {
        Self { entries: BTreeMap::new(), capacity, dropped: 0 }
    }

    fn add(&mut self, code: &str, message: &str) {
        if let Some(entry) = self.entries.get_mut(code) {
            entry.count = entry.count.saturating_add(1);
            return;
        }
        if self.entries.len() >= self.capacity {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.entries.insert(
            code.to_owned(),
            WarningReport { code: code.to_owned(), message: message.to_owned(), count: 1 },
        );
    }

    fn reports(&self) -> Vec<WarningReport> {
        let mut reports: Vec<_> = self.entries.values().cloned().collect();
        if self.dropped > 0 {
            reports.push(WarningReport {
                code: "warning_capacity_exceeded".to_owned(),
                message: "additional warning categories were omitted from the report".to_owned(),
                count: self.dropped,
            });
        }
        reports
    }
}

#[derive(Debug)]
struct SpaceSavingTable {
    capacity: usize,
    entries: HashMap<String, CounterEntry>,
    by_id: HashMap<u64, String>,
    order: BTreeSet<(u64, u64)>,
    next_id: u64,
    evictions: u64,
}

#[derive(Clone, Copy, Debug)]
struct CounterEntry {
    count: u64,
    error_estimate: u64,
    id: u64,
}

impl SpaceSavingTable {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::with_capacity(capacity.min(16_384)),
            by_id: HashMap::with_capacity(capacity.min(16_384)),
            order: BTreeSet::new(),
            next_id: 0,
            evictions: 0,
        }
    }

    fn add(&mut self, key: String) {
        if let Some(current) = self.entries.get(&key).copied() {
            self.order.remove(&(current.count, current.id));
            let updated = CounterEntry { count: current.count.saturating_add(1), ..current };
            self.entries.insert(key, updated);
            self.order.insert((updated.count, updated.id));
            return;
        }

        if self.entries.len() == self.capacity {
            let Some(&(minimum, minimum_id)) = self.order.first() else {
                return;
            };
            self.order.remove(&(minimum, minimum_id));
            if let Some(old_key) = self.by_id.remove(&minimum_id) {
                self.entries.remove(&old_key);
            }
            self.evictions = self.evictions.saturating_add(1);
            let entry =
                CounterEntry { count: minimum.saturating_add(1), error_estimate: minimum, id: minimum_id };
            self.entries.insert(key.clone(), entry);
            self.by_id.insert(minimum_id, key);
            self.order.insert((entry.count, entry.id));
            return;
        }

        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let entry = CounterEntry { count: 1, error_estimate: 0, id };
        self.entries.insert(key.clone(), entry);
        self.by_id.insert(id, key);
        self.order.insert((entry.count, entry.id));
    }

    fn report(&self, top: usize) -> PatternReport {
        let mut entries: Vec<_> = self
            .entries
            .iter()
            .map(|(pattern, entry)| PatternEntryReport {
                pattern: pattern.clone(),
                count: entry.count,
                error_estimate: entry.error_estimate,
            })
            .collect();
        entries.sort_by(|left, right| {
            right.count.cmp(&left.count).then_with(|| left.pattern.cmp(&right.pattern))
        });
        entries.truncate(top);
        PatternReport {
            entries,
            capacity: self.capacity,
            evictions: self.evictions,
            approximate: self.evictions > 0,
        }
    }
}

#[derive(Debug)]
struct TimeAccumulator {
    max_buckets: usize,
    records_with_timestamps: u64,
    records_with_timezone: u64,
    zoned: TimeAxis,
    wall: TimeAxis,
}

impl TimeAccumulator {
    fn new(max_buckets: usize) -> Self {
        Self {
            max_buckets,
            records_with_timestamps: 0,
            records_with_timezone: 0,
            zoned: TimeAxis::new(true),
            wall: TimeAxis::new(false),
        }
    }

    fn observe(&mut self, timestamp: &Timestamp, is_error: bool) {
        self.records_with_timestamps = self.records_with_timestamps.saturating_add(1);
        match timestamp {
            Timestamp::Zoned { seconds, display } => {
                self.records_with_timezone = self.records_with_timezone.saturating_add(1);
                self.zoned.observe(*seconds, display, is_error, self.max_buckets);
            }
            Timestamp::Wall { seconds, display } => {
                self.wall.observe(*seconds, display, is_error, self.max_buckets);
            }
            Timestamp::Partial { .. } => {}
        }
    }

    fn report(&self) -> TimeReport {
        let (start, end) = if self.zoned.has_values() {
            (self.zoned.start_display.clone(), self.zoned.end_display.clone())
        } else {
            (self.wall.start_display.clone(), self.wall.end_display.clone())
        };
        TimeReport {
            start,
            end,
            records_with_timestamps: self.records_with_timestamps,
            records_with_timezone: self.records_with_timezone,
            zoned: self.zoned.report(),
            wall_clock: self.wall.report(),
        }
    }
}

#[derive(Debug)]
struct TimeAxis {
    known_timezone: bool,
    interval_seconds: i64,
    buckets: BTreeMap<i64, TimeBucket>,
    start_display: Option<String>,
    end_display: Option<String>,
    min_seconds: Option<i64>,
    max_seconds: Option<i64>,
    rebalances: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct TimeBucket {
    events: u64,
    errors: u64,
}

impl TimeAxis {
    fn new(known_timezone: bool) -> Self {
        Self {
            known_timezone,
            interval_seconds: 60,
            buckets: BTreeMap::new(),
            start_display: None,
            end_display: None,
            min_seconds: None,
            max_seconds: None,
            rebalances: 0,
        }
    }

    fn has_values(&self) -> bool {
        !self.buckets.is_empty()
    }

    fn observe(&mut self, seconds: i64, display: &str, is_error: bool, max_buckets: usize) {
        if self.min_seconds.is_none_or(|minimum| seconds < minimum) {
            self.min_seconds = Some(seconds);
            self.start_display = Some(display.to_owned());
        }
        if self.max_seconds.is_none_or(|maximum| seconds > maximum) {
            self.max_seconds = Some(seconds);
            self.end_display = Some(display.to_owned());
        }
        let bucket = self.bucket_start(seconds);
        let entry = self.buckets.entry(bucket).or_default();
        entry.events = entry.events.saturating_add(1);
        if is_error {
            entry.errors = entry.errors.saturating_add(1);
        }
        while self.buckets.len() > max_buckets {
            let next_interval = self.interval_seconds.saturating_mul(2).max(1);
            if next_interval == self.interval_seconds {
                break;
            }
            self.interval_seconds = next_interval;
            self.rebalances = self.rebalances.saturating_add(1);
            let old = std::mem::take(&mut self.buckets);
            for (start, old_bucket) in old {
                let new_start = self.bucket_start(start);
                let entry = self.buckets.entry(new_start).or_default();
                entry.events = entry.events.saturating_add(old_bucket.events);
                entry.errors = entry.errors.saturating_add(old_bucket.errors);
            }
        }
    }

    fn bucket_start(&self, seconds: i64) -> i64 {
        seconds.div_euclid(self.interval_seconds).saturating_mul(self.interval_seconds)
    }

    fn report(&self) -> Option<TimeSeriesReport> {
        if self.buckets.is_empty() {
            return None;
        }
        let buckets = self
            .buckets
            .iter()
            .map(|(start, bucket)| TimeBucketReport {
                start: if self.known_timezone {
                    format_zoned_seconds(*start)
                } else {
                    format_wall_seconds(*start)
                },
                events: bucket.events,
                errors: bucket.errors,
            })
            .collect();
        Some(TimeSeriesReport {
            axis: if self.known_timezone { "zoned" } else { "wallClock" }.to_owned(),
            interval_seconds: self.interval_seconds as u64,
            buckets,
            approximate: self.rebalances > 0,
        })
    }
}

#[derive(Debug)]
struct HttpAccumulator {
    requests: u64,
    error_responses: u64,
    status_codes: BTreeMap<String, u64>,
    methods: BTreeMap<String, u64>,
    method_capacity: usize,
    method_evictions: u64,
    endpoints: SpaceSavingTable,
    duration_count: u64,
    duration_total_ms: f64,
    max_duration_ms: Option<f64>,
    slowest: Option<SlowRequestReport>,
}

impl HttpAccumulator {
    fn new(endpoint_capacity: usize) -> Self {
        Self {
            requests: 0,
            error_responses: 0,
            status_codes: BTreeMap::new(),
            methods: BTreeMap::new(),
            method_capacity: endpoint_capacity.max(1),
            method_evictions: 0,
            endpoints: SpaceSavingTable::new(endpoint_capacity),
            duration_count: 0,
            duration_total_ms: 0.0,
            max_duration_ms: None,
            slowest: None,
        }
    }

    fn observe(&mut self, event: &crate::model::HttpEvent) {
        self.requests = self.requests.saturating_add(1);
        if let Some(status) = event.status {
            increment(&mut self.status_codes, status.to_string());
            if status >= 400 {
                self.error_responses = self.error_responses.saturating_add(1);
            }
        }
        if let Some(method) = &event.method {
            if self.methods.contains_key(method) || self.methods.len() < self.method_capacity {
                increment(&mut self.methods, method.clone());
            } else {
                self.method_evictions = self.method_evictions.saturating_add(1);
            }
        }
        if let (Some(method), Some(path)) = (&event.method, &event.path) {
            self.endpoints.add(format!("{method} {path}"));
        }
        let Some(duration_ms) = event.duration_ms.filter(|value| value.is_finite() && *value >= 0.0) else {
            return;
        };
        self.duration_count = self.duration_count.saturating_add(1);
        let total = self.duration_total_ms + duration_ms;
        self.duration_total_ms = if total.is_finite() { total } else { f64::MAX };
        if self.max_duration_ms.is_none_or(|maximum| duration_ms > maximum) {
            self.max_duration_ms = Some(duration_ms);
        }
        if self.slowest.as_ref().is_none_or(|slowest| duration_ms > slowest.duration_ms) {
            self.slowest = Some(SlowRequestReport {
                duration_ms,
                method: event.method.clone(),
                path: event.path.clone(),
                status: event.status,
            });
        }
    }

    fn report(&self) -> Option<HttpReport> {
        (self.requests > 0).then(|| HttpReport {
            requests: self.requests,
            error_responses: self.error_responses,
            status_codes: self.status_codes.clone(),
            methods: self.methods.clone(),
            method_evictions: self.method_evictions,
            endpoints: self.endpoints.report(10),
            duration_count: self.duration_count,
            average_duration_ms: (self.duration_count > 0)
                .then_some(self.duration_total_ms / self.duration_count as f64),
            max_duration_ms: self.max_duration_ms,
            slowest: self.slowest.clone(),
        })
    }
}

fn increment<K: Ord>(map: &mut BTreeMap<K, u64>, key: K) {
    let entry = map.entry(key).or_default();
    *entry = entry.saturating_add(1);
}

fn normalize_message(message: &str) -> String {
    let redacted = secret_regex().replace_all(message, "$1=<redacted>");
    let uuid = uuid_regex().replace_all(&redacted, "<uuid>");
    let ip = ip_regex().replace_all(&uuid, "<ip>");
    let hex = hex_regex().replace_all(&ip, "<hex>");
    number_regex().replace_all(&hex, "<num>").into_owned()
}

fn secret_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?i)\b(password|passwd|token|secret|api[_-]?key)\s*=\s*[^\s&,;]+")
            .expect("secret normalization regex is valid")
    })
}

fn uuid_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b")
            .expect("UUID normalization regex is valid")
    })
}

fn ip_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("IP normalization regex is valid"))
}

fn hex_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"\b0x[0-9a-fA-F]+\b").expect("hex normalization regex is valid"))
}

fn number_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"\b\d+(?:\.\d+)?\b").expect("number normalization regex is valid"))
}

#[cfg(test)]
mod tests {
    use regex::Regex;

    use super::*;
    use crate::model::{HttpEvent, ParserKind};

    fn analyzer() -> Analyzer {
        Analyzer::new(AnalyzerConfig {
            filter: Filter {
                min_severity: Severity::Unknown,
                grep: None,
                regex: None,
                statuses: BTreeSet::new(),
                since: None,
                until: None,
            },
            max_patterns: 2,
            max_time_buckets: 2,
            top: 10,
        })
    }

    #[test]
    fn bounded_patterns_remain_bounded_and_mark_approximation() {
        let mut analyzer = analyzer();
        let input = analyzer.begin_input("test".to_owned());
        for letter in 'a'..='t' {
            analyzer.record_event(
                input,
                Event {
                    timestamp: None,
                    severity: Severity::Error,
                    message: format!("failure {letter}"),
                    parser: ParserKind::Plain,
                    http: None,
                },
            );
        }
        let report = analyzer.report();
        assert!(report.patterns.entries.len() <= 2);
        assert!(report.patterns.approximate);
    }

    #[test]
    fn filters_are_applied_before_aggregation() {
        let mut analyzer = Analyzer::new(AnalyzerConfig {
            filter: Filter {
                min_severity: Severity::Error,
                grep: Some("database".to_owned()),
                regex: Some(Regex::new("timeout").expect("regex")),
                statuses: BTreeSet::new(),
                since: None,
                until: None,
            },
            max_patterns: 8,
            max_time_buckets: 8,
            top: 10,
        });
        let input = analyzer.begin_input("test".to_owned());
        analyzer.record_event(
            input,
            Event {
                timestamp: None,
                severity: Severity::Error,
                message: "database timeout".to_owned(),
                parser: ParserKind::Plain,
                http: None,
            },
        );
        analyzer.record_event(
            input,
            Event {
                timestamp: None,
                severity: Severity::Info,
                message: "database timeout".to_owned(),
                parser: ParserKind::Plain,
                http: None,
            },
        );
        let report = analyzer.report();
        assert_eq!(report.statistics.records_parsed, 2);
        assert_eq!(report.statistics.records_matched, 1);
        assert_eq!(report.patterns.entries[0].count, 1);
    }

    #[test]
    fn http_statistics_are_aggregated() {
        let mut analyzer = analyzer();
        let input = analyzer.begin_input("access.log".to_owned());
        analyzer.record_event(
            input,
            Event {
                timestamp: None,
                severity: Severity::Error,
                message: "GET /items/1 -> 500".to_owned(),
                parser: ParserKind::Nginx,
                http: Some(HttpEvent {
                    method: Some("GET".to_owned()),
                    path: Some("/items/1".to_owned()),
                    status: Some(500),
                    response_bytes: Some(42),
                    duration_ms: Some(250.0),
                }),
            },
        );
        let report = analyzer.report();
        let http = report.http.expect("http report");
        assert_eq!(http.requests, 1);
        assert_eq!(http.error_responses, 1);
        assert_eq!(http.max_duration_ms, Some(250.0));
    }
}
