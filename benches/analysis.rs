use logwatch::cli::InputFormat;

fn main() {
    divan::main();
}

#[divan::bench]
fn parse_plain_record() {
    let line = "2026-08-14T12:30:00Z ERROR request failed for user 123";
    divan::black_box(logwatch::parser::parse_line(line, InputFormat::Auto));
}

#[divan::bench]
fn parse_json_record() {
    let line = r#"{"timestamp":"2026-08-14T12:30:00Z","level":"error","message":"request failed","status":500,"duration_ms":42}"#;
    divan::black_box(logwatch::parser::parse_line(line, InputFormat::Jsonl));
}

#[divan::bench]
fn normalize_and_aggregate() {
    let mut analyzer = logwatch::aggregate::Analyzer::new(logwatch::aggregate::AnalyzerConfig {
        filter: logwatch::aggregate::Filter {
            min_severity: logwatch::model::Severity::Unknown,
            grep: None,
            regex: None,
            statuses: std::collections::BTreeSet::new(),
            since: None,
            until: None,
        },
        max_patterns: 4096,
        max_time_buckets: 4096,
        top: 10,
    });
    let input = analyzer.begin_input("bench".to_owned());
    for number in 0..100 {
        let event = logwatch::parser::parse_line(
            &format!("2026-08-14T12:30:00Z ERROR request failed for user {number}"),
            InputFormat::Plain,
        )
        .event
        .expect("event");
        analyzer.record_event(input, event);
    }
    divan::black_box(analyzer.report());
}
