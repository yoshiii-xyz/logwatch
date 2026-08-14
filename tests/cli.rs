use std::fs;
use std::path::Path;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::tempdir;

fn command() -> Command {
    Command::cargo_bin("logwatch").expect("binary is built")
}

fn write_log(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write fixture");
}

#[test]
fn human_report_summarizes_plain_and_access_records() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("server.log");
    write_log(
        &path,
        "2026-08-14T12:30:00Z INFO service started\n2026-08-14T12:31:00Z ERROR database timeout for user 10\n127.0.0.1 - - [14/Aug/2026:12:32:00 +0000] \"GET /api/items/12?token=secret HTTP/1.1\" 500 42 \"-\" \"curl\" 0.250\n",
    );

    let output = command().arg(&path).output().expect("run logwatch");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(stdout.contains("records                 3 parsed, 3 matched, 0 filtered"));
    assert!(stdout.contains("nginx"));
    assert!(stdout.contains("error responses         1"));
    assert!(stdout.contains("<num>"));
    assert!(!stdout.contains("token=secret"));
}

#[test]
fn json_output_is_structured_and_script_friendly() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("events.jsonl");
    write_log(
        &path,
        "{\"timestamp\":\"2026-08-14T12:30:00Z\",\"level\":\"error\",\"message\":\"cache miss\",\"method\":\"GET\",\"status\":503,\"path\":\"/cache/12?token=secret\"}\n",
    );

    let output = command().args(["--json", "--format", "jsonl"]).arg(&path).output().expect("run logwatch");
    assert!(output.status.success());
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(document["schemaVersion"], 1);
    assert_eq!(document["statistics"]["recordsMatched"], 1);
    assert_eq!(document["severity"]["error"], 1);
    assert_eq!(document["http"]["statusCodes"]["503"], 1);
    assert_eq!(document["http"]["endpoints"]["entries"][0]["pattern"], "GET /cache/12");
}

#[test]
fn stdin_is_supported_without_terminal_decoration() {
    let output =
        command().arg("-").write_stdin("INFO from stdin\nERROR failed\n").output().expect("run logwatch");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(stdout.contains("lines read              2"));
    assert!(!stdout.contains("\u{1b}"));
}

#[test]
fn filters_are_applied_before_summary_counts() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("filter.log");
    write_log(&path, "INFO ready\nERROR database timeout\nWARN network timeout\n");

    let output = command()
        .args(["--json", "--errors", "--grep", "database"])
        .arg(&path)
        .output()
        .expect("run logwatch");
    assert!(output.status.success());
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(document["statistics"]["recordsParsed"], 3);
    assert_eq!(document["statistics"]["recordsMatched"], 1);
    assert_eq!(document["statistics"]["recordsFiltered"], 2);
}

#[test]
fn malformed_lines_are_retained_and_reported() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("malformed.log");
    let mut bytes = b"{not-json\nINFO safe\n".to_vec();
    bytes.extend_from_slice(b"bad ");
    bytes.push(0xff);
    bytes.extend_from_slice(b" byte\n");
    fs::write(&path, bytes).expect("write fixture");

    let output = command().args(["--json", "--format", "jsonl"]).arg(&path).output().expect("run logwatch");
    assert!(output.status.success());
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(document["statistics"]["linesRead"], 3);
    assert_eq!(document["statistics"]["invalidUtf8Lines"], 1);
    assert!(
        document["warnings"]
            .as_array()
            .expect("warnings array")
            .iter()
            .any(|warning| { warning["code"] == "invalid_json" })
    );
}

#[test]
fn long_lines_are_bounded_and_skipped() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("long.log");
    write_log(&path, &format!("{}\nINFO retained\n", "x".repeat(1024)));

    let output =
        command().args(["--json", "--max-line-bytes", "64"]).arg(&path).output().expect("run logwatch");
    assert!(output.status.success());
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(document["statistics"]["linesRead"], 2);
    assert_eq!(document["statistics"]["truncatedLines"], 1);
    assert_eq!(document["statistics"]["recordsMatched"], 1);
}

#[test]
fn missing_file_returns_runtime_error_and_json_remains_valid() {
    let directory = tempdir().expect("temporary directory");
    let missing = directory.path().join("missing.log");
    let output = command().args(["--json"]).arg(&missing).output().expect("run logwatch");
    assert_eq!(output.status.code(), Some(1));
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(document["inputs"][0]["status"], "error");
}

#[test]
fn duplicate_input_paths_are_processed_once() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("once.log");
    write_log(&path, "INFO once\n");

    let output = command().args(["--json"]).arg(&path).arg(&path).output().expect("run logwatch");
    assert!(output.status.success());
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(document["inputs"].as_array().expect("inputs").len(), 1);
    assert_eq!(document["statistics"]["linesRead"], 1);
}
