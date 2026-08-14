use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use thiserror::Error;

use crate::aggregate::{Analyzer, AnalyzerConfig};
use crate::cli::InputFormat;
use crate::model::Report;
use crate::parser::parse_line;
use crate::render::render_human;

const BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug)]
pub struct ScanResult {
    pub report: Report,
    pub had_errors: bool,
}

pub fn scan_sources(
    paths: &[PathBuf],
    format: InputFormat,
    max_line_bytes: usize,
    allow_binary: bool,
    config: AnalyzerConfig,
) -> ScanResult {
    let mut analyzer = Analyzer::new(config);
    let mut had_errors = false;
    let mut seen = BTreeSet::new();

    for path in paths {
        let label = path.to_string_lossy().into_owned();
        if !seen.insert(label.clone()) {
            continue;
        }
        let input = analyzer.begin_input(label.clone());
        let result = if path == Path::new("-") {
            let stdin = io::stdin();
            let reader = BufReader::with_capacity(BUFFER_SIZE, stdin.lock());
            scan_reader(reader, &mut analyzer, input, format, max_line_bytes, allow_binary, false)
        } else {
            match File::open(path) {
                Ok(file) => {
                    let reader = BufReader::with_capacity(BUFFER_SIZE, file);
                    scan_reader(reader, &mut analyzer, input, format, max_line_bytes, allow_binary, false)
                }
                Err(error) => Err(ReaderError::Io(error)),
            }
        };
        if let Err(error) = result {
            analyzer.record_input_error(input, format_reader_error(&label, &error));
            had_errors = true;
        }
    }

    ScanResult { report: analyzer.report(), had_errors }
}

pub fn follow_file(
    path: &Path,
    format: InputFormat,
    max_line_bytes: usize,
    allow_binary: bool,
    config: AnalyzerConfig,
    interval: Duration,
) -> Result<u8, String> {
    let file = File::open(path).map_err(|error| format!("could not open {}: {error}", path.display()))?;
    let mut reader =
        RecordReader::new(BufReader::with_capacity(BUFFER_SIZE, file), max_line_bytes, allow_binary)
            .map_err(|error| format_reader_error(&path.to_string_lossy(), &error))?;
    let mut analyzer = Analyzer::new(config.clone());
    let mut input = analyzer.begin_input(path.to_string_lossy().into_owned());
    let mut first_render = true;
    let mut had_errors = false;

    loop {
        if let Err(error) = process_available(&mut reader, &mut analyzer, input, format, true) {
            analyzer.record_input_error(input, format_reader_error(&path.to_string_lossy(), &error));
            had_errors = true;
        }

        let report = analyzer.report();
        let output = if first_render {
            render_human(&report)
        } else {
            format!("\x1b[2J\x1b[H{}", render_human(&report))
        };
        let mut stdout = io::stdout().lock();
        stdout.write_all(output.as_bytes()).map_err(|error| format!("could not refresh report: {error}"))?;
        stdout.flush().map_err(|error| format!("could not flush report: {error}"))?;
        first_render = false;

        let metadata = std::fs::metadata(path)
            .map_err(|error| format!("could not inspect {} while following: {error}", path.display()))?;
        if metadata.len() < reader.physical_position() {
            reader.reset_to_start().map_err(|error| format_reader_error(&path.to_string_lossy(), &error))?;
            analyzer = Analyzer::new(config.clone());
            input = analyzer.begin_input(path.to_string_lossy().into_owned());
            had_errors = false;
        }
        thread::sleep(interval);
        if had_errors {
            return Ok(1);
        }
    }
}

fn scan_reader<R: Read>(
    reader: BufReader<R>,
    analyzer: &mut Analyzer,
    input: usize,
    format: InputFormat,
    max_line_bytes: usize,
    allow_binary: bool,
    complete_only: bool,
) -> Result<(), ReaderError> {
    let mut reader = RecordReader::new(reader, max_line_bytes, allow_binary)?;
    process_available(&mut reader, analyzer, input, format, complete_only)?;
    Ok(())
}

fn process_available<R: BufRead>(
    reader: &mut RecordReader<R>,
    analyzer: &mut Analyzer,
    input: usize,
    format: InputFormat,
    complete_only: bool,
) -> Result<(), ReaderError> {
    loop {
        match reader.next_line(complete_only)? {
            ReadStatus::Eof | ReadStatus::Pending => return Ok(()),
            ReadStatus::Line(line) => {
                analyzer.record_line(input, line.bytes, line.invalid_encoding, line.truncated);
                if line.truncated {
                    continue;
                }
                let outcome = parse_line(&line.text, format);
                analyzer.record_parser(input, outcome.parser);
                if let Some(warning) = outcome.warning {
                    analyzer.record_warning(input, warning);
                }
                if let Some(event) = outcome.event {
                    analyzer.record_event(input, event);
                }
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum ReaderError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("binary-looking input was skipped; pass --allow-binary to decode it as text")]
    Binary,
}

fn format_reader_error(path: &str, error: &ReaderError) -> String {
    format!("{path}: {error}")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Encoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

#[derive(Debug)]
struct ReadLine {
    text: String,
    bytes: usize,
    invalid_encoding: bool,
    truncated: bool,
}

#[derive(Debug)]
enum ReadStatus {
    Line(ReadLine),
    Eof,
    Pending,
}

#[derive(Debug)]
struct RecordReader<R> {
    reader: R,
    encoding: Encoding,
    max_line_bytes: usize,
    allow_binary: bool,
    pending_bytes_utf8: Vec<u8>,
    pending_units_utf16: Vec<u16>,
    pending_utf16_byte: Option<u8>,
    pending_bytes: usize,
    pending_truncated: bool,
    pending_invalid: bool,
    physical_position: u64,
}

impl<R: BufRead> RecordReader<R> {
    fn new(reader: R, max_line_bytes: usize, allow_binary: bool) -> Result<Self, ReaderError> {
        let mut record_reader = Self {
            reader,
            encoding: Encoding::Utf8,
            max_line_bytes,
            allow_binary,
            pending_bytes_utf8: Vec::with_capacity(max_line_bytes.min(64 * 1024)),
            pending_units_utf16: Vec::with_capacity((max_line_bytes / 2).min(32 * 1024)),
            pending_utf16_byte: None,
            pending_bytes: 0,
            pending_truncated: false,
            pending_invalid: false,
            physical_position: 0,
        };
        record_reader.initialize()?;
        Ok(record_reader)
    }

    fn initialize(&mut self) -> Result<(), ReaderError> {
        let sample = self.reader.fill_buf()?;
        let (encoding, bom_bytes) = if sample.starts_with(&[0xef, 0xbb, 0xbf]) {
            (Encoding::Utf8, 3)
        } else if sample.starts_with(&[0xff, 0xfe]) {
            (Encoding::Utf16Le, 2)
        } else if sample.starts_with(&[0xfe, 0xff]) {
            (Encoding::Utf16Be, 2)
        } else {
            if !self.allow_binary && sample.contains(&0) {
                return Err(ReaderError::Binary);
            }
            (Encoding::Utf8, 0)
        };
        self.reader.consume(bom_bytes);
        self.encoding = encoding;
        self.physical_position = bom_bytes as u64;
        Ok(())
    }

    fn next_line(&mut self, complete_only: bool) -> Result<ReadStatus, ReaderError> {
        match self.encoding {
            Encoding::Utf8 => self.next_utf8_line(complete_only),
            Encoding::Utf16Le | Encoding::Utf16Be => self.next_utf16_line(complete_only),
        }
    }

    fn next_utf8_line(&mut self, complete_only: bool) -> Result<ReadStatus, ReaderError> {
        loop {
            let chunk = self.reader.fill_buf()?;
            if chunk.is_empty() {
                if self.pending_bytes == 0 {
                    return Ok(ReadStatus::Eof);
                }
                if complete_only {
                    return Ok(ReadStatus::Pending);
                }
                return Ok(ReadStatus::Line(self.finish_utf8_line()));
            }
            let newline = chunk.iter().position(|byte| *byte == b'\n');
            let take = newline.map_or(chunk.len(), |index| index + 1);
            let content_len = newline.unwrap_or(take);
            let remaining = self.max_line_bytes.saturating_sub(self.pending_bytes_utf8.len());
            let stored_len = content_len.min(remaining);
            let content = chunk[..stored_len].to_vec();
            let truncated = stored_len < content_len;
            self.pending_bytes = self.pending_bytes.saturating_add(take);
            self.physical_position = self.physical_position.saturating_add(take as u64);
            self.reader.consume(take);
            self.pending_bytes_utf8.extend_from_slice(&content);
            self.pending_truncated |= truncated;
            if newline.is_some() {
                return Ok(ReadStatus::Line(self.finish_utf8_line()));
            }
        }
    }

    fn next_utf16_line(&mut self, complete_only: bool) -> Result<ReadStatus, ReaderError> {
        loop {
            let first_was_pending = self.pending_utf16_byte.is_some();
            let first = if let Some(first) = self.pending_utf16_byte.take() {
                first
            } else {
                let Some(first) = self.read_byte()? else {
                    if self.pending_bytes == 0 {
                        return Ok(ReadStatus::Eof);
                    }
                    if complete_only {
                        return Ok(ReadStatus::Pending);
                    }
                    return Ok(ReadStatus::Line(self.finish_utf16_line()));
                };
                first
            };
            let Some(second) = self.read_byte()? else {
                self.pending_utf16_byte = Some(first);
                if !first_was_pending {
                    self.pending_bytes = self.pending_bytes.saturating_add(1);
                }
                if complete_only {
                    return Ok(ReadStatus::Pending);
                }
                self.pending_invalid = true;
                return Ok(ReadStatus::Line(self.finish_utf16_line()));
            };
            let unit = match self.encoding {
                Encoding::Utf16Le => u16::from_le_bytes([first, second]),
                Encoding::Utf16Be => u16::from_be_bytes([first, second]),
                Encoding::Utf8 => unreachable!("UTF-8 is handled separately"),
            };
            self.pending_bytes = self.pending_bytes.saturating_add(if first_was_pending { 1 } else { 2 });
            if unit == b'\n' as u16 {
                return Ok(ReadStatus::Line(self.finish_utf16_line()));
            }
            self.append_utf16(unit);
        }
    }

    fn read_byte(&mut self) -> Result<Option<u8>, ReaderError> {
        let chunk = self.reader.fill_buf()?;
        let Some(byte) = chunk.first().copied() else {
            return Ok(None);
        };
        self.reader.consume(1);
        self.physical_position = self.physical_position.saturating_add(1);
        Ok(Some(byte))
    }

    fn append_utf16(&mut self, unit: u16) {
        if self.pending_units_utf16.len().saturating_mul(2) < self.max_line_bytes {
            self.pending_units_utf16.push(unit);
        } else {
            self.pending_truncated = true;
        }
    }

    fn finish_utf8_line(&mut self) -> ReadLine {
        let mut bytes = std::mem::take(&mut self.pending_bytes_utf8);
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        let invalid_encoding = self.pending_invalid || std::str::from_utf8(&bytes).is_err();
        let text =
            if self.pending_truncated { String::new() } else { String::from_utf8_lossy(&bytes).into_owned() };
        let line =
            ReadLine { text, bytes: self.pending_bytes, invalid_encoding, truncated: self.pending_truncated };
        self.reset_pending();
        line
    }

    fn finish_utf16_line(&mut self) -> ReadLine {
        if self.pending_units_utf16.last() == Some(&(b'\r' as u16)) {
            self.pending_units_utf16.pop();
        }
        let units = std::mem::take(&mut self.pending_units_utf16);
        let invalid_encoding = self.pending_invalid
            || std::char::decode_utf16(units.iter().copied()).any(|result| result.is_err());
        let text = if self.pending_truncated { String::new() } else { String::from_utf16_lossy(&units) };
        let line =
            ReadLine { text, bytes: self.pending_bytes, invalid_encoding, truncated: self.pending_truncated };
        self.reset_pending();
        line
    }

    fn reset_pending(&mut self) {
        self.pending_utf16_byte = None;
        self.pending_bytes = 0;
        self.pending_truncated = false;
        self.pending_invalid = false;
    }

    fn physical_position(&self) -> u64 {
        self.physical_position
    }
}

impl<R: BufRead + Seek> RecordReader<R> {
    fn reset_to_start(&mut self) -> Result<(), ReaderError> {
        self.reader.seek(SeekFrom::Start(0))?;
        self.pending_bytes_utf8.clear();
        self.pending_units_utf16.clear();
        self.reset_pending();
        self.physical_position = 0;
        self.initialize()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn reads_invalid_utf8_lossily_without_unbounded_growth() {
        let input = Cursor::new(vec![b'a', 0xff, b'\n', b'b', b'\n']);
        let mut reader = RecordReader::new(BufReader::new(input), 8, false).expect("reader");
        let ReadStatus::Line(line) = reader.next_line(false).expect("line") else {
            panic!("expected line");
        };
        assert!(line.invalid_encoding);
        assert!(line.text.contains('�'));
    }

    #[test]
    fn skips_or_accepts_binary_input_by_policy() {
        let input = Cursor::new(vec![0, 1, 2, b'\n']);
        assert!(matches!(RecordReader::new(BufReader::new(input), 8, false), Err(ReaderError::Binary)));
        let input = Cursor::new(vec![0, 1, 2, b'\n']);
        assert!(RecordReader::new(BufReader::new(input), 8, true).is_ok());
    }

    #[test]
    fn holds_an_incomplete_follow_line_until_newline() {
        let input = Cursor::new(b"first\nsecond".to_vec());
        let mut reader = RecordReader::new(BufReader::new(input), 64, false).expect("reader");
        assert!(matches!(reader.next_line(true).expect("line"), ReadStatus::Line(_)));
        assert!(matches!(reader.next_line(true).expect("pending"), ReadStatus::Pending));
    }

    #[test]
    fn recognizes_utf16_with_bom() {
        let mut bytes = vec![0xff, 0xfe];
        for unit in "INFO hello\n".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let mut reader = RecordReader::new(BufReader::new(Cursor::new(bytes)), 64, false).expect("reader");
        let ReadStatus::Line(line) = reader.next_line(false).expect("line") else {
            panic!("expected line");
        };
        assert_eq!(line.text, "INFO hello");
    }
}
