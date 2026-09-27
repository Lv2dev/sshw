//! Incremental, line-oriented output. Raw network chunks never reach a writer.
use super::{redact_partial_text, redact_with_known_secrets};
use crate::error::ResultErrorKindExt;
use crate::output::{ErrorKind, filter_startup_stderr_noise, is_pem_marker};
use crate::ssh::OutputStream;
use std::io::Write;

struct Redactor<'a> {
    pending: Vec<u8>,
    in_key: bool,
    secrets: &'a [Option<&'a str>],
    multiline_secret: bool,
    stderr: bool,
}

impl<'a> Redactor<'a> {
    fn new(secrets: &'a [Option<&'a str>], stderr: bool) -> Self {
        Self {
            pending: Vec::new(),
            in_key: false,
            secrets,
            multiline_secret: secrets.iter().flatten().any(|value| value.contains('\n')),
            stderr,
        }
    }
    fn line(&mut self, line: &str, partial: bool) -> String {
        if self.in_key {
            if is_pem_marker(line.trim(), "-----END") {
                self.in_key = false;
            }
            return String::new();
        }
        if is_pem_marker(line.trim(), "-----BEGIN") {
            self.in_key = true;
            return if line.ends_with('\n') {
                "[redacted private key]\n"
            } else {
                "[redacted private key]"
            }
            .into();
        }
        let line = if self.stderr {
            filter_startup_stderr_noise(line)
        } else {
            line.to_string()
        };
        if partial {
            redact_partial_text(&line, self.secrets)
        } else {
            redact_with_known_secrets(&line, self.secrets)
        }
    }
    fn push(&mut self, bytes: &[u8]) -> String {
        self.pending.extend_from_slice(bytes);
        if self.multiline_secret {
            return String::new();
        }
        let Some(end) = self.pending.iter().rposition(|byte| *byte == b'\n') else {
            return String::new();
        };
        let ready: Vec<_> = self.pending.drain(..=end).collect();
        let ready = String::from_utf8_lossy(&ready);
        ready
            .split_inclusive('\n')
            .map(|line| self.line(line, false))
            .collect()
    }
    fn finish(&mut self, failed: bool) -> String {
        let pending = std::mem::take(&mut self.pending);
        let text = String::from_utf8_lossy(&pending);
        if self.multiline_secret {
            return if failed {
                redact_partial_text(&text, self.secrets)
            } else {
                redact_with_known_secrets(&text, self.secrets)
            };
        }
        self.line(&text, failed)
    }
}

pub(super) struct Writer<'a, O, E> {
    stdout: O,
    stderr: E,
    out: Redactor<'a>,
    err: Redactor<'a>,
}

impl<'a, O: Write, E: Write> Writer<'a, O, E> {
    pub(super) fn new(stdout: O, stderr: E, secrets: &'a [Option<&'a str>]) -> Self {
        Self {
            stdout,
            stderr,
            out: Redactor::new(secrets, false),
            err: Redactor::new(secrets, true),
        }
    }
    pub(super) fn push(&mut self, stream: OutputStream, bytes: &[u8]) -> anyhow::Result<()> {
        let (writer, text): (&mut dyn Write, String) = match stream {
            OutputStream::Stdout => (&mut self.stdout, self.out.push(bytes)),
            OutputStream::Stderr => (&mut self.stderr, self.err.push(bytes)),
        };
        writer
            .write_all(text.as_bytes())
            .with_error_kind(ErrorKind::Io)?;
        writer.flush().with_error_kind(ErrorKind::Io)
    }
    pub(super) fn finish(&mut self, failed: bool) -> anyhow::Result<()> {
        self.stdout
            .write_all(self.out.finish(failed).as_bytes())
            .with_error_kind(ErrorKind::Io)?;
        self.stderr
            .write_all(self.err.finish(failed).as_bytes())
            .with_error_kind(ErrorKind::Io)?;
        self.stdout.flush().with_error_kind(ErrorKind::Io)?;
        self.stderr.flush().with_error_kind(ErrorKind::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_chunk_boundary_preserves_secret_utf8_and_pem_redaction() {
        let secrets = [Some("synth-secret")];
        let text = "시작 synth-secret\npassword=hidden\nAuthorization: Bearer abc\n-----BEGIN PRIVATE KEY-----\nprivate bytes\n-----END PRIVATE KEY-----\n끝\n";
        let expected = redact_with_known_secrets(text, &secrets);
        for split in 0..=text.len() {
            let mut output = Vec::new();
            let mut writer = Writer::new(&mut output, Vec::new(), &secrets);
            writer
                .push(OutputStream::Stdout, &text.as_bytes()[..split])
                .unwrap();
            writer
                .push(OutputStream::Stdout, &text.as_bytes()[split..])
                .unwrap();
            writer.finish(false).unwrap();
            assert_eq!(
                String::from_utf8(output).unwrap(),
                expected,
                "split {split}"
            );
        }
    }
    #[test]
    fn complete_lines_are_released_but_incomplete_secrets_wait() {
        let secrets = [Some("synth-secret")];
        let mut redactor = Redactor::new(&secrets, false);
        assert_eq!(redactor.push(b"first\nsynth-"), "first\n");
        assert_eq!(redactor.push(b"sec"), "");
        assert_eq!(redactor.finish(true), "<redacted>");
    }
    #[test]
    fn multiline_known_secrets_are_buffered_conservatively() {
        let secrets = [Some("first\nsecond")];
        let mut redactor = Redactor::new(&secrets, false);
        assert_eq!(redactor.push(b"prefix first\n"), "");
        assert_eq!(redactor.push(b"second\n"), "");
        assert_eq!(redactor.finish(false), "prefix <redacted>\n");
    }
}
