//! Best-effort stderr observations; display failures never retry or abort a transfer.
use crate::ssh::{TransferPhase, TransferProgress};
use std::io::{self, IsTerminal, Write};
use std::time::{Duration, Instant};

pub(super) struct ProgressDisplay<W: Write> {
    writer: Option<W>,
    terminal: bool,
    direction: &'static str,
    started: Instant,
    last_update: Duration,
    last_event: Option<TransferProgress>,
    width: usize,
    ended: bool,
}

impl ProgressDisplay<io::Stderr> {
    pub(super) fn stderr(direction: &'static str) -> Self {
        let stderr = io::stderr();
        let terminal = stderr.is_terminal();
        Self::new(stderr, terminal, direction)
    }
}

impl<W: Write> ProgressDisplay<W> {
    fn new(writer: W, terminal: bool, direction: &'static str) -> Self {
        let mut display = Self {
            writer: Some(writer),
            terminal,
            direction,
            started: Instant::now(),
            last_update: Duration::ZERO,
            last_event: None,
            width: 0,
            ended: false,
        };
        display.line(
            &format!("sshw {direction}: connecting / preparing transfer"),
            false,
        );
        display
    }

    pub(super) fn update(&mut self, event: TransferProgress) {
        self.update_at(event, self.started.elapsed());
    }

    fn update_at(&mut self, event: TransferProgress, elapsed: Duration) {
        let changed_phase = self.last_event.is_none_or(|last| last.phase != event.phase);
        self.last_event = Some(event);
        let interval = if self.terminal {
            Duration::from_millis(100)
        } else {
            Duration::from_secs(1)
        };
        if !changed_phase && elapsed.saturating_sub(self.last_update) < interval {
            return;
        }
        self.last_update = elapsed;
        let complete = event.phase == TransferPhase::Complete;
        let percent = if complete {
            100
        } else if event.total == 0 {
            0
        } else {
            ((u128::from(event.bytes) * 100 / u128::from(event.total)).min(99)) as u64
        };
        let speed = event.bytes as f64 / elapsed.as_secs_f64().max(0.001);
        let stage = match event.phase {
            TransferPhase::Data => "transferring",
            TransferPhase::Finalizing => "verifying completion",
            TransferPhase::Complete => "complete",
        };
        let line = if self.terminal {
            let stage = match event.phase {
                TransferPhase::Data => "transferring",
                TransferPhase::Finalizing => "verifying",
                TransferPhase::Complete => "complete",
            };
            format!(
                "sshw {}: {percent:3}% {}/{} {}/s {stage}",
                self.direction,
                byte_rate(event.bytes as f64),
                byte_rate(event.total as f64),
                byte_rate(speed)
            )
        } else {
            format!(
                "sshw {}: {percent:3}% {}/{} bytes ({}/s) - {stage}",
                self.direction,
                event.bytes,
                event.total,
                byte_rate(speed)
            )
        };
        self.line(&line, complete);
        self.ended = complete;
    }

    pub(super) fn finish(&mut self, success: bool) {
        if !success && !self.ended {
            let copied = self
                .last_event
                .map(|event| {
                    if self.terminal {
                        format!(" after {}", byte_rate(event.bytes as f64))
                    } else {
                        format!(" after {} bytes", event.bytes)
                    }
                })
                .unwrap_or_default();
            self.line(
                &format!(
                    "sshw {}: failed{copied}; completion unconfirmed",
                    self.direction
                ),
                true,
            );
            self.ended = true;
        }
    }

    fn line(&mut self, line: &str, end: bool) {
        if let Some(writer) = self.writer.as_mut() {
            let result = if self.terminal {
                self.width = self.width.max(line.len());
                write!(
                    writer,
                    "\r{line:<width$}{}",
                    if end { "\n" } else { "" },
                    width = self.width
                )
            } else {
                writeln!(writer, "{line}")
            }
            .and_then(|_| writer.flush());
            if result.is_err() {
                self.writer = None;
            }
        }
    }
}

impl<W: Write> Drop for ProgressDisplay<W> {
    fn drop(&mut self) {
        if self.terminal
            && !self.ended
            && let Some(writer) = self.writer.as_mut()
        {
            let _ = writeln!(writer).and_then(|_| writer.flush());
        }
    }
}

fn byte_rate(mut value: f64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    let mut unit = 0;
    while value >= 1024.0 && unit < units.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", units[unit])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirected_output_is_throttled_and_completion_is_verified_even_for_empty_files() {
        for total in [0, 4096, u64::MAX] {
            let mut output = Vec::new();
            {
                let mut display = ProgressDisplay::new(&mut output, false, "upload");
                for (bytes, millis, phase) in [
                    (0, 0, TransferPhase::Data),
                    (total / 2, 50, TransferPhase::Data),
                    (total, 60, TransferPhase::Finalizing),
                ] {
                    display.update_at(
                        TransferProgress {
                            bytes,
                            total,
                            phase,
                        },
                        Duration::from_millis(millis),
                    );
                }
                // Full data does not imply confirmed remote completion.
                assert!(
                    !String::from_utf8_lossy(display.writer.as_ref().unwrap()).contains("100%")
                );
                display.update_at(
                    TransferProgress {
                        bytes: total,
                        total,
                        phase: TransferPhase::Complete,
                    },
                    Duration::from_secs(2),
                );
                display.finish(true);
            }
            let text = String::from_utf8(output).unwrap();
            assert_eq!(text.lines().count(), 4);
            assert!(!text.contains('\r'));
            assert!(!text.contains('\x1b'));
            assert!(text.contains("100%"));
            assert!(text.contains("/s) - complete"));
            assert!(text.ends_with("complete\n"));
        }
    }

    #[test]
    fn terminal_and_failure_end_on_a_new_line_without_false_success() {
        for bytes in [4096, u64::MAX] {
            let mut output = Vec::new();
            {
                let mut display = ProgressDisplay::new(&mut output, true, "download");
                display.update_at(
                    TransferProgress {
                        bytes,
                        total: bytes,
                        phase: TransferPhase::Finalizing,
                    },
                    Duration::from_secs(2),
                );
                display.finish(false);
            }
            let text = String::from_utf8(output).unwrap();
            assert!(text.starts_with('\r'));
            assert!(text.contains("99%"));
            if bytes == 4096 {
                assert!(text.contains("2.0 KiB/s"));
            }
            assert!(text.contains("failed after"));
            assert!(!text.contains("100%"));
            assert!(text.ends_with('\n'));
            assert!(
                text.split('\r')
                    .all(|line| line.trim_end_matches('\n').len() < 80)
            );
        }
    }

    #[test]
    fn broken_progress_writer_is_disabled_without_panicking_or_failing_transfer() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                panic!("disabled writer must not be flushed");
            }
        }
        let mut display = ProgressDisplay::new(Broken, true, "upload");
        assert!(display.writer.is_none());
        display.update(TransferProgress {
            bytes: 0,
            total: 0,
            phase: TransferPhase::Complete,
        });
        display.finish(true);
    }
}
