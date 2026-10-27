use std::io::{self, IsTerminal, Read};
#[cfg(test)]
use std::io::{BufRead, Write};

#[cfg(not(windows))]
use rprompt::prompt_reply;
#[cfg(windows)]
use windows_confirmation::prompt_reply;

pub trait Prompter {
    /// Check readiness without prompting. Existing programmatic prompters remain available.
    fn ensure_confirmation_available(&mut self, _option: &str) -> anyhow::Result<()> {
        Ok(())
    }
    fn confirm(&mut self, prompt: &str) -> anyhow::Result<bool>;
    fn confirm_with_option(&mut self, prompt: &str, _option: &str) -> anyhow::Result<bool> {
        self.confirm(prompt)
    }
    fn password(&mut self, prompt: &str) -> anyhow::Result<String>;
    fn password_stdin(&mut self) -> anyhow::Result<String>;
}

pub(crate) struct TerminalPrompter;

impl Prompter for TerminalPrompter {
    fn ensure_confirmation_available(&mut self, option: &str) -> anyhow::Result<()> {
        check_confirmation_terminal(io::stdin().is_terminal(), option)
    }

    fn confirm(&mut self, prompt: &str) -> anyhow::Result<bool> {
        self.confirm_with_option(prompt, "--yes")
    }

    fn confirm_with_option(&mut self, prompt: &str, option: &str) -> anyhow::Result<bool> {
        self.ensure_confirmation_available(option)?;

        // Read the reply from the controlling terminal (CONIN$ on Windows) instead of the
        // inherited stdin handle. std's buffered stdin read_line can hang under ConPTY
        // (Windows Terminal / PowerShell), whereas rprompt opens the console device
        // directly. On Windows also prepare line input: Ctrl+C can terminate a previous
        // password reader before it restores the console's raw/no-echo input mode.
        confirmation_from_reply(prompt_reply(prompt), option)
    }

    fn password(&mut self, prompt: &str) -> anyhow::Result<String> {
        rpassword::prompt_password(prompt).map_err(|error| {
            let detail = crate::output::redact_secrets(&error.to_string());
            anyhow::Error::new(error).context(format!(
                "cannot read password from the terminal: {detail}; run in an interactive terminal, or pipe the password from a secret manager and pass --password-stdin"
            ))
        })
    }

    fn password_stdin(&mut self) -> anyhow::Result<String> {
        let stdin = io::stdin();
        read_redirected_password(stdin.is_terminal(), || {
            let mut input = stdin.lock();
            password_from_reader(&mut input)
        })
    }
}

#[cfg(windows)]
mod windows_confirmation {
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
        ENABLE_VIRTUAL_TERMINAL_INPUT, GetConsoleMode, SetConsoleMode,
    };

    struct ConsoleInputMode {
        input: File,
        original: Option<u32>,
    }

    impl ConsoleInputMode {
        fn line_input() -> io::Result<Self> {
            let input = OpenOptions::new().read(true).write(true).open("CONIN$")?;
            let mut original = 0;
            // SAFETY: input owns a live console handle and original is a writable DWORD.
            if unsafe { GetConsoleMode(input.as_raw_handle(), &mut original) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let mode = Self {
                input,
                original: Some(original),
            };
            let line_input =
                (original | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT)
                    & !ENABLE_VIRTUAL_TERMINAL_INPUT;
            // SAFETY: mode owns the console handle until restoration and close.
            if unsafe { SetConsoleMode(mode.input.as_raw_handle(), line_input) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(mode)
        }

        fn restore(&mut self) -> io::Result<()> {
            if let Some(original) = self.original {
                // SAFETY: input remains open and original came from GetConsoleMode.
                if unsafe { SetConsoleMode(self.input.as_raw_handle(), original) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                self.original = None;
            }
            Ok(())
        }
    }

    impl Drop for ConsoleInputMode {
        fn drop(&mut self) {
            // Also restore on unwinding; normal completion reports restoration failures.
            let _ = self.restore();
        }
    }

    pub(super) fn prompt_reply(prompt: &str) -> io::Result<String> {
        let mut mode = ConsoleInputMode::line_input()?;
        let reply = rprompt::prompt_reply(prompt);
        let restored = mode.restore();
        // Preserve the original read error when both reading and restoration fail.
        reply.and_then(|answer| restored.map(|()| answer))
    }
}

fn check_confirmation_terminal(interactive: bool, option: &str) -> anyhow::Result<()> {
    if !interactive {
        return Err(anyhow::anyhow!(
            "confirmation requires an interactive terminal; rerun with {option} to confirm"
        ));
    }
    Ok(())
}

fn is_affirmative(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn confirmation_from_reply(reply: io::Result<String>, option: &str) -> anyhow::Result<bool> {
    let answer = reply.map_err(|error| {
        let detail = crate::output::redact_secrets(&error.to_string());
        anyhow::Error::new(error).context(format!(
            "cannot read confirmation from the terminal: {detail}; use an interactive terminal, or if you intend to confirm this action, rerun with {option}"
        ))
    })?;
    Ok(is_affirmative(&answer))
}

/// Testable mirror of `TerminalPrompter::confirm`. Production reads the console device
/// directly via `rprompt::prompt_reply`; this exercises the interactive gate and answer
/// parsing against an injected reader/writer. An EOF reply (no trailing newline) is rejected.
#[cfg(test)]
fn confirm_from_reader<R, W>(
    prompt: &str,
    input: &mut R,
    output: &mut W,
    interactive: bool,
) -> anyhow::Result<bool>
where
    R: BufRead,
    W: Write,
{
    check_confirmation_terminal(interactive, "--yes")?;

    confirmation_from_reply(
        rprompt::prompt_reply_from_bufread(input, output, prompt),
        "--yes",
    )
}

fn password_from_reader<R>(input: &mut R) -> anyhow::Result<String>
where
    R: Read,
{
    let mut password = String::new();
    input.read_to_string(&mut password)?;

    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }

    if password.is_empty() {
        return Err(anyhow::anyhow!("password cannot be empty"));
    }

    Ok(password)
}

fn read_redirected_password(
    interactive: bool,
    read: impl FnOnce() -> anyhow::Result<String>,
) -> anyhow::Result<String> {
    if interactive {
        return Err(anyhow::anyhow!(
            "--password-stdin requires redirected input; stdin is a terminal. Omit --password-stdin for hidden terminal input, or pipe/redirect the password from a secret manager. Never put passwords in arguments"
        ));
    }
    read()
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    #[test]
    fn confirmation_read_failure_keeps_io_source_and_the_action_specific_option() {
        for option in ["--yes", "--force"] {
            let source = std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "terminal reply ended; token=fixture-marker",
            );
            let error = super::confirmation_from_reply(Err(source), option).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("cannot read confirmation from the terminal")
                    && error.to_string().contains(option)
            );
            assert!(!error.to_string().contains("fixture-marker"));
            assert!(error.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::UnexpectedEof)
            }));
        }
        assert!(!super::confirmation_from_reply(Ok("no".into()), "--yes").unwrap());
        assert!(super::confirmation_from_reply(Ok("YES\n".into()), "--force").unwrap());
    }

    #[test]
    fn trust_readiness_uses_the_same_terminal_gate_without_prompting() {
        for option in ["--yes", "--force"] {
            assert!(super::check_confirmation_terminal(true, option).is_ok());
            let error = super::check_confirmation_terminal(false, option).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "confirmation requires an interactive terminal; rerun with {option} to confirm"
                )
            );
        }
    }

    #[test]
    fn local_stdin_terminal_gate_rejects_before_reading_and_keeps_redirected_data() {
        let error =
            super::read_redirected_password(true, || panic!("terminal input must not be read"))
                .unwrap_err();
        assert!(
            error.to_string().contains("stdin is a terminal")
                && error.to_string().contains("hidden terminal input")
                && error.to_string().contains("pipe/redirect")
        );
        let mut source = Cursor::new(b"line-one\nline-two\r\n");
        let password =
            super::read_redirected_password(false, || super::password_from_reader(&mut source))
                .unwrap();
        assert_eq!(password, "line-one\nline-two");
    }

    #[test]
    fn confirm_from_reader_rejects_non_interactive_stdin() {
        let mut input = Cursor::new(b"yes\n");
        let mut output = Vec::new();

        let err =
            super::confirm_from_reader("confirm? ", &mut input, &mut output, false).unwrap_err();

        assert!(err.to_string().contains("interactive terminal"));
    }

    #[test]
    fn confirm_from_reader_rejects_eof() {
        let mut input = Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();

        let result = super::confirm_from_reader("confirm? ", &mut input, &mut output, true);

        assert!(result.is_err());
    }

    #[test]
    fn confirm_from_reader_accepts_yes_only() {
        let mut yes = Cursor::new(b"yes\n");
        let mut no = Cursor::new(b"no\n");
        let mut output = Vec::new();

        assert!(super::confirm_from_reader("confirm? ", &mut yes, &mut output, true).unwrap());
        assert!(!super::confirm_from_reader("confirm? ", &mut no, &mut output, true).unwrap());
    }

    #[test]
    fn password_from_reader_strips_one_final_lf() {
        let mut input = Cursor::new(b"secret\n");

        let password = super::password_from_reader(&mut input).unwrap();

        assert_eq!(password, "secret");
    }

    #[test]
    fn password_from_reader_strips_one_final_crlf() {
        let mut input = Cursor::new(b"secret\r\n");

        let password = super::password_from_reader(&mut input).unwrap();

        assert_eq!(password, "secret");
    }

    #[test]
    fn password_from_reader_preserves_embedded_newline() {
        let mut input = Cursor::new(b"line-one\nline-two\n");

        let password = super::password_from_reader(&mut input).unwrap();

        assert_eq!(password, "line-one\nline-two");
    }

    #[test]
    fn password_from_reader_rejects_empty_after_trimming_final_newline() {
        let mut input = Cursor::new(b"\n");

        let err = super::password_from_reader(&mut input).unwrap_err();

        assert!(err.to_string().contains("password cannot be empty"));
    }
}
