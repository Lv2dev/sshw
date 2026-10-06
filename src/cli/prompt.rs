use std::io::{self, IsTerminal, Read};
#[cfg(test)]
use std::io::{BufRead, Write};

pub trait Prompter {
    fn confirm(&mut self, prompt: &str) -> anyhow::Result<bool>;
    fn confirm_with_option(&mut self, prompt: &str, _option: &str) -> anyhow::Result<bool> {
        self.confirm(prompt)
    }
    fn password(&mut self, prompt: &str) -> anyhow::Result<String>;
    fn password_stdin(&mut self) -> anyhow::Result<String>;
}

pub(crate) struct TerminalPrompter;

impl Prompter for TerminalPrompter {
    fn confirm(&mut self, prompt: &str) -> anyhow::Result<bool> {
        self.confirm_with_option(prompt, "--yes")
    }

    fn confirm_with_option(&mut self, prompt: &str, option: &str) -> anyhow::Result<bool> {
        if !io::stdin().is_terminal() {
            return Err(anyhow::anyhow!(
                "confirmation requires an interactive terminal; rerun with {option} to confirm"
            ));
        }

        // Read the reply from the controlling terminal (CONIN$ on Windows) instead of the
        // inherited stdin handle. std's buffered stdin read_line can hang under ConPTY
        // (Windows Terminal / PowerShell), whereas rprompt opens the console device
        // directly, the same way rpassword does for the password prompt.
        let answer = rprompt::prompt_reply(prompt)?;
        Ok(is_affirmative(&answer))
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

fn is_affirmative(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
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
    if !interactive {
        return Err(anyhow::anyhow!(
            "confirmation requires an interactive terminal; rerun with --yes to confirm"
        ));
    }

    let answer = rprompt::prompt_reply_from_bufread(input, output, prompt)?;
    Ok(is_affirmative(&answer))
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
