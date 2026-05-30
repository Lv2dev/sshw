use std::io::{self, BufRead, IsTerminal, Write};

pub trait Prompter {
    fn confirm(&mut self, prompt: &str) -> anyhow::Result<bool>;
    fn password(&mut self, prompt: &str) -> anyhow::Result<String>;
}

pub(crate) struct TerminalPrompter;

impl Prompter for TerminalPrompter {
    fn confirm(&mut self, prompt: &str) -> anyhow::Result<bool> {
        let stdin = io::stdin();
        let interactive = stdin.is_terminal();
        let mut input = stdin.lock();
        let mut output = io::stderr();

        confirm_from_reader(prompt, &mut input, &mut output, interactive)
    }

    fn password(&mut self, prompt: &str) -> anyhow::Result<String> {
        Ok(rpassword::prompt_password(prompt)?)
    }
}

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

    write!(output, "{prompt}")?;
    output.flush()?;

    let mut answer = String::new();
    let bytes_read = input.read_line(&mut answer)?;
    if bytes_read == 0 {
        return Err(anyhow::anyhow!(
            "confirmation input ended before a response; rerun with --yes to confirm"
        ));
    }

    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

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

        let err =
            super::confirm_from_reader("confirm? ", &mut input, &mut output, true).unwrap_err();

        assert!(err.to_string().contains("confirmation input ended"));
    }

    #[test]
    fn confirm_from_reader_accepts_yes_only() {
        let mut yes = Cursor::new(b"yes\n");
        let mut no = Cursor::new(b"no\n");
        let mut output = Vec::new();

        assert!(super::confirm_from_reader("confirm? ", &mut yes, &mut output, true).unwrap());
        assert!(!super::confirm_from_reader("confirm? ", &mut no, &mut output, true).unwrap());
    }
}
