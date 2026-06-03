use crate::policy::path_within;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyDecision {
    Allow,
    Block { reason: String },
}

pub fn classify_command(command: &str, yes: bool) -> SafetyDecision {
    if yes {
        return SafetyDecision::Allow;
    }

    let lowered = command.to_ascii_lowercase();
    let tokens = shellish_tokens(&lowered);

    if has_rm_recursive_force(&tokens) {
        return SafetyDecision::Block {
            reason: "recursive force delete requires --yes".to_string(),
        };
    }

    if tokens.iter().any(|token| command_name_is(token, "sudo")) {
        return SafetyDecision::Block {
            reason: "sudo requires --yes".to_string(),
        };
    }

    if has_recursive_command(&tokens, "chmod") {
        return SafetyDecision::Block {
            reason: "recursive chmod requires --yes".to_string(),
        };
    }

    if has_recursive_command(&tokens, "chown") {
        return SafetyDecision::Block {
            reason: "recursive chown requires --yes".to_string(),
        };
    }

    if has_adjacent_tokens(&tokens, "pm2", "delete") {
        return SafetyDecision::Block {
            reason: "pm2 delete requires --yes".to_string(),
        };
    }

    if writes_to_etc(&lowered) {
        return SafetyDecision::Block {
            reason: "writing to /etc requires --yes".to_string(),
        };
    }

    SafetyDecision::Allow
}

pub fn classify_remote_write_path(path: &str, yes: bool) -> SafetyDecision {
    if yes {
        return SafetyDecision::Allow;
    }

    let system_paths = [
        "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/root",
    ];
    if system_paths
        .iter()
        .any(|system_path| path_within(system_path, path))
    {
        return SafetyDecision::Block {
            reason: format!("writing to {path} requires --yes"),
        };
    }

    SafetyDecision::Allow
}

fn writes_to_etc(command: &str) -> bool {
    let tokens = shellish_tokens(command);
    let redirects_to_etc = tokens
        .windows(2)
        .any(|window| matches!(window[0].as_str(), ">" | ">>") && is_etc_path(&window[1]))
        || tokens
            .windows(3)
            .any(|window| window[0] == ">" && window[1] == ">" && is_etc_path(&window[2]));
    let tools_write_to_etc = command_targets_etc(&tokens, "tee")
        || command_targets_etc(&tokens, "cp")
        || command_targets_etc(&tokens, "mv")
        || command_targets_etc(&tokens, "install")
        || dd_writes_to_etc(&tokens);

    redirects_to_etc || tools_write_to_etc
}

fn shellish_tokens(command: &str) -> Vec<String> {
    let mut normalized = String::with_capacity(command.len() + 8);
    for ch in command.chars() {
        match ch {
            '>' => {
                normalized.push(' ');
                normalized.push('>');
                normalized.push(' ');
            }
            '&' | '|' | ';' | '(' | ')' => normalized.push(' '),
            _ => normalized.push(ch),
        }
    }

    normalized
        .split_whitespace()
        .map(|token| token.trim_matches(|ch| ch == '\'' || ch == '"').to_string())
        .filter(|token| !token.is_empty())
        .collect()
}

fn has_rm_recursive_force(tokens: &[String]) -> bool {
    tokens.iter().enumerate().any(|(index, token)| {
        command_name_is(token, "rm") && {
            let mut recursive = false;
            let mut force = false;
            for arg in tokens.iter().skip(index + 1) {
                if !arg.starts_with('-') {
                    continue;
                }
                recursive |=
                    has_short_flag(arg, 'r') || has_short_flag(arg, 'R') || arg == "--recursive";
                force |= has_short_flag(arg, 'f') || arg == "--force";
            }
            recursive && force
        }
    })
}

fn has_recursive_command(tokens: &[String], command: &str) -> bool {
    tokens.iter().enumerate().any(|(index, token)| {
        command_name_is(token, command)
            && tokens.iter().skip(index + 1).any(|arg| {
                has_short_flag(arg, 'r') || has_short_flag(arg, 'R') || arg == "--recursive"
            })
    })
}

fn has_short_flag(arg: &str, flag: char) -> bool {
    arg.starts_with('-') && !arg.starts_with("--") && arg.chars().skip(1).any(|ch| ch == flag)
}

fn has_adjacent_tokens(tokens: &[String], first: &str, second: &str) -> bool {
    tokens
        .windows(2)
        .any(|window| command_name_is(&window[0], first) && window[1] == second)
}

fn command_targets_etc(tokens: &[String], command: &str) -> bool {
    tokens.iter().enumerate().any(|(index, token)| {
        command_name_is(token, command) && tokens.iter().skip(index + 1).any(|arg| is_etc_path(arg))
    })
}

fn dd_writes_to_etc(tokens: &[String]) -> bool {
    tokens.iter().enumerate().any(|(index, token)| {
        command_name_is(token, "dd")
            && tokens
                .iter()
                .skip(index + 1)
                .any(|arg| arg.strip_prefix("of=").is_some_and(is_etc_path))
    })
}

fn command_name_is(token: &str, expected: &str) -> bool {
    token
        .rsplit(['/', '\\'])
        .next()
        .is_some_and(|name| name == expected)
}

fn is_etc_path(path: &str) -> bool {
    path_within("/etc", path)
}
