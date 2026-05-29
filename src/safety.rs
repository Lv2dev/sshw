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
    let patterns = [
        ("rm -rf", "recursive force delete requires --yes"),
        ("sudo", "sudo requires --yes"),
        ("chmod -r", "recursive chmod requires --yes"),
        ("chown -r", "recursive chown requires --yes"),
        ("pm2 delete", "pm2 delete requires --yes"),
    ];

    for (pattern, reason) in patterns {
        if lowered.contains(pattern) {
            return SafetyDecision::Block {
                reason: reason.to_string(),
            };
        }
    }

    if writes_to_etc(&lowered) {
        return SafetyDecision::Block {
            reason: "writing to /etc requires --yes".to_string(),
        };
    }

    SafetyDecision::Allow
}

fn writes_to_etc(command: &str) -> bool {
    command.contains("> /etc/")
        || command.contains(">> /etc/")
        || command.contains(">/etc/")
        || command.contains(">>/etc/")
}
