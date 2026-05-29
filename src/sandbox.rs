use crate::policy::PolicyRules;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxDecision {
    Allow,
    Deny { reason: String },
}

/// Authorization layer for remote operations. The initial backends provide no
/// OS-level isolation; stronger per-OS sandbox backends are a future extension
/// point behind this same trait.
pub trait Sandbox {
    fn check_command(&self, command: &str) -> SandboxDecision;
    fn check_put(&self, remote_path: &str) -> SandboxDecision;
    fn check_get(&self, remote_path: &str) -> SandboxDecision;
}

/// No sandboxing: every operation is allowed. Used when policy is disabled.
pub struct NoopSandbox;

impl Sandbox for NoopSandbox {
    fn check_command(&self, _command: &str) -> SandboxDecision {
        SandboxDecision::Allow
    }

    fn check_put(&self, _remote_path: &str) -> SandboxDecision {
        SandboxDecision::Allow
    }

    fn check_get(&self, _remote_path: &str) -> SandboxDecision {
        SandboxDecision::Allow
    }
}

/// Enforces policy allowlists but provides no OS-level isolation.
pub struct PolicyOnlySandbox {
    rules: PolicyRules,
}

impl PolicyOnlySandbox {
    pub fn new(rules: PolicyRules) -> Self {
        Self { rules }
    }
}

impl Sandbox for PolicyOnlySandbox {
    fn check_command(&self, command: &str) -> SandboxDecision {
        if self.rules.allows_command(command) {
            SandboxDecision::Allow
        } else {
            SandboxDecision::Deny {
                reason: format!("command blocked by policy: '{command}' is not in the allowlist"),
            }
        }
    }

    fn check_put(&self, remote_path: &str) -> SandboxDecision {
        if self.rules.allows_put(remote_path) {
            SandboxDecision::Allow
        } else {
            SandboxDecision::Deny {
                reason: format!(
                    "upload blocked by policy: '{remote_path}' is not in the allowed paths"
                ),
            }
        }
    }

    fn check_get(&self, remote_path: &str) -> SandboxDecision {
        if self.rules.allows_get(remote_path) {
            SandboxDecision::Allow
        } else {
            SandboxDecision::Deny {
                reason: format!(
                    "download blocked by policy: '{remote_path}' is not in the allowed paths"
                ),
            }
        }
    }
}
