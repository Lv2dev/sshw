use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Long-form help appended after the usage/options, shown only by `--help`
/// (not the short `-h`). It exists so an agent can learn the full security
/// model, the stable exit-code contract, the `--json` envelope, and example
/// invocations from `sshw --help` alone. Every claim here is verified against
/// the code: the exit codes mirror `output::ErrorKind::exit_code` and
/// `output::REMOTE_NONZERO_EXIT_CODE`; the `--json` subcommand list mirrors
/// `Command::wants_json_errors`.
const AFTER_LONG_HELP: &str = r#"SECURITY MODEL:
  sshw is a sandbox-aware SSH wrapper, not a strong OS sandbox; running `sshw
  run` grants the configured account's server authority.
  - Secrets (SSH passwords, privilege passwords, keys, tokens) are never passed
    on argv and never stored in config files. Password and privilege passwords
    live only in the OS credential store, or opt-in in a session-only in-memory
    backend selected by `credential_backend: session_only` in servers.json and
    fed via SSHW_PASSWORD. There is intentionally no `--password <value>`.
  - SSH host keys are verified fail-closed: an unknown or changed key is never
    accepted silently. Approve a host with `sshw trust <name>` before `run`/
    `put`/`get` can connect.
  - The policy allowlist and the safety rails gate dangerous commands and
    writes; both fail closed. Policy enforcement is on when `--policy` is passed
    or when policy.json sets `enabled: true`. Output and audit redaction are
    best-effort.

HOME SELECTION:
  Home resolution order is `--home`, `SSHW_HOME`, then `--profile <name>`.
  The `--profile` selection is after SSHW_HOME and before the registry default
  profile, followed by the app default.

EXIT CODES (stable; sshw's own operational failures):
  0  success
  1  unknown   failure not matched to a stable category
  2  safety    a safety rail blocked the operation (usually needs --yes)
  3  config    config/registry/profile missing, invalid, or unknown entry
  4  auth      credential lookup or authentication setup failed
  5  ssh       SSH connect, host key, known_hosts, session, or transfer failed
  6  io        local file or filesystem handling failed
  7  policy    a policy allowlist denied the operation, or policy failed closed
  9  usage     invalid CLI arguments, detected before any command runs
  8  is separate: a `run` that connected but whose REMOTE command exited
     non-zero exits 8, so a remote status is never mistaken for an sshw failure.
     The real remote status is in `run --json` (`exit_status`).
  sudo password rejection is reported as the remote command's non-zero status (exit 8).
  su prompt/auth failure maps to auth (exit 4) before completion.

JSON OUTPUT:
  `--json` is accepted by: add, list, show, trust, run, put, get, remove,
  doctor, profile list, profile show, privilege set/show/clear.
  default/profile state changes have no --json.
  Success (single object) carries `"ok":true`, e.g.:
    run:      {"ok":true,"server":"web","command":"uptime","exit_status":0,...}
    put/get:  {"ok":true,"server":"web","local":"./app","remote":"/srv/app","bytes":1234}
    change:   {"ok":true,"action":"added","server":"web"}
  list / profile list return a JSON array on success (no wrapping object).
  Failure (any --json command, including usage errors) uses one envelope:
    {"ok":false,"error":{"kind":"config","message":"unknown server 'x'","exit_code":3}}
  `kind` is one of safety/config/auth/ssh/io/policy/usage/unknown (see EXIT CODES).

AUTOMATION:
  Chain dependent sshw calls with `&&`, not `;`, so a failed upload or trust
  step stops the sequence instead of running the next remote command against
  missing state.
  Exit 5 with a key-exchange or handshake message means SSH setup failed before
  the command ran. Example: `Unable to exchange encryption keys`.
  If this appears during rapid repeated connections, wait briefly and retry from
  the failed step. Retry earlier successful steps only when they are idempotent
  and safe to repeat. If it fails again, inspect network, server, and host trust
  state before retrying.

EXAMPLES:
  sshw add web --host 192.0.2.10 --port 22 --user deploy   # password auth (prompts)
  secret-read web | sshw add web --host 192.0.2.10 --port 22 --user deploy --password-stdin
  sshw trust web                                           # approve the host key
  sshw run web "uptime" --json                             # run a command, JSON out
  sshw run web "systemctl restart app" --as-root --yes     # privileged (needs --yes)
  sshw put web ./app /srv/app/app                          # upload [server] <local> <remote>
  sshw get web /var/log/app.log ./app.log                  # download [server] <remote> <local>
"#;

#[derive(Debug, Parser)]
#[command(
    name = "sshw",
    version,
    about = "Operate configured SSH servers without exposing secrets",
    after_long_help = AFTER_LONG_HELP
)]
pub struct Cli {
    /// Use an explicit sshw home directory for this invocation (config,
    /// known_hosts, policy, audit). Overrides `SSHW_HOME`; cannot be combined
    /// with `--profile`.
    #[arg(long, global = true, value_name = "PATH")]
    pub home: Option<PathBuf>,
    /// Select a registered profile by name after SSHW_HOME and before the
    /// registry default (see `sshw profile`). Cannot be combined with `--home`.
    #[arg(long, global = true, value_name = "NAME")]
    pub profile: Option<String>,
    /// Force policy.json enforcement for this invocation. Enforcement is also
    /// on automatically when policy.json sets `enabled: true`. Fails closed if
    /// requested but the file is missing; an invalid policy file always fails
    /// closed.
    #[arg(long, global = true)]
    pub policy: bool,
    /// Inactivity timeout in seconds for remote operations (run/put/get) after
    /// the connection is established. 0 means no timeout. Connection setup
    /// always uses a fixed timeout. Default: no operation timeout.
    #[arg(long, global = true, value_name = "SECONDS")]
    pub timeout: Option<u64>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Register or update a server (metadata only; secrets go to the credential store).
    Add(AddArgs),
    /// List configured servers (credential keys shown, secrets never).
    List(ListArgs),
    /// Show one server's configuration (no secrets).
    Show(ShowArgs),
    /// Show or set the default server used when a name is omitted.
    Default(DefaultArgs),
    /// Approve a server's SSH host key into known_hosts (required before connecting).
    Trust(TrustArgs),
    /// Run a remote command over SSH and return its output.
    Run(RunArgs),
    /// Upload a local file to a server over SCP.
    Put(PutArgs),
    /// Download a remote file from a server over SCP.
    Get(GetArgs),
    /// Remove a server, its stored credential, and any privilege metadata.
    Remove(RemoveArgs),
    /// Report the resolved home, paths, native library, and credential health.
    Doctor(DoctorArgs),
    /// Manage privilege escalation credentials for a configured server.
    Privilege(PrivilegeArgs),
    /// Manage named sshw profiles (each maps a name to a home directory).
    Profile(ProfileArgs),
}

impl Command {
    pub(crate) fn wants_json_errors(&self) -> bool {
        match self {
            Self::List(args) => args.json,
            Self::Show(args) => args.json,
            Self::Run(args) => args.json,
            Self::Doctor(args) => args.json,
            Self::Profile(args) => match &args.command {
                ProfileCommand::List(a) => a.json,
                ProfileCommand::Show(a) => a.json,
                ProfileCommand::Add(_) | ProfileCommand::Default(_) | ProfileCommand::Remove(_) => {
                    false
                }
            },
            Self::Privilege(args) => match &args.command {
                PrivilegeCommand::Show(a) => a.json,
                PrivilegeCommand::Set(a) => a.json,
                PrivilegeCommand::Clear(a) => a.json,
            },
            Self::Put(args) => args.json,
            Self::Get(args) => args.json,
            Self::Add(args) => args.json,
            Self::Trust(args) => args.json,
            Self::Remove(args) => args.json,
            Self::Default(_) => false,
        }
    }
}

#[derive(Debug, Args)]
pub struct PrivilegeArgs {
    #[command(subcommand)]
    pub command: PrivilegeCommand,
}

#[derive(Debug, Subcommand)]
pub enum PrivilegeCommand {
    /// Store privilege escalation metadata and password for a server.
    Set(PrivilegeSetArgs),
    /// Show privilege metadata without revealing the password.
    Show(PrivilegeShowArgs),
    /// Remove privilege metadata and delete the stored privilege password.
    Clear(PrivilegeClearArgs),
}

#[derive(Debug, Args)]
pub struct PrivilegeSetArgs {
    /// Server name to configure.
    pub name: String,
    /// Privilege method used by `run --as-root`; see possible values below.
    /// Default: sudo.
    #[arg(long, value_enum, default_value_t = PrivilegeMethodArg::Sudo)]
    pub method: PrivilegeMethodArg,
    /// Target privileged user.
    #[arg(long, default_value = "root")]
    pub user: String,
    /// Read the privilege password from stdin instead of a hidden prompt.
    #[arg(long)]
    pub password_stdin: bool,
    /// Overwrite an existing privilege configuration without prompting.
    #[arg(long)]
    pub force: bool,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct PrivilegeShowArgs {
    /// Server name to inspect.
    pub name: String,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct PrivilegeClearArgs {
    /// Server name to clear.
    pub name: String,
    /// Confirm removal non-interactively.
    #[arg(long)]
    pub yes: bool,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PrivilegeMethodArg {
    /// `sudo -S` with the password fed over SSH channel stdin (default).
    Sudo,
    /// `su` over a PTY, injecting the password at the prompt; more
    /// environment-sensitive and fails closed on an unrecognized prompt.
    Su,
}

#[derive(Debug, Args)]
pub struct ProfileArgs {
    #[command(subcommand)]
    pub command: ProfileCommand,
}

#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// Register a profile. The home directory is taken from the global
    /// `--home <path>` flag, e.g. `sshw profile add prod --home /srv/prod`.
    Add(ProfileAddArgs),
    /// List registered profiles and which one is the default.
    List(ProfileListArgs),
    /// Show one profile's id and home path.
    Show(ProfileShowArgs),
    /// Set the default profile used when neither --home nor --profile is given.
    Default(ProfileDefaultArgs),
    /// Remove a profile registry entry (leaves its home dir and credentials intact).
    Remove(ProfileRemoveArgs),
}

#[derive(Debug, Args)]
pub struct ProfileAddArgs {
    /// Profile name to register. Its home is taken from the global --home flag.
    pub name: String,
    /// Overwrite an existing profile entry without confirmation.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct ProfileListArgs {
    /// Emit a JSON array instead of human text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ProfileShowArgs {
    /// Profile name to inspect.
    pub name: String,
    /// Emit JSON instead of human text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ProfileDefaultArgs {
    /// Profile name to make the default.
    pub name: String,
}

#[derive(Debug, Args)]
pub struct ProfileRemoveArgs {
    /// Profile name to remove from the registry.
    pub name: String,
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// Server name (the alias used by run/put/get/trust).
    pub name: String,
    /// Hostname or IP address to connect to.
    #[arg(long)]
    pub host: String,
    /// TCP port of the SSH server.
    #[arg(long)]
    pub port: u16,
    /// Remote username to log in as.
    #[arg(long)]
    pub user: String,
    /// Authentication method (default: password).
    #[arg(long, value_enum, default_value_t = AuthArg::Password)]
    pub auth: AuthArg,
    /// Overwrite an existing server without the confirmation prompt (needed for
    /// non-interactive/agent use).
    #[arg(long)]
    pub force: bool,
    /// Read the password from stdin once instead of a hidden prompt. Password
    /// auth only; there is no `--password <value>` flag.
    #[arg(long)]
    pub password_stdin: bool,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AuthArg {
    /// Password auth; the password is stored in the credential backend, never in config.
    Password,
    /// SSH agent auth; stores no secret and uses the active SSH agent.
    Agent,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// Emit a JSON array instead of human text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ShowArgs {
    /// Server name to show.
    pub name: String,
    /// Emit JSON instead of human text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct DefaultArgs {
    /// Server name to set as default; omit to print the current default.
    pub name: Option<String>,
}

#[derive(Debug, Args)]
pub struct TrustArgs {
    /// Server whose host key to fetch, display, and approve into known_hosts.
    pub name: String,
    /// Skip the interactive fingerprint confirmation (still re-verifies before writing).
    #[arg(long)]
    pub yes: bool,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Grammar: `[server] <command>`. With one value it is the command and the
    /// default server is used; with two, the first is the server name. Quote
    /// the command so it stays one argument.
    #[arg(value_name = "TARGET", num_args = 1..=2)]
    pub target: Vec<String>,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
    /// Confirm safety-sensitive commands non-interactively.
    #[arg(long)]
    pub yes: bool,
    /// Run through the server's configured privilege path (`sshw privilege
    /// set`). Requires `--yes`; never automatic. Uses the stored method (`sudo`
    /// or `su`); with NOPASSWD sudoers the command runs even if the stored
    /// password is wrong, since sudo does not consume it. A sudo password
    /// rejection reports the remote command's non-zero status (exit 8), while
    /// a su prompt/auth failure maps to auth (exit 4).
    #[arg(long)]
    pub as_root: bool,
}

#[derive(Debug, Args)]
pub struct PutArgs {
    /// Grammar: `[server] <local> <remote>`. With two values the default server
    /// is used; with three, the first is the server name.
    #[arg(value_name = "TARGET", num_args = 2..=3)]
    pub target: Vec<String>,
    /// Confirm writes to system paths non-interactively.
    #[arg(long)]
    pub yes: bool,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct GetArgs {
    /// Grammar: `[server] <remote> <local>`. With two values the default server
    /// is used; with three, the first is the server name.
    #[arg(value_name = "TARGET", num_args = 2..=3)]
    pub target: Vec<String>,
    /// Confirm overwriting an existing local file non-interactively.
    #[arg(long)]
    pub yes: bool,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// Server name to remove.
    pub name: String,
    /// Confirm removal non-interactively.
    #[arg(long)]
    pub yes: bool,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Emit JSON instead of human text.
    #[arg(long)]
    pub json: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// `sshw --help` must be self-sufficient for an agent: it has to carry the
    /// security model, the stable exit-code table, the `--json` envelope, and
    /// examples, and every subcommand must have a non-empty about line. This
    /// fails closed if any section header or a representative command's about
    /// is dropped, so the help can never silently regress to bare flags.
    #[test]
    fn long_help_documents_security_exit_codes_json_and_examples() {
        let help = Cli::command().render_long_help().to_string();
        let normalized_help = help.split_whitespace().collect::<Vec<_>>().join(" ");

        for marker in [
            "SECURITY MODEL:",
            "EXIT CODES",
            "sshw trust",
            "JSON OUTPUT:",
            "`--json` is accepted by: add, list, show, trust, run, put, get, remove,",
            "doctor, profile list, profile show, privilege set/show/clear.",
            "default/profile state changes have no --json.",
            "after SSHW_HOME and before the registry default",
            "sudo password rejection is reported as the remote command's non-zero status",
            "su prompt/auth failure maps to auth",
            "change:   {\"ok\":true,\"action\":\"added\",\"server\":\"web\"}",
            "{\"ok\":false,\"error\":",
            "EXAMPLES:",
            "AUTOMATION:",
            "Chain dependent sshw calls with `&&`, not `;`",
            "Exit 5",
            "key-exchange or handshake",
            "Unable to exchange encryption keys",
            "rapid repeated connections",
            "idempotent",
            "safe to repeat",
            "inspect network, server, and host trust",
            // Spot-check exact codes so a future renumber cannot pass silently.
            "0  success",
            "1  unknown",
            "2  safety",
            "3  config",
            "4  auth",
            "5  ssh",
            "6  io",
            "7  policy",
            "8  is separate",
            "9  usage",
        ] {
            assert!(
                help.contains(marker),
                "long help is missing the {marker:?} section/marker"
            );
        }

        for marker in [
            "Exit 5 with a key-exchange or handshake message means SSH setup failed before the command ran",
            "If this appears during rapid repeated connections, wait briefly and retry from the failed step",
            "Retry earlier successful steps only when they are idempotent and safe to repeat",
            "If it fails again, inspect network, server, and host trust state before retrying",
        ] {
            assert!(
                normalized_help.contains(marker),
                "long help is missing the {marker:?} normalized automation guidance"
            );
        }
    }

    /// Every subcommand must surface a non-empty about line so an agent reading
    /// `--help` sees what each command does. Checks the top-level commands and
    /// the nested profile/privilege subcommands.
    #[test]
    fn every_subcommand_has_a_non_empty_about() {
        fn assert_abouts(cmd: &clap::Command) {
            for sub in cmd.get_subcommands() {
                let about = sub.get_about().map(|a| a.to_string()).unwrap_or_default();
                assert!(
                    !about.trim().is_empty(),
                    "subcommand `{}` is missing an about line",
                    sub.get_name()
                );
                assert_abouts(sub);
            }
        }

        let cmd = Cli::command();
        assert_abouts(&cmd);

        // Representative spot-checks so the recursive walk above cannot be
        // weakened into a no-op without failing.
        for name in ["run", "put", "get", "trust", "add", "doctor"] {
            let sub = cmd
                .get_subcommands()
                .find(|c| c.get_name() == name)
                .unwrap_or_else(|| panic!("missing `{name}` subcommand"));
            assert!(
                !sub.get_about()
                    .map(|a| a.to_string())
                    .unwrap_or_default()
                    .is_empty(),
                "`{name}` about must be non-empty"
            );
        }
    }
}
