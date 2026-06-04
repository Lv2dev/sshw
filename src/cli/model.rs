use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "sshw",
    version,
    about = "Operate configured SSH servers without exposing secrets"
)]
pub struct Cli {
    /// Use an explicit sshw home directory for this invocation (config,
    /// known_hosts, policy, audit). Overrides `SSHW_HOME` and `--profile`.
    #[arg(long, global = true, value_name = "PATH")]
    pub home: Option<PathBuf>,
    /// Select a registered profile by name (see `sshw profile`). Cannot be
    /// combined with `--home`.
    #[arg(long, global = true, value_name = "NAME")]
    pub profile: Option<String>,
    /// Enforce the active home's policy.json for this invocation. Off by
    /// default; fails closed if the policy file is missing or invalid.
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
    Add(AddArgs),
    List(ListArgs),
    Show(ShowArgs),
    Default(DefaultArgs),
    Trust(TrustArgs),
    Run(RunArgs),
    Put(PutArgs),
    Get(GetArgs),
    Remove(RemoveArgs),
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
                PrivilegeCommand::Set(_) | PrivilegeCommand::Clear(_) => false,
            },
            Self::Put(args) => args.json,
            Self::Get(args) => args.json,
            Self::Add(_) | Self::Default(_) | Self::Trust(_) | Self::Remove(_) => false,
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
    /// Privilege method. Both execute via `run --as-root`: `sudo` uses
    /// `sudo -S` (password over stdin); `su` uses a PTY and injects the password
    /// at the prompt (more environment-sensitive).
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PrivilegeMethodArg {
    Sudo,
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
    List(ProfileListArgs),
    Show(ProfileShowArgs),
    Default(ProfileDefaultArgs),
    Remove(ProfileRemoveArgs),
}

#[derive(Debug, Args)]
pub struct ProfileAddArgs {
    pub name: String,
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct ProfileListArgs {
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ProfileShowArgs {
    pub name: String,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ProfileDefaultArgs {
    pub name: String,
}

#[derive(Debug, Args)]
pub struct ProfileRemoveArgs {
    pub name: String,
}

#[derive(Debug, Args)]
pub struct AddArgs {
    pub name: String,
    #[arg(long)]
    pub host: String,
    #[arg(long)]
    pub port: u16,
    #[arg(long)]
    pub user: String,
    #[arg(long, value_enum, default_value_t = AuthArg::Password)]
    pub auth: AuthArg,
    #[arg(long)]
    pub force: bool,
    #[arg(long)]
    pub password_stdin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AuthArg {
    Password,
    Agent,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ShowArgs {
    pub name: String,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct DefaultArgs {
    pub name: Option<String>,
}

#[derive(Debug, Args)]
pub struct TrustArgs {
    pub name: String,
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    #[arg(value_name = "TARGET", num_args = 1..=2)]
    pub target: Vec<String>,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
    /// Confirm safety-sensitive commands non-interactively.
    #[arg(long)]
    pub yes: bool,
    /// Run through the server's configured sudo privilege path. Requires
    /// `--yes`; never automatic. With NOPASSWD sudoers the command runs even if
    /// the stored password is wrong, since sudo does not consume it.
    #[arg(long)]
    pub as_root: bool,
}

#[derive(Debug, Args)]
pub struct PutArgs {
    #[arg(value_name = "TARGET", num_args = 2..=3)]
    pub target: Vec<String>,
    #[arg(long)]
    pub yes: bool,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct GetArgs {
    #[arg(value_name = "TARGET", num_args = 2..=3)]
    pub target: Vec<String>,
    #[arg(long)]
    pub yes: bool,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    pub name: String,
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    #[arg(long)]
    pub json: bool,
}
