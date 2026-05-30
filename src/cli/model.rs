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
            Self::Add(_)
            | Self::Default(_)
            | Self::Trust(_)
            | Self::Put(_)
            | Self::Get(_)
            | Self::Remove(_) => false,
        }
    }
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
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct PutArgs {
    #[arg(value_name = "TARGET", num_args = 2..=3)]
    pub target: Vec<String>,
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct GetArgs {
    #[arg(value_name = "TARGET", num_args = 2..=3)]
    pub target: Vec<String>,
    #[arg(long)]
    pub yes: bool,
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
