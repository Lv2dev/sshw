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
    backend selected by `credential_backend: session_only` in servers.json.
    Login and privilege secrets are fed separately via SSHW_PASSWORD and
    SSHW_PRIVILEGE_PASSWORD. There is intentionally no `--password <value>`.
  - SSH host keys are verified fail-closed: an unknown or changed key is never
    accepted silently. Approve a host with `sshw trust <name>` before `run`/
    `put`/`get`/`test` can authenticate.
  - The policy allowlist and the safety rails gate dangerous commands and
    writes; both fail closed. A non-default `--user` also requires an exact
    policy v2 allow_accounts entry when policy is enabled. Policy enforcement
    is on when `--policy` is passed or when policy.json sets `enabled: true`.
    Output and audit redaction are best-effort.

HOME SELECTION:
  Use `--home`, `SSHW_HOME`, or `--profile <name>` to select a home.
  An explicit --profile conflicts with SSHW_HOME; unset SSHW_HOME first.
  Otherwise cwd .sshw independently selects local/global servers and policy.
  Missing local resources inherit the registry default profile or app default.
  Local server lists do not merge with global lists; parent folders are not searched.
  Inherited settings are read-only: use --global or project init to select writes.
  --global ignores cwd and SSHW_HOME; --project-dir explicitly selects a project.
  Inspect sources with project status or doctor. project init starts local policy.

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
  `--json` is accepted by: add, list, show, rename, endpoint, trust, run, put, get, remove,
  doctor, default, password, test, all account/profile/policy/project subcommands, and privilege
  set/show/clear. A completed run uses command_succeeded for remote success.
  Success (single object) carries `"ok":true`, e.g.:
    run:      {"ok":true,"server":"web","user":"ops","command":"uptime","exit_status":0,...}
    put/get:  {"ok":true,"server":"web","user":"ops","local":"./app","remote":"/srv/app","bytes":1234}
    change:   {"ok":true,"action":"added","server":"web"}
  list / account list / profile list return a JSON array on success (no wrapping object).
  Failure (any --json command, including usage errors) uses one envelope:
    {"ok":false,"error":{"kind":"config","message":"unknown server 'x'","exit_code":3}}
  `kind` is one of safety/config/auth/ssh/io/policy/usage/unknown (see EXIT CODES).
  An optional `causes` array preserves the redacted error chain when nested
  causes exist; it is omitted when the chain has no additional messages.

AUTOMATION:
  Chain dependent sshw calls with `&&`, not `;`, so a failed upload or trust
  step stops the sequence instead of running the next remote command against
  missing state.
  If retained output exceeds 16 MiB, sshw fails the operation with exit 5; the
  remote command may already have side effects, so do not blindly retry a
  non-idempotent command.
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
  sshw test web --user deploy                              # verify trust and login, no remote command
  sshw rename web production                               # keep accounts, passwords and trust
  sshw endpoint web --port 10022                            # keep accounts; verify the destination key
  sshw password web                                        # update the saved login password
  sshw password web --privilege                            # keep the privilege method and target
  sshw list --filter prod                                  # match a name or host
  sshw doctor web --json                                   # diagnose one registered server
  sshw completions powershell                              # print the Tab completion script
  sshw run web "uptime" --json                             # run a command, JSON out
  sshw account add web ops --auth agent                    # register another login user
  sshw run web "whoami" --user ops                         # select a registered account
  sshw run web "systemctl restart app" --user ops --as-root
  sshw run web "id -u" --as-root --no-password
  sshw policy check web "uptime" --json
  sshw put web ./app /srv/app/app --user ops               # upload [server] <local> <remote>
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
    /// Select a registered profile. Conflicts with --home and a non-empty
    /// SSHW_HOME; unset SSHW_HOME to select a profile explicitly.
    #[arg(long, global = true, value_name = "NAME")]
    pub profile: Option<String>,
    /// Use the registry-default/built-in settings, ignoring cwd .sshw and SSHW_HOME.
    #[arg(long, global = true, conflicts_with_all = ["home", "profile", "project_dir"])]
    pub global: bool,
    /// Select a project directory explicitly; it must contain .sshw. Overrides SSHW_HOME.
    #[arg(long,global=true,value_name="PATH",conflicts_with_all=["home","profile"])]
    pub project_dir: Option<PathBuf>,
    /// Force policy.json enforcement for this invocation. Enforcement is also
    /// on automatically when policy.json sets `enabled: true`. Fails closed if
    /// requested but the file is missing; an invalid policy file always fails
    /// closed.
    #[arg(long, global = true)]
    pub policy: bool,
    /// Absolute timeout in seconds for remote operations (run/put/get) after
    /// the connection is established. Progress does not extend it. 0 disables
    /// the deadline. Default: 900 seconds. Exceeding the 16 MiB combined output
    /// limit fails the operation even if the remote command already ran.
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
    /// Show a server, all login accounts and their privilege settings (no secrets).
    Show(ShowArgs),
    /// Rename a server and preserve its accounts, credentials, default and account policy.
    Rename(RenameArgs),
    /// Change only a server's host/port, preserving accounts, passwords and privilege settings.
    Endpoint(EndpointArgs),
    /// Update an existing account's saved login or privilege password.
    Password(PasswordArgs),
    /// Print a shell completion script (load it in your shell to enable Tab completion).
    Completions(CompletionsArgs),
    /// Show, set or clear the default server used when a name is omitted.
    Default(DefaultArgs),
    /// Approve a server's SSH host key into known_hosts (required before connecting).
    Trust(TrustArgs),
    /// Verify the host key and authenticate, without running a remote command.
    Test(TestArgs),
    /// Run a remote command over SSH and return its output.
    Run(RunArgs),
    /// Upload a local file to a server over SCP.
    Put(PutArgs),
    /// Download a remote file from a server over SCP.
    Get(GetArgs),
    /// Remove a server, its credentials, privilege metadata and account allowlist entries.
    Remove(RemoveArgs),
    /// Diagnose local settings and credentials, optionally for one registered server.
    Doctor(DoctorArgs),
    /// Manage command/path/account allowlists and explain local execution checks.
    Policy(super::policy_cmd::PolicyArgs),
    /// Manage privilege escalation credentials for a configured server.
    Privilege(PrivilegeArgs),
    /// Manage registered login accounts for a configured server.
    Account(AccountArgs),
    /// Manage named sshw profiles (each maps a name to a home directory).
    Profile(ProfileArgs),
    /// Initialize or inspect this directory's .sshw server/policy selection.
    Project(ProjectArgs),
}

impl Command {
    pub(crate) fn wants_json_errors(&self) -> bool {
        match self {
            Self::List(args) => args.json,
            Self::Show(args) => args.json,
            Self::Rename(args) => args.json,
            Self::Endpoint(args) => args.json,
            Self::Password(args) => args.json,
            Self::Completions(_) => false,
            Self::Project(args) => match &args.command {
                ProjectCommand::Init(args) => args.json,
                ProjectCommand::Status(args) => args.json,
            },
            Self::Run(args) => args.json,
            Self::Doctor(args) => args.json,
            Self::Test(args) => args.json,
            Self::Policy(args) => args.json,
            Self::Profile(args) => match &args.command {
                ProfileCommand::List(a) => a.json,
                ProfileCommand::Show(a) => a.json,
                ProfileCommand::Add(a) => a.json,
                ProfileCommand::Default(a) => a.json,
                ProfileCommand::Remove(a) => a.json,
                ProfileCommand::Rename(a) => a.json,
            },
            Self::Privilege(args) => match &args.command {
                PrivilegeCommand::Show(a) => a.json,
                PrivilegeCommand::Set(a) => a.json,
                PrivilegeCommand::Clear(a) => a.json,
            },
            Self::Account(args) => match &args.command {
                AccountCommand::Add(a) => a.json,
                AccountCommand::List(a) => a.json,
                AccountCommand::Show(a) => a.json,
                AccountCommand::Remove(a) => a.json,
                AccountCommand::Default(a) => a.json,
            },
            Self::Put(args) => args.json,
            Self::Get(args) => args.json,
            Self::Add(args) => args.json,
            Self::Trust(args) => args.json,
            Self::Remove(args) => args.json,
            Self::Default(args) => args.json,
        }
    }
}

impl Cli {
    /// Validate transfer argument counts that depend on --into, before runtime setup.
    pub fn validate_usage(&self) -> Result<(), clap::Error> {
        use clap::CommandFactory;
        if matches!(&self.command, Command::Doctor(args) if args.user.is_some() && args.name.is_none())
        {
            return Err(Self::command().error(
                clap::error::ErrorKind::MissingRequiredArgument,
                "doctor --user requires a server name",
            ));
        }
        let (target, into, upload) = match &self.command {
            Command::Get(args) => (&args.target, &args.into, false),
            Command::Policy(args) => match &args.command {
                super::policy_cmd::PolicyCommand::CheckGet(args) => {
                    if args.atomic {
                        return Err(Self::command().error(
                            clap::error::ErrorKind::InvalidValue,
                            "--atomic is only supported by check-put",
                        ));
                    }
                    (&args.target, &args.into, false)
                }
                super::policy_cmd::PolicyCommand::CheckPut(args) => {
                    (&args.target, &args.into, true)
                }
                _ => return Ok(()),
            },
            _ => return Ok(()),
        };
        let message = if upload && into.is_some() {
            Some("--into is only supported by get and policy check-get")
        } else if into
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            Some("--into directory cannot be empty")
        } else if into.is_some() && !(1..=2).contains(&target.len()) {
            Some("with --into, TARGET must be [server] <remote>; omit the local filename")
        } else if into.is_none() && !(2..=3).contains(&target.len()) {
            Some(
                "TARGET must be [server] <source> <destination>; for get, use --into <directory> instead of the local filename",
            )
        } else {
            None
        };
        match message {
            Some(message) => {
                Err(Self::command().error(clap::error::ErrorKind::WrongNumberOfValues, message))
            }
            None => Ok(()),
        }
    }
}

#[derive(Debug, Args)]
pub struct AccountArgs {
    #[command(subcommand)]
    pub command: AccountCommand,
}

#[derive(Debug, Subcommand)]
pub enum AccountCommand {
    /// Register or update a login account for a server.
    Add(AccountAddArgs),
    /// List registered login accounts for a server.
    List(AccountListArgs),
    /// Show one registered login account without revealing secrets.
    Show(AccountShowArgs),
    /// Set the account used when `--user` is omitted.
    Default(AccountDefaultArgs),
    /// Remove a saved login account, its credentials and account allowlist entries.
    /// Removing the default requires --switch-default with another registered login.
    Remove(AccountRemoveArgs),
}

#[derive(Debug, Args)]
pub struct AccountAddArgs {
    /// Server name that owns the account.
    pub name: String,
    /// Remote SSH username to register.
    pub user: String,
    /// Authentication method (default: password).
    #[arg(long, value_enum, default_value_t = AuthArg::Password)]
    pub auth: AuthArg,
    /// Read the password from stdin once instead of a hidden prompt.
    #[arg(long)]
    pub password_stdin: bool,
    /// Overwrite an existing account without prompting.
    #[arg(long)]
    pub force: bool,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct AccountListArgs {
    /// Server name whose accounts are listed.
    pub name: String,
    /// Emit a JSON array.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct AccountShowArgs {
    /// Server name that owns the account.
    pub name: String,
    /// Remote SSH username to show.
    pub user: String,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct AccountDefaultArgs {
    /// Server name that owns the account.
    pub name: String,
    /// Registered remote SSH username to make the default.
    pub user: String,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct AccountRemoveArgs {
    /// Server name that owns the account.
    pub name: String,
    /// Registered remote SSH username to remove.
    pub user: String,
    /// When removing the default login, select this different registered account in the same save.
    #[arg(long, value_name = "USER")]
    pub switch_default: Option<String>,
    /// Confirm removal non-interactively.
    #[arg(long)]
    pub yes: bool,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct PrivilegeArgs {
    #[command(subcommand)]
    pub command: PrivilegeCommand,
}

#[derive(Debug, Subcommand)]
pub enum PrivilegeCommand {
    /// Store privilege settings; use --no-password for non-interactive sudo.
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
    /// Login account whose privilege configuration is updated.
    #[arg(long, visible_alias = "login-user", value_name = "LOGIN_USER")]
    pub account: Option<String>,
    /// Privilege method used by `run --as-root`; see possible values below.
    /// Default: sudo.
    #[arg(long, value_enum, default_value_t = PrivilegeMethodArg::Sudo)]
    pub method: PrivilegeMethodArg,
    /// Target privileged user.
    #[arg(long, visible_alias = "target-user", default_value = "root")]
    pub user: String,
    /// Read the privilege password from stdin instead of a hidden prompt.
    #[arg(long)]
    pub password_stdin: bool,
    /// Store a sudo target without a password. run --as-root will use sudo -n.
    /// Cannot be used with --method su or --password-stdin.
    #[arg(long, conflicts_with = "password_stdin")]
    pub no_password: bool,
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
    /// Login account to inspect (default: server default account).
    #[arg(long, value_name = "LOGIN_USER")]
    pub account: Option<String>,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct PrivilegeClearArgs {
    /// Server name to clear.
    pub name: String,
    /// Login account to clear (default: server default account).
    #[arg(long, value_name = "LOGIN_USER")]
    pub account: Option<String>,
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
    /// Rename a profile, preserving its home, credential namespace and default selection.
    Rename(ProfileRenameArgs),
    /// Set or clear the default profile used when no explicit selector is given.
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
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
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
    /// Profile name to make the default; mutually exclusive with --clear.
    #[arg(required_unless_present = "clear", conflicts_with = "clear")]
    pub name: Option<String>,
    /// Clear the default profile; without an explicit selector use the built-in home.
    #[arg(long)]
    pub clear: bool,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ProfileRemoveArgs {
    /// Profile name to remove from the registry.
    pub name: String,
    /// When removing the default, select another registered profile instead of the first name.
    #[arg(long, conflicts_with = "clear_default", value_name = "NAME")]
    pub switch_default: Option<String>,
    /// When removing the default, clear its selection and use the built-in home.
    #[arg(long)]
    pub clear_default: bool,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ProfileRenameArgs {
    /// Registered profile name to rename.
    pub name: String,
    /// New unused profile name.
    pub new_name: String,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// Server name (the alias used by run/put/get/trust).
    pub name: String,
    /// Hostname or IP address (nonblank, no control characters). Registration
    /// does not resolve the address or test the connection.
    #[arg(long)]
    pub host: String,
    /// TCP port of the SSH server, from 1 to 65535 (default: 22).
    #[arg(long, default_value_t = 22)]
    pub port: u16,
    /// Remote username to register and make the default login account. Use
    /// `account add` to add an account while keeping the current default.
    #[arg(long)]
    pub user: String,
    /// Authentication method (default: password).
    #[arg(long, value_enum, default_value_t = AuthArg::Password)]
    pub auth: AuthArg,
    /// Overwrite an existing server without the confirmation prompt (needed for
    /// non-interactive/agent use).
    #[arg(long)]
    pub force: bool,
    /// Replace the whole server, removing its other accounts and privilege
    /// settings. Required for address changes through add; use endpoint for
    /// an address-only edit that preserves accounts and privilege settings.
    #[arg(long)]
    pub replace: bool,
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
    /// Case-insensitive literal substring of the server name or host.
    #[arg(long, value_name = "TEXT")]
    pub filter: Option<String>,
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
    /// Clear the default server, requiring an explicit server for remote operations.
    #[arg(long, conflicts_with = "name")]
    pub clear: bool,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RenameArgs {
    /// Existing server name.
    pub name: String,
    /// New, unused server name (existing servers and account policy names are not overwritten).
    pub new_name: String,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct EndpointArgs {
    /// Registered server to update.
    pub name: String,
    /// New hostname or IP address; omit to keep the current host.
    #[arg(long, required_unless_present = "port")]
    pub host: Option<String>,
    /// New SSH port; omit to keep the current port.
    #[arg(long, required_unless_present = "host")]
    pub port: Option<u16>,
    /// Confirm changing the endpoint without prompting.
    #[arg(long)]
    pub yes: bool,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ProjectArgs {
    #[command(subcommand)]
    pub command: ProjectCommand,
}
#[derive(Debug, Subcommand)]
pub enum ProjectCommand {
    /// Initialize resource sources and show policy enforcement; new local policy preserves global enablement.
    Init(ProjectInitArgs),
    /// Show project sources, paths and saved/current policy enforcement without secrets or SSH.
    Status(ProjectStatusArgs),
}
#[derive(Debug, Args)]
pub struct ProjectInitArgs {
    /// Server list source. First init defaults to global; local starts with an empty list.
    #[arg(long = "servers-source", id = "servers_source", value_enum)]
    pub servers: Option<crate::project::ResourceMode>,
    /// Policy source. First init defaults to local and preserves global rules as the starting point.
    #[arg(long = "policy-source", id = "policy_source", value_enum)]
    pub policy: Option<crate::project::ResourceMode>,
    #[arg(long)]
    pub json: bool,
}
#[derive(Debug, Args)]
pub struct ProjectStatusArgs {
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct PasswordArgs {
    /// Existing server name.
    pub name: String,
    /// Registered login account (default: the server's default login).
    #[arg(long)]
    pub user: Option<String>,
    /// Update the saved privilege password, preserving the configured sudo/su method and target.
    #[arg(long)]
    pub privilege: bool,
    /// Read the new password from stdin instead of a hidden prompt.
    #[arg(long)]
    pub password_stdin: bool,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct CompletionsArgs {
    #[arg(value_enum)]
    pub shell: CompletionShell,
    /// Internal data-only completion request on stdin; never executes the command being completed.
    #[arg(long, hide = true)]
    pub query: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CompletionShell {
    Powershell,
}

#[derive(Debug, Args)]
pub struct TrustArgs {
    /// Server whose endpoint, settings source and fingerprint to display before approving its host key.
    pub name: String,
    /// Skip the interactive fingerprint confirmation (still re-verifies before writing).
    #[arg(long)]
    pub yes: bool,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct TestArgs {
    /// Registered server to connect to; always explicit.
    pub name: String,
    /// Registered login account (default: the server's default account).
    #[arg(long, value_name = "USER")]
    pub user: Option<String>,
    /// Emit JSON instead of human text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Grammar: `[server] <command>`. With one value it is the command and the
    /// default server is used; with two, the first is the server name. Quote
    /// the command so it stays one argument.
    #[arg(value_name = "TARGET", num_args = 1..=2, required = true)]
    pub target: Vec<String>,
    /// Use this registered login account instead of the server default.
    #[arg(long, value_name = "USER")]
    pub user: Option<String>,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
    /// Stream redacted complete lines while running (ordinary SSH or sudo).
    /// Incomplete lines wait until completion. Incompatible with JSON and su PTY.
    #[arg(long, conflicts_with = "json")]
    pub stream: bool,
    /// Confirm safety-sensitive commands non-interactively.
    #[arg(long)]
    pub yes: bool,
    /// Run through the selected account's configured privilege path (`sshw
    /// privilege set`). This flag explicitly requests elevation; dangerous commands
    /// still require `--yes`. Uses the stored method (`sudo`
    /// or `su`); with NOPASSWD sudoers the command runs even if the stored
    /// password is wrong, since sudo does not consume it. A sudo password
    /// rejection reports the remote command's non-zero status (exit 8), while
    /// a su prompt/auth failure maps to auth (exit 4).
    #[arg(long, visible_alias = "elevate")]
    pub as_root: bool,
    /// With --as-root, use non-interactive sudo -n without a stored privilege
    /// password. Uses the configured sudo target, or root if not configured.
    /// The server must already permit this through sudoers (e.g. NOPASSWD).
    #[arg(long, requires = "as_root")]
    pub no_password: bool,
}

#[derive(Debug, Args)]
pub struct PutArgs {
    /// Grammar: `[server] <local> <remote>`. With two values the default server
    /// is used; with three, the first is the server name. In Git Bash/MSYS,
    /// write an absolute remote path as `remote:/path` to prevent conversion.
    #[arg(value_name = "TARGET", num_args = 2..=3, required = true)]
    pub target: Vec<String>,
    /// Use this registered login account instead of the server default.
    #[arg(long, value_name = "USER")]
    pub user: Option<String>,
    /// Remote file permissions in octal, e.g. 755 for an executable. Default: 600.
    #[arg(long, value_parser = parse_file_mode)]
    pub mode: Option<u32>,
    /// Stage beside the destination and atomically replace it using the SFTP
    /// posix-rename extension. Requires parent-directory policy/write permission.
    /// New file mode defaults to 600; existing inode ownership/ACLs are not kept.
    #[arg(long)]
    pub atomic: bool,
    /// Confirm writes to system paths non-interactively.
    #[arg(long)]
    pub yes: bool,
    /// Show transfer bytes, percentage and average speed on stderr, including with --json.
    #[arg(long)]
    pub progress: bool,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

fn parse_file_mode(value: &str) -> Result<u32, String> {
    if !(3..=4).contains(&value.len()) || !value.bytes().all(|c| (b'0'..=b'7').contains(&c)) {
        return Err("use octal permissions such as 600 or 755 (no special bits)".to_string());
    }
    let mode = u32::from_str_radix(value, 8).map_err(|_| "invalid file mode".to_string())?;
    if mode > 0o777 {
        return Err("special permission bits are not supported".to_string());
    }
    Ok(mode)
}

#[derive(Debug, Args)]
pub struct GetArgs {
    /// Grammar: `[server] <remote> <local>`. With two values the default server
    /// is used; with three, the first is the server name. In Git Bash/MSYS,
    /// write an absolute remote path as `remote:/path` to prevent conversion.
    /// With --into, use [server] <remote>; keep the source filename in that directory.
    #[arg(value_name = "TARGET", num_args = 1..=3, required = true)]
    pub target: Vec<String>,
    /// Download into this local directory using the remote source's filename.
    /// Replaces the positional local filename; existing overwrite protection still applies.
    #[arg(long, value_name = "DIRECTORY")]
    pub into: Option<PathBuf>,
    /// Use this registered login account instead of the server default.
    #[arg(long, value_name = "USER")]
    pub user: Option<String>,
    /// Confirm overwriting an existing local file non-interactively.
    #[arg(long)]
    pub yes: bool,
    /// Show transfer bytes, percentage and average speed on stderr, including with --json.
    #[arg(long)]
    pub progress: bool,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// Server name to remove.
    pub name: String,
    /// When removing the default, select another registered server instead of the first name.
    #[arg(long, conflicts_with = "clear_default", value_name = "NAME")]
    pub switch_default: Option<String>,
    /// When removing the default, leave no default server selected.
    #[arg(long)]
    pub clear_default: bool,
    /// Confirm removal non-interactively.
    #[arg(long)]
    pub yes: bool,
    /// Emit JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Limit server-specific checks to this registered server; keep home-wide diagnostics.
    pub name: Option<String>,
    /// Check only this registered login and its privilege credentials; requires a server name.
    #[arg(long, requires = "name", value_name = "USER")]
    pub user: Option<String>,
    /// Emit JSON instead of human text.
    #[arg(long)]
    pub json: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn check_get_atomic_is_rejected_by_early_usage_validation() {
        use clap::Parser;
        for target in [
            vec!["source", "destination"],
            vec!["web", "source", "destination"],
        ] {
            let mut args = vec!["sshw", "policy", "check-get"];
            args.extend(target);
            args.push("--atomic");
            let cli = Cli::try_parse_from(args).unwrap();
            let error = cli.validate_usage().unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("--atomic is only supported by check-put")
            );
        }
        assert!(
            Cli::try_parse_from([
                "sshw",
                "policy",
                "check-put",
                "source",
                "destination",
                "--atomic"
            ])
            .unwrap()
            .validate_usage()
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "sshw",
                "policy",
                "check-get",
                "source",
                "--into",
                "downloads"
            ])
            .unwrap()
            .validate_usage()
            .is_ok()
        );
    }

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
            "`--json` is accepted by: add, list, show, rename, endpoint, trust, run, put, get, remove,",
            "doctor, default, password, test, all account/profile/policy/project subcommands, and privilege",
            "set/show/clear. A completed run uses command_succeeded for remote success.",
            "sshw account add web ops --auth agent",
            "An explicit --profile conflicts with SSHW_HOME",
            "sudo password rejection is reported as the remote command's non-zero status",
            "su prompt/auth failure maps to auth",
            "change:   {\"ok\":true,\"action\":\"added\",\"server\":\"web\"}",
            "{\"ok\":false,\"error\":",
            "optional `causes` array preserves the redacted error chain",
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
            "If retained output exceeds 16 MiB, sshw fails the operation",
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
