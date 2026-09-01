use crate::audit::{self, AuditRecord, AuditSink, AuditStatus, FileAuditSink, NoopAudit};
use crate::config::{
    AccountConfig, AuthConfig, ConfigRevision, CredentialBackend, PrivilegeConfig, PrivilegeMethod,
    ServerConfig, SshwConfig, load_config, load_config_with_revision,
    validate_config_credential_references,
};
use crate::credentials::keyring_store::KeyringCredentialStore;
use crate::credentials::session_store::SessionOnlyStore;
use crate::credentials::{AuthMaterial, CredentialStore, CredentialStoreHealth};
use crate::error::{ResultErrorKindExt, app_error};
use crate::home::{CredentialPurpose, ResolvedHome, builtin_default_home, sshw_base_dir};
use crate::output::{
    ErrorKind, ErrorResponse, RunOutput, filter_startup_stderr_noise, redact_secrets,
};
use crate::policy::{Policy, describe_policy, resolve_policy};
use crate::profile::{load_registry, resolve_home_with_registry};
use crate::safety::{SafetyDecision, classify_command, command_program};
use crate::sandbox::{NoopSandbox, PolicyOnlySandbox, Sandbox, SandboxDecision};
use crate::ssh::ssh2_client::{
    Ssh2Client, runtime_library_versions, su_begin_marker, su_end_prefix,
};
use crate::ssh::{SshClient, SshTarget};
use anyhow::Context;
use clap::Parser;
use serde_json::json;
use std::ffi::OsStr;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

mod account;
mod model;
mod privilege;
mod profile;
mod prompt;
mod server;
mod transfer;

pub use model::{
    AccountAddArgs, AccountArgs, AccountCommand, AccountDefaultArgs, AccountListArgs,
    AccountRemoveArgs, AccountShowArgs, AddArgs, AuthArg, Cli, Command, DefaultArgs, DoctorArgs,
    GetArgs, ListArgs, PrivilegeArgs, PrivilegeClearArgs, PrivilegeCommand, PrivilegeMethodArg,
    PrivilegeSetArgs, PrivilegeShowArgs, ProfileAddArgs, ProfileArgs, ProfileCommand,
    ProfileDefaultArgs, ProfileListArgs, ProfileRemoveArgs, ProfileShowArgs, PutArgs, RemoveArgs,
    RunArgs, ShowArgs, TrustArgs,
};
pub use prompt::Prompter;
use prompt::TerminalPrompter;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Runtime context resolved from the active sshw home/profile plus the global
/// profile registry, bundling the policy-enforcement flag and audit sink that
/// command handlers need.
pub struct ExecContext<'a> {
    pub home: &'a ResolvedHome,
    pub registry_path: &'a Path,
    /// The `--policy` flag: force policy enforcement for this invocation.
    pub policy_forced: bool,
    pub audit: &'a dyn AuditSink,
}

pub fn run() -> i32 {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        // Argument-parsing failures never reach a command, so handle them here:
        // help/version exit 0, genuine usage errors get the dedicated `usage`
        // kind / exit code, as a JSON envelope when `--json` was requested.
        Err(err) => return print_output(parse_error_output(err, json_requested_in_args())),
    };
    let json_errors = cli.command.wants_json_errors();
    let (home, registry_path) = match resolve_runtime(&cli) {
        Ok(resolved) => resolved,
        Err(err) => return print_output(error_output(&err, json_errors)),
    };
    // Omission preserves the client's bounded default. `--timeout 0` is the
    // only explicit opt-out; a positive value replaces the absolute deadline.
    let mut ssh = Ssh2Client::default().with_known_hosts(home.known_hosts_path.clone());
    if let Some(op_timeout) = operation_timeout_override(cli.timeout) {
        ssh = ssh.with_op_timeout(op_timeout);
    }
    let mut prompter = TerminalPrompter;
    let audit = FileAuditSink::new(runtime_audit_path(&cli, &home, &registry_path));
    let ctx = ExecContext {
        home: &home,
        registry_path: &registry_path,
        policy_forced: cli.policy,
        audit: &audit,
    };

    let output = execute_for_runtime_selecting_backend(
        cli,
        &ctx,
        &KeyringCredentialStore,
        SessionOnlyStore::from_env,
        &ssh,
        &mut prompter,
    );

    print_output(output)
}

fn operation_timeout_override(timeout: Option<u64>) -> Option<Option<Duration>> {
    timeout.map(|seconds| (seconds > 0).then(|| Duration::from_secs(seconds)))
}

fn runtime_audit_path(cli: &Cli, home: &ResolvedHome, registry_path: &Path) -> PathBuf {
    if matches!(&cli.command, Command::Profile(_))
        && let Some(sshw_base) = registry_path.parent()
    {
        return builtin_default_home(sshw_base).audit_path;
    }
    home.audit_path.clone()
}

fn resolve_runtime(cli: &Cli) -> anyhow::Result<(ResolvedHome, PathBuf)> {
    let sshw_base = sshw_base_dir().with_error_kind(ErrorKind::Config)?;
    let env_home = std::env::var_os("SSHW_HOME").filter(|value| !value.is_empty());
    resolve_runtime_with_base(cli, &sshw_base, env_home.as_deref())
}

fn resolve_runtime_with_base(
    cli: &Cli,
    sshw_base: &Path,
    env_home: Option<&std::ffi::OsStr>,
) -> anyhow::Result<(ResolvedHome, PathBuf)> {
    let registry_path = sshw_base.join("profiles.json");

    if matches!(
        &cli.command,
        Command::Profile(ProfileArgs {
            command: ProfileCommand::Remove(_)
        })
    ) && cli.profile.is_none()
    {
        let home = resolve_home_with_registry(
            cli.home.as_deref(),
            env_home,
            None,
            &crate::profile::ProfileRegistry::default(),
            sshw_base,
        )
        .with_error_kind(ErrorKind::Config)?;
        return Ok((home, registry_path));
    }

    match resolve_runtime_with_base_strict(cli, sshw_base, env_home) {
        Ok(resolved) => Ok(resolved),
        Err(_err)
            if matches!(&cli.command, Command::Doctor(_))
                && !(cli.home.is_some() && cli.profile.is_some())
                && load_registry(&registry_path).is_err() =>
        {
            Ok((builtin_default_home(sshw_base), registry_path))
        }
        Err(err) => Err(err),
    }
}

fn resolve_runtime_with_base_strict(
    cli: &Cli,
    sshw_base: &Path,
    env_home: Option<&std::ffi::OsStr>,
) -> anyhow::Result<(ResolvedHome, PathBuf)> {
    let registry_path = sshw_base.join("profiles.json");
    let needs_registry =
        matches!(&cli.command, Command::Profile(_)) || (cli.home.is_none() && env_home.is_none());
    let registry = if needs_registry {
        load_registry(&registry_path).with_error_kind(ErrorKind::Config)?
    } else {
        crate::profile::ProfileRegistry::default()
    };
    let home = resolve_home_with_registry(
        cli.home.as_deref(),
        env_home,
        cli.profile.as_deref(),
        &registry,
        sshw_base,
    )
    .with_error_kind(ErrorKind::Config)?;
    Ok((home, registry_path))
}

fn sibling_registry_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .map(|parent| parent.join("profiles.json"))
        .unwrap_or_else(|| PathBuf::from("profiles.json"))
}

/// Backward-compatible facade: treat the parent of `config_path` as an ad-hoc
/// home, with the profile registry as its sibling. Used by tests and callers
/// that pass a config path directly.
pub fn execute<C, S, P>(
    cli: Cli,
    config_path: &Path,
    credentials: &C,
    ssh: &S,
    prompter: &mut P,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
    S: SshClient,
    P: Prompter,
{
    let home = ResolvedHome::from_config_path(config_path);
    let registry_path = sibling_registry_path(config_path);
    let policy_forced = cli.policy;
    let audit = NoopAudit;
    let ctx = ExecContext {
        home: &home,
        registry_path: &registry_path,
        policy_forced,
        audit: &audit,
    };
    execute_with(cli, &ctx, credentials, ssh, prompter)
}

pub fn execute_for_runtime<C, S, P>(
    cli: Cli,
    config_path: &Path,
    credentials: &C,
    ssh: &S,
    prompter: &mut P,
) -> CommandOutput
where
    C: CredentialStore,
    S: SshClient,
    P: Prompter,
{
    let home = ResolvedHome::from_config_path(config_path);
    let registry_path = sibling_registry_path(config_path);
    let policy_forced = cli.policy;
    let audit = NoopAudit;
    let ctx = ExecContext {
        home: &home,
        registry_path: &registry_path,
        policy_forced,
        audit: &audit,
    };
    execute_for_runtime_with(cli, &ctx, credentials, ssh, prompter)
}

fn execute_for_runtime_selecting_backend<N, E, S, P, MakeSession>(
    cli: Cli,
    ctx: &ExecContext,
    native_credentials: &N,
    make_session_credentials: MakeSession,
    ssh: &S,
    prompter: &mut P,
) -> CommandOutput
where
    N: CredentialStore,
    E: CredentialStore,
    S: SshClient,
    P: Prompter,
    MakeSession: FnOnce() -> E,
{
    let backend = if matches!(&cli.command, Command::Profile(_)) {
        CredentialBackend::Native
    } else {
        load_config(&ctx.home.config_path)
            .map(|config| config.credential_backend)
            .unwrap_or_default()
    };
    match backend {
        CredentialBackend::Native => {
            execute_for_runtime_with(cli, ctx, native_credentials, ssh, prompter)
        }
        CredentialBackend::SessionOnly => {
            let session_credentials = make_session_credentials();
            execute_for_runtime_with(cli, ctx, &session_credentials, ssh, prompter)
        }
    }
}

pub fn execute_for_runtime_with<C, S, P>(
    cli: Cli,
    ctx: &ExecContext,
    credentials: &C,
    ssh: &S,
    prompter: &mut P,
) -> CommandOutput
where
    C: CredentialStore,
    S: SshClient,
    P: Prompter,
{
    let json_errors = cli.command.wants_json_errors();
    match execute_with(cli, ctx, credentials, ssh, prompter) {
        Ok(output) => output,
        Err(err) => error_output(&err, json_errors),
    }
}

pub fn execute_with<C, S, P>(
    cli: Cli,
    ctx: &ExecContext,
    credentials: &C,
    ssh: &S,
    prompter: &mut P,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
    S: SshClient,
    P: Prompter,
{
    let Cli {
        home: home_flag,
        profile: _,
        policy: _,
        timeout: _,
        command,
    } = cli;

    let config_path = ctx.home.config_path.as_path();
    let command = match command {
        Command::Profile(args) => {
            let descriptor = profile_audit_descriptor(&args.command);
            let result = profile::run_profile(args, ctx.registry_path, home_flag.as_deref());
            record_audit_result(ctx.audit, descriptor, &result);
            return result;
        }
        Command::Doctor(args) => {
            return doctor(
                args,
                ctx.home,
                ctx.registry_path,
                ctx.policy_forced,
                credentials,
            );
        }
        command => command,
    };
    let _home_lock = if command_mutates_home(&command) {
        Some(
            crate::storage::acquire_exclusive_lock(&ctx.home.root.join(".sshw.lock"))
                .with_error_kind(ErrorKind::Config)?,
        )
    } else {
        None
    };
    let (mut config, revision) = load_active_config_with_revision(ctx.home)?;

    let descriptor = audit_descriptor(&command, &config);
    // Captured before `command` is consumed by dispatch: used to remap a remote
    // command's exit code after auditing the real status.
    let is_run = matches!(&command, Command::Run(_));
    let run_json = matches!(&command, Command::Run(args) if args.json);

    let result = match command {
        Command::Add(args) => server::add_server(
            args,
            config_path,
            &revision,
            &ctx.home.namespace,
            credentials,
            prompter,
            &mut config,
        ),
        Command::List(args) => server::list_servers(args, &config),
        Command::Show(args) => server::show_server(args, &config),
        Command::Default(args) => server::default_server(args, config_path, &revision, &mut config),
        Command::Trust(args) => server::trust_server(args, ssh, prompter, &config),
        Command::Run(args) => build_sandbox(&ctx.home.policy_path, ctx.policy_forced)
            .and_then(|sandbox| run_remote(args, sandbox.as_ref(), credentials, ssh, &config)),
        Command::Put(args) => {
            build_sandbox(&ctx.home.policy_path, ctx.policy_forced).and_then(|sandbox| {
                transfer::put_file(args, sandbox.as_ref(), credentials, ssh, &config)
            })
        }
        Command::Get(args) => {
            build_sandbox(&ctx.home.policy_path, ctx.policy_forced).and_then(|sandbox| {
                transfer::get_file(args, sandbox.as_ref(), credentials, ssh, &config)
            })
        }
        Command::Remove(args) => server::remove_server(
            args,
            config_path,
            &revision,
            credentials,
            prompter,
            &mut config,
        ),
        Command::Doctor(_) => unreachable!("doctor is dispatched before config enforcement"),
        Command::Privilege(args) => match args.command {
            PrivilegeCommand::Set(args) => privilege::set_privilege(
                args,
                config_path,
                &revision,
                &ctx.home.namespace,
                credentials,
                prompter,
                &mut config,
            ),
            PrivilegeCommand::Show(args) => privilege::show_privilege(args, &config),
            PrivilegeCommand::Clear(args) => privilege::clear_privilege(
                args,
                config_path,
                &revision,
                credentials,
                prompter,
                &mut config,
            ),
        },
        Command::Account(args) => match args.command {
            AccountCommand::Add(args) => account::add_account(
                args,
                config_path,
                &revision,
                &ctx.home.namespace,
                credentials,
                prompter,
                &mut config,
            ),
            AccountCommand::List(args) => account::list_accounts(args, &config),
            AccountCommand::Show(args) => account::show_account(args, &config),
            AccountCommand::Default(args) => {
                account::default_account(args, config_path, &revision, &mut config)
            }
            AccountCommand::Remove(args) => account::remove_account(
                args,
                config_path,
                &revision,
                credentials,
                prompter,
                &mut config,
            ),
        },
        Command::Profile(_) => unreachable!("profile is dispatched before config loading"),
    };

    record_audit_result(ctx.audit, descriptor, &result);

    // Remap a remote command's non-zero exit (recorded above) so it cannot be
    // confused with sshw's own operational exit codes.
    result.map(|output| remap_remote_nonzero_exit(output, is_run, run_json))
}

type AuditDescriptor = (&'static str, Option<String>, Option<String>, Option<String>);

fn record_audit_result(
    audit: &dyn AuditSink,
    descriptor: Option<AuditDescriptor>,
    result: &anyhow::Result<CommandOutput>,
) {
    let Some((action, server, user, detail)) = descriptor else {
        return;
    };
    let (status, exit_code) = match result {
        Ok(output) => (AuditStatus::Ok, output.exit_code),
        Err(err) => (
            AuditStatus::Error,
            ErrorResponse::from_error(err).error.exit_code,
        ),
    };
    // Best-effort: an audit write failure must not fail the operation.
    let _ = audit.record(&AuditRecord {
        action: action.to_string(),
        server,
        user,
        detail,
        status,
        exit_code,
    });
}

fn profile_audit_descriptor(command: &ProfileCommand) -> Option<AuditDescriptor> {
    match command {
        ProfileCommand::Add(args) => {
            Some(("profile", None, None, Some(format!("add:{}", args.name))))
        }
        ProfileCommand::Default(args) => Some((
            "profile",
            None,
            None,
            Some(format!("default:{}", args.name)),
        )),
        ProfileCommand::Remove(args) => {
            Some(("profile", None, None, Some(format!("remove:{}", args.name))))
        }
        ProfileCommand::List(_) | ProfileCommand::Show(_) => None,
    }
}

fn command_mutates_home(command: &Command) -> bool {
    matches!(
        command,
        Command::Add(_) | Command::Trust(_) | Command::Remove(_)
    ) || matches!(command, Command::Default(args) if args.name.is_some())
        || matches!(
            command,
            Command::Account(AccountArgs {
                command: AccountCommand::Add(_)
                    | AccountCommand::Default(_)
                    | AccountCommand::Remove(_),
            })
        )
        || matches!(
            command,
            Command::Privilege(PrivilegeArgs {
                command: PrivilegeCommand::Set(_) | PrivilegeCommand::Clear(_),
            })
        )
}

fn load_active_config(home: &ResolvedHome) -> anyhow::Result<SshwConfig> {
    load_active_config_with_revision(home).map(|(config, _revision)| config)
}

fn load_active_config_with_revision(
    home: &ResolvedHome,
) -> anyhow::Result<(SshwConfig, ConfigRevision)> {
    let config_path = home.config_path.as_path();
    let (config, revision) =
        load_config_with_revision(config_path).with_error_kind(ErrorKind::Config)?;
    validate_config_credential_references(&config, &home.namespace)
        .map_err(|err| anyhow::anyhow!("failed to load config at {}: {err}", config_path.display()))
        .with_error_kind(ErrorKind::Config)?;
    Ok((config, revision))
}

/// Remap a remote command's non-zero exit to [`crate::output::REMOTE_NONZERO_EXIT_CODE`]
/// so it can never collide with sshw's operational exit codes (1-7). Applied
/// after auditing, which records the real remote status. In non-JSON mode a
/// human-readable note carries the real status; JSON output already includes
/// `exit_status`.
fn remap_remote_nonzero_exit(mut output: CommandOutput, is_run: bool, json: bool) -> CommandOutput {
    if is_run && output.exit_code != 0 {
        if !json {
            if !output.stderr.is_empty() && !output.stderr.ends_with('\n') {
                output.stderr.push('\n');
            }
            output.stderr.push_str(&format!(
                "note: remote command exited with status {}\n",
                output.exit_code
            ));
        }
        output.exit_code = crate::output::REMOTE_NONZERO_EXIT_CODE;
    }
    output
}

/// Best-effort `(action, server, detail)` for the auditable commands. Returns
/// `None` for read-only commands (list/show/doctor/profile) that are not
/// audited. `detail` is redacted by the sink before being written.
fn audit_descriptor(command: &Command, config: &SshwConfig) -> Option<AuditDescriptor> {
    let default = || config.default.clone();
    match command {
        Command::Add(a) => Some(("add", Some(a.name.clone()), Some(a.user.clone()), None)),
        Command::Remove(a) => Some(("remove", Some(a.name.clone()), None, None)),
        Command::Trust(a) => Some(("trust", Some(a.name.clone()), None, None)),
        Command::Default(a) => Some(("default", a.name.clone().or_else(default), None, None)),
        Command::Run(a) => {
            // target is `[name] <command>`.
            let (server, command) = match split_target(&a.target, 1) {
                Some((name, rest)) => (
                    name.map(str::to_string).or_else(default),
                    Some(rest[0].clone()),
                ),
                None => (default(), None),
            };
            // Record only the program name, never the full argument string, so
            // secrets passed inline (e.g. `mysql -phunter2`) are not persisted.
            let program = command.as_deref().and_then(command_program);
            let user = a.user.clone().or_else(|| {
                server
                    .as_deref()
                    .and_then(|name| config.servers.get(name))
                    .map(|server| server.default_user.clone())
            });
            let detail = if a.as_root {
                let program = program.unwrap_or_else(|| "unknown".to_string());
                let marker = server
                    .as_deref()
                    .and_then(|server| config.servers.get(server))
                    .and_then(|server| user.as_deref().and_then(|user| server.account(user)))
                    .and_then(|account| account.privilege.as_ref())
                    .map(|privilege| {
                        format!(
                            "as-root:{}:{}:{}",
                            privilege::method_label(privilege.method),
                            privilege.user,
                            program
                        )
                    })
                    .unwrap_or_else(|| format!("as-root:missing:{program}"));
                Some(marker)
            } else {
                program
            };
            Some(("run", server, user, detail))
        }
        Command::Put(a) => {
            // target is `[name] <local> <remote>`; audit records the remote dest.
            let (server, detail) = match split_target(&a.target, 2) {
                Some((name, rest)) => (
                    name.map(str::to_string).or_else(default),
                    Some(transfer::remote_path_for_audit(&rest[1])),
                ),
                None => (default(), None),
            };
            let user = a.user.clone().or_else(|| {
                server
                    .as_deref()
                    .and_then(|name| config.servers.get(name))
                    .map(|server| server.default_user.clone())
            });
            Some(("put", server, user, detail))
        }
        Command::Get(a) => {
            // target is `[name] <remote> <local>`; audit records the remote source.
            let (server, detail) = match split_target(&a.target, 2) {
                Some((name, rest)) => (
                    name.map(str::to_string).or_else(default),
                    Some(transfer::remote_path_for_audit(&rest[0])),
                ),
                None => (default(), None),
            };
            let user = a.user.clone().or_else(|| {
                server
                    .as_deref()
                    .and_then(|name| config.servers.get(name))
                    .map(|server| server.default_user.clone())
            });
            Some(("get", server, user, detail))
        }
        Command::Privilege(a) => match &a.command {
            PrivilegeCommand::Set(args) => Some((
                "privilege",
                Some(args.name.clone()),
                args.account.clone().or_else(|| {
                    config
                        .servers
                        .get(&args.name)
                        .map(|server| server.default_user.clone())
                }),
                Some("set".to_string()),
            )),
            PrivilegeCommand::Clear(args) => Some((
                "privilege",
                Some(args.name.clone()),
                args.account.clone().or_else(|| {
                    config
                        .servers
                        .get(&args.name)
                        .map(|server| server.default_user.clone())
                }),
                Some("clear".to_string()),
            )),
            PrivilegeCommand::Show(_) => None,
        },
        Command::Account(a) => match &a.command {
            AccountCommand::Add(args) => Some((
                "account",
                Some(args.name.clone()),
                Some(args.user.clone()),
                Some(format!("add:{}", args.user)),
            )),
            AccountCommand::Default(args) => Some((
                "account",
                Some(args.name.clone()),
                Some(args.user.clone()),
                Some(format!("default:{}", args.user)),
            )),
            AccountCommand::Remove(args) => Some((
                "account",
                Some(args.name.clone()),
                Some(args.user.clone()),
                Some(format!("remove:{}", args.user)),
            )),
            AccountCommand::List(_) | AccountCommand::Show(_) => None,
        },
        _ => None,
    }
}

fn build_sandbox(policy_path: &Path, forced: bool) -> anyhow::Result<Box<dyn Sandbox>> {
    match resolve_policy(policy_path, forced).with_error_kind(ErrorKind::Policy)? {
        Policy::Disabled => Ok(Box::new(NoopSandbox)),
        Policy::Enabled(rules) => Ok(Box::new(PolicyOnlySandbox::new(rules))),
    }
}

fn run_remote<C, S>(
    args: RunArgs,
    sandbox: &dyn Sandbox,
    credentials: &C,
    ssh: &S,
    config: &SshwConfig,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
    S: SshClient,
{
    let RunArgs {
        target,
        user,
        json,
        yes,
        as_root,
    } = args;
    let (server_name, command) = resolve_run_target(target, config)?;

    if as_root && !yes {
        return Err(app_error(
            ErrorKind::Safety,
            "root privilege escalation requires --yes; review the command and rerun with --yes",
        ));
    }

    match classify_command(&command, yes) {
        SafetyDecision::Allow => {}
        SafetyDecision::Block { reason } => return Err(app_error(ErrorKind::Safety, reason)),
    }

    if let SandboxDecision::Deny { reason } = sandbox.check_command(&command) {
        return Err(app_error(ErrorKind::Policy, reason));
    }

    let server = get_server(config, &server_name)?;
    let (login_user, account) = select_account(&server_name, server, user.as_deref())?;
    if let SandboxDecision::Deny { reason } =
        sandbox.check_account(&server_name, login_user, login_user == server.default_user)
    {
        return Err(app_error(ErrorKind::Policy, reason));
    }
    let auth = resolve_auth(account, login_user, credentials)?;
    let ssh_target = SshTarget::new(server, login_user);
    let privileged = if as_root {
        Some(resolve_privileged_execution(
            &server_name,
            login_user,
            account,
            &command,
            credentials,
        )?)
    } else {
        None
    };
    let remote_command = privileged
        .as_ref()
        .map(|execution| execution.command.as_str())
        .unwrap_or(command.as_str());
    let result = if let Some(stdin) = privileged
        .as_ref()
        .and_then(|execution| execution.stdin.as_ref())
    {
        ssh.run_with_stdin(&ssh_target, &auth, remote_command, stdin.as_str())
            .with_error_kind(ErrorKind::Ssh)?
    } else if let Some(password) = privileged
        .as_ref()
        .and_then(|execution| execution.pty_password.as_ref())
    {
        let marker_nonce = privileged
            .as_ref()
            .and_then(|execution| execution.pty_marker_nonce.as_deref())
            .unwrap_or_default();
        ssh.run_with_pty_password(
            &ssh_target,
            &auth,
            remote_command,
            password.as_str(),
            marker_nonce,
        )
        .with_error_kind(ErrorKind::Ssh)?
    } else {
        ssh.run(&ssh_target, &auth, remote_command)
            .with_error_kind(ErrorKind::Ssh)?
    };
    let exit_code = result.exit_status;
    let login_secret = match &auth {
        AuthMaterial::Password(password) => Some(password.as_str()),
        AuthMaterial::Agent => None,
    };
    let privilege_secret = privileged
        .as_ref()
        .and_then(|execution| execution.redact_secret.as_ref())
        .map(|secret| secret.as_str());
    let secrets = [login_secret, privilege_secret];
    let redacted_command = redact_with_known_secrets(&command, &secrets);
    let stdout = redact_with_known_secrets(&result.stdout, &secrets);
    let stderr = redact_with_known_secrets(&filter_startup_stderr_noise(&result.stderr), &secrets);

    if json {
        let output = RunOutput {
            ok: true,
            server: server_name,
            user: login_user.to_string(),
            command: redacted_command,
            exit_status: result.exit_status,
            stdout,
            stderr,
            duration_ms: result.duration_ms,
        };
        return Ok(CommandOutput {
            stdout: format!("{}\n", serde_json::to_string(&output)?),
            stderr: String::new(),
            exit_code,
        });
    }

    Ok(CommandOutput {
        stdout,
        stderr,
        exit_code,
    })
}

struct PrivilegedExecution {
    command: String,
    /// sudo: password sent once over the channel stdin.
    stdin: Option<Zeroizing<String>>,
    /// su: password injected at the PTY prompt by the ssh backend.
    pty_password: Option<Zeroizing<String>>,
    /// su: per-execution nonce for the output framing markers, passed to the
    /// backend so it parses exactly the markers `su_command` produced.
    pty_marker_nonce: Option<String>,
    redact_secret: Option<Zeroizing<String>>,
}

fn resolve_privileged_execution<C>(
    server_name: &str,
    login_user: &str,
    account: &AccountConfig,
    command: &str,
    credentials: &C,
) -> anyhow::Result<PrivilegedExecution>
where
    C: CredentialStore,
{
    let privilege = account
        .privilege
        .as_ref()
        .ok_or_else(|| privilege::missing_privilege(server_name, login_user))?;

    match privilege.method {
        PrivilegeMethod::Sudo => sudo_execution(command, privilege, credentials),
        PrivilegeMethod::Su => su_execution(command, privilege, credentials),
    }
}

/// Fetch the stored privilege password for `privilege` and validate its shape.
/// Shared by the sudo and su execution builders so the credential lookup,
/// missing-entry context, and non-empty/single-line validation stay identical.
fn fetch_validated_privilege_password<C>(
    privilege: &PrivilegeConfig,
    credentials: &C,
) -> anyhow::Result<Zeroizing<String>>
where
    C: CredentialStore,
{
    let password = Zeroizing::new(
        credentials
            .get_password_for(
                CredentialPurpose::Privilege,
                &privilege.credential,
                &privilege.user,
            )
            .with_error_kind(ErrorKind::Auth)
            .with_context(|| {
                format!(
                    "missing credential entry for {} and privilege user {}",
                    privilege.credential, privilege.user
                )
            })?,
    );
    privilege::validate_privilege_password(password.as_str())?;
    Ok(password)
}

fn sudo_execution<C>(
    command: &str,
    privilege: &PrivilegeConfig,
    credentials: &C,
) -> anyhow::Result<PrivilegedExecution>
where
    C: CredentialStore,
{
    let password = fetch_validated_privilege_password(privilege, credentials)?;
    Ok(PrivilegedExecution {
        command: sudo_command(command, &privilege.user),
        stdin: Some(Zeroizing::new(format!("{}\n", password.as_str()))),
        pty_password: None,
        pty_marker_nonce: None,
        redact_secret: Some(password),
    })
}

fn su_execution<C>(
    command: &str,
    privilege: &PrivilegeConfig,
    credentials: &C,
) -> anyhow::Result<PrivilegedExecution>
where
    C: CredentialStore,
{
    let password = fetch_validated_privilege_password(privilege, credentials)?;
    let marker_nonce = su_marker_nonce();
    Ok(PrivilegedExecution {
        command: su_command(command, &privilege.user, &marker_nonce),
        stdin: None,
        // su prompts for the password on the PTY; the ssh backend injects this
        // value when it detects the prompt. It is never placed on the command
        // line or in the audit detail.
        pty_password: Some(password.clone()),
        pty_marker_nonce: Some(marker_nonce),
        redact_secret: Some(password),
    })
}

fn sudo_command(command: &str, user: &str) -> String {
    let quoted_user = shell_quote(user);
    let quoted_command = shell_quote(command);
    let script = format!(
        "IFS= read -r sshw_sudo_password || exit 1; \
         printf '%s\\n' \"$sshw_sudo_password\" | sudo -S -p '' -u {quoted_user} -v; \
         sshw_sudo_status=$?; unset sshw_sudo_password; \
         [ \"$sshw_sudo_status\" -eq 0 ] || exit \"$sshw_sudo_status\"; \
         sudo -n -p '' -u {quoted_user} -- sh -lc {quoted_command} < /dev/null"
    );
    format!("sh -c {}", shell_quote(&script))
}

fn su_command(command: &str, user: &str, marker_nonce: &str) -> String {
    // su reads its password from the controlling terminal (PTY), so there is no
    // `-S`/stdin trick — the backend injects the password at the prompt. LC_ALL=C
    // forces the English "Password:" prompt so the backend can detect it. The
    // command is wrapped in BEGIN/END markers so the backend extracts exactly the
    // command's own output and its exit code from the merged PTY stream, instead
    // of guessing which lines are prompt vs output. The markers embed a
    // per-execution nonce so the command's own stdout cannot reproduce the END
    // marker and forge the exit code (the backend uses the same nonce to parse).
    let quoted_user = shell_quote(user);
    let inner = format!(
        "printf '{begin}\\n'; sh -c {cmd}; __sshw_ec=$?; printf '{end}%d__\\n' \"$__sshw_ec\"",
        begin = su_begin_marker(marker_nonce),
        cmd = shell_quote(command),
        end = su_end_prefix(marker_nonce),
    );
    format!("LC_ALL=C su - {quoted_user} -c {}", shell_quote(&inner))
}

/// Generate an unpredictable hex nonce for one `su` execution's output framing.
/// Mixes a process-wide sequence counter, a wall-clock nanosecond sample, and
/// the pid through the standard library's randomized hasher — dependency-free,
/// and different on every call so a command's stdout cannot guess the markers.
fn su_marker_nonce() -> String {
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(seq);
    hasher.write_u64(nanos);
    hasher.write_u32(std::process::id());
    format!("{:016x}", hasher.finish())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn redact_with_known_secrets(input: &str, secrets: &[Option<&str>]) -> String {
    let mut redacted = redact_secrets(input);
    let mut known_secrets: Vec<_> = secrets
        .iter()
        .filter_map(|secret| *secret)
        .filter(|secret| !secret.is_empty())
        .collect();
    known_secrets
        .sort_unstable_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
    known_secrets.dedup();
    for secret in known_secrets {
        redacted = redacted.replace(secret, "<redacted>");
    }
    redacted
}

fn doctor<C>(
    args: DoctorArgs,
    home: &ResolvedHome,
    registry_path: &Path,
    policy_forced: bool,
    credentials: &C,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
{
    let config_path = home.config_path.as_path();
    let registry_result = load_registry(registry_path);
    let registry_valid = registry_result.is_ok();
    let registry_message = registry_result
        .as_ref()
        .map(|_| "ok".to_string())
        .unwrap_or_else(|err| err.to_string());
    let config_result = load_active_config(home);
    let config_valid = config_result.is_ok();
    let config_message = config_result
        .as_ref()
        .map(|_| "ok".to_string())
        .unwrap_or_else(|err| err.to_string());
    let config_exists = match std::fs::symlink_metadata(config_path) {
        Ok(_) => true,
        Err(err) => err.kind() != std::io::ErrorKind::NotFound,
    };
    let policy = describe_policy(&home.policy_path, policy_forced);
    let audit_writable = audit::is_writable(&home.audit_path);
    let health = credentials
        .health_check()
        .unwrap_or_else(|err| CredentialStoreHealth {
            backend: std::env::consts::OS.to_string(),
            available: false,
            message: format!("credential store unavailable: {err}"),
        });
    let missing_credentials = config_result
        .as_ref()
        .map(|config| missing_credentials(credentials, config))
        .unwrap_or_default();
    let library_versions = runtime_library_versions();

    if args.json {
        let output = json!({
            "ok": true,
            "home": home.root,
            "home_source": home.description,
            "registry_path": registry_path,
            "registry_valid": registry_valid,
            "registry_message": registry_message,
            "config_path": config_path,
            "config_exists": config_exists,
            "config_valid": config_valid,
            "config_message": config_message,
            "known_hosts_path": home.known_hosts_path,
            "policy_path": home.policy_path,
            "policy_present": policy.present,
            "policy_valid": policy.valid,
            "policy_enabled": policy.enabled,
            "audit_path": home.audit_path,
            "audit_writable": audit_writable,
            "credential_namespace": home.namespace.token(),
            "os": std::env::consts::OS,
            "libssh2_version": library_versions.libssh2,
            "openssl_version": library_versions.openssl,
            "credential_backend": health.backend,
            "credential_available": health.available,
            "credential_message": health.message,
            "missing_credentials": missing_credentials,
        });
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    let mut stdout = format!(
        "home: {}\nhome source: {}\nregistry path: {}\nregistry valid: {}\nregistry message: {}\nconfig path: {}\nconfig exists: {}\nconfig valid: {}\nconfig message: {}\nknown_hosts path: {}\npolicy path: {}\npolicy present: {}\npolicy valid: {}\npolicy enabled: {}\naudit path: {}\naudit writable: {}\ncredential namespace: {}\nos: {}\nlibssh2 version: {}\nopenssl version: {}\ncredential backend: {}\ncredential available: {}\ncredential message: {}\n",
        home.root.display(),
        home.description,
        registry_path.display(),
        registry_valid,
        registry_message,
        config_path.display(),
        config_exists,
        config_valid,
        config_message,
        home.known_hosts_path.display(),
        home.policy_path.display(),
        policy.present,
        policy.valid,
        policy.enabled,
        home.audit_path.display(),
        audit_writable,
        home.namespace.token(),
        std::env::consts::OS,
        library_versions.libssh2,
        library_versions.openssl,
        health.backend,
        health.available,
        health.message
    );
    if !missing_credentials.is_empty() {
        stdout.push_str(&format!(
            "missing credential entries: {}\n",
            missing_credentials.join(", ")
        ));
    }
    Ok(ok(stdout))
}

fn resolve_auth<C>(
    account: &AccountConfig,
    login_user: &str,
    credentials: &C,
) -> anyhow::Result<AuthMaterial>
where
    C: CredentialStore,
{
    match &account.auth {
        AuthConfig::Password { credential } => {
            let password = credentials
                .get_password_for(CredentialPurpose::Login, credential, login_user)
                .with_error_kind(ErrorKind::Auth)
                .with_context(|| {
                    format!(
                        "missing credential entry for {} and user {}",
                        credential, login_user
                    )
                })?;
            Ok(AuthMaterial::Password(password))
        }
        AuthConfig::Agent => Ok(AuthMaterial::Agent),
    }
}

/// Split a positional `target` into its optional leading server name and the
/// `fixed` trailing positionals the command requires. The name is present
/// exactly when one extra argument was passed (`run` has 1 fixed arg, `put` and
/// `get` have 2). Returns `None` when the count is neither `fixed` nor
/// `fixed + 1`, which the parser's `num_args` normally prevents. Shared by
/// `audit_descriptor` and the `resolve_*_target` helpers so the "[name] comes
/// first" rule lives in one place and the audit log can't drift from what runs.
fn split_target(target: &[String], fixed: usize) -> Option<(Option<&str>, &[String])> {
    match target.len() {
        n if n == fixed => Some((None, target)),
        n if n == fixed + 1 => Some((Some(target[0].as_str()), &target[1..])),
        _ => None,
    }
}

/// Resolve the server name for a target, falling back to the configured default
/// when the caller did not name one explicitly.
fn resolve_target_server(name: Option<&str>, config: &SshwConfig) -> anyhow::Result<String> {
    match name {
        Some(name) => Ok(name.to_string()),
        None => default_server_name(config),
    }
}

fn resolve_run_target(
    target: Vec<String>,
    config: &SshwConfig,
) -> anyhow::Result<(String, String)> {
    let (name, rest) = split_target(&target, 1)
        .ok_or_else(|| app_error(ErrorKind::Config, "run expects [name] <command>"))?;
    Ok((resolve_target_server(name, config)?, rest[0].clone()))
}

fn default_server_name(config: &SshwConfig) -> anyhow::Result<String> {
    config.default.clone().ok_or_else(no_default_server_error)
}

fn no_default_server_error() -> anyhow::Error {
    app_error(
        ErrorKind::Config,
        "no default server configured; run 'sshw default <name>' to set one or pass an explicit server name",
    )
}

fn get_server<'a>(config: &'a SshwConfig, name: &str) -> anyhow::Result<&'a ServerConfig> {
    config.servers.get(name).ok_or_else(|| unknown_server(name))
}

fn select_account<'a>(
    server_name: &str,
    server: &'a ServerConfig,
    requested_user: Option<&str>,
) -> anyhow::Result<(&'a str, &'a AccountConfig)> {
    let user = requested_user.unwrap_or(&server.default_user);
    server
        .accounts
        .get_key_value(user)
        .map(|(user, account)| (user.as_str(), account))
        .ok_or_else(|| account::unknown_account(server_name, user))
}

fn unknown_server(name: &str) -> anyhow::Error {
    app_error(ErrorKind::Config, format!("unknown server '{name}'"))
}

fn missing_credentials<C>(credentials: &C, config: &SshwConfig) -> Vec<String>
where
    C: CredentialStore,
{
    config
        .servers
        .iter()
        .flat_map(|(name, server)| {
            server
                .accounts
                .iter()
                .filter_map(move |(user, account)| match &account.auth {
                    AuthConfig::Password { credential } => credentials
                        .get_password_for(CredentialPurpose::Login, credential, user)
                        .err()
                        .map(|_| format!("{name}/{user}")),
                    AuthConfig::Agent => None,
                })
        })
        .collect()
}

fn ok(stdout: String) -> CommandOutput {
    CommandOutput {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

fn error_output(err: &anyhow::Error, json_errors: bool) -> CommandOutput {
    let response = ErrorResponse::from_error(err);
    let exit_code = response.error.exit_code;

    if json_errors {
        return CommandOutput {
            stdout: error_json_line(&response),
            stderr: String::new(),
            exit_code,
        };
    }

    CommandOutput {
        stdout: String::new(),
        stderr: format!("{}\n", response.error.message),
        exit_code,
    }
}

fn error_json_line(response: &ErrorResponse) -> String {
    match serde_json::to_string(response) {
        Ok(body) => format!("{body}\n"),
        Err(err) => {
            let fallback = ErrorResponse {
                ok: false,
                error: crate::output::ErrorBody {
                    kind: ErrorKind::Unknown,
                    message: format!("failed to serialize error response: {err}"),
                    causes: Vec::new(),
                    exit_code: ErrorKind::Unknown.exit_code(),
                },
            };
            match serde_json::to_string(&fallback) {
                Ok(body) => format!("{body}\n"),
                Err(_) => {
                    "{\"ok\":false,\"error\":{\"kind\":\"unknown\",\"message\":\"failed to serialize error response\",\"exit_code\":1}}\n".to_string()
                }
            }
        }
    }
}

fn print_output(output: CommandOutput) -> i32 {
    let stdout = io::stdout();
    let stderr = io::stderr();
    let result = write_command_output(&output, &mut stdout.lock(), &mut stderr.lock());
    output_exit_code(output.exit_code, result)
}

fn write_command_output<W, E>(
    output: &CommandOutput,
    stdout: &mut W,
    stderr: &mut E,
) -> io::Result<()>
where
    W: Write,
    E: Write,
{
    stdout.write_all(output.stdout.as_bytes())?;
    stdout.flush()?;
    stderr.write_all(output.stderr.as_bytes())?;
    stderr.flush()
}

fn output_exit_code(intended: i32, write_result: io::Result<()>) -> i32 {
    match write_result {
        Ok(()) => intended,
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => intended,
        Err(_) => ErrorKind::Io.exit_code(),
    }
}

/// Whether `--json` appears in the process arguments. Parsing already failed by
/// the time this is consulted, so the raw args are scanned directly to decide
/// how to format a clap usage error.
fn json_requested_in_args() -> bool {
    json_requested_in_args_iter(std::env::args_os().skip(1))
}

fn json_requested_in_args_iter<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    for arg in args {
        let arg = arg.as_ref();
        if arg == OsStr::new("--") {
            return false;
        }
        if arg == OsStr::new("--json") {
            return true;
        }
    }
    false
}

/// Map a clap parse failure to a [`CommandOutput`]. Help/version requests are
/// not errors: clap renders them to stdout and the process exits 0. Genuine
/// usage errors get the dedicated `usage` kind / exit code 9 (distinct from the
/// safety code 2), surfaced as a JSON envelope on stdout when `--json` was
/// requested, or clap's formatted message on stderr otherwise.
fn parse_error_output(err: clap::Error, json: bool) -> CommandOutput {
    use clap::error::ErrorKind as ClapErrorKind;

    if matches!(
        err.kind(),
        ClapErrorKind::DisplayHelp
            | ClapErrorKind::DisplayVersion
            | ClapErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    ) {
        return CommandOutput {
            stdout: err.render().to_string(),
            stderr: String::new(),
            exit_code: 0,
        };
    }

    let kind = ErrorKind::Usage;
    let exit_code = kind.exit_code();
    let rendered = err.render().to_string();

    if json {
        let response = ErrorResponse {
            ok: false,
            error: crate::output::ErrorBody {
                kind,
                message: clap_usage_summary(&rendered),
                causes: Vec::new(),
                exit_code,
            },
        };
        return CommandOutput {
            stdout: error_json_line(&response),
            stderr: String::new(),
            exit_code,
        };
    }

    CommandOutput {
        stdout: String::new(),
        stderr: rendered,
        exit_code,
    }
}

/// Condense clap's multi-line usage error into a concise single-line message for
/// the JSON envelope (the first non-empty line, minus clap's `error: ` prefix).
fn clap_usage_summary(rendered: &str) -> String {
    rendered
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| line.trim_start_matches("error: ").to_string())
        .unwrap_or_else(|| rendered.trim().to_string())
}

#[cfg(test)]
mod runtime_backend_tests {
    use super::*;
    use crate::audit::NoopAudit;
    use crate::config::{CredentialBackend, save_config};
    use crate::credentials::{CredentialStore, CredentialStoreHealth};
    use crate::home::ResolvedHome;
    use crate::ssh::{HostKeyInfo, RunResult, TransferResult};
    use std::cell::Cell;

    struct NamedCredentialStore(&'static str);

    impl CredentialStore for NamedCredentialStore {
        fn set_password(
            &self,
            _credential: &str,
            _user: &str,
            _password: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        fn get_password(&self, _credential: &str, _user: &str) -> anyhow::Result<String> {
            Err(anyhow::anyhow!("missing credential"))
        }

        fn delete_password(&self, _credential: &str, _user: &str) -> anyhow::Result<()> {
            Ok(())
        }

        fn health_check(&self) -> anyhow::Result<CredentialStoreHealth> {
            Ok(CredentialStoreHealth {
                backend: self.0.to_string(),
                available: true,
                message: "ok".to_string(),
            })
        }
    }

    struct NoopSsh;

    impl SshClient for NoopSsh {
        fn host_key(&self, _server: &ServerConfig) -> anyhow::Result<HostKeyInfo> {
            unreachable!("doctor does not query host keys")
        }

        fn trust_host(
            &self,
            _server_name: &str,
            _server: &ServerConfig,
            _expected_fingerprint_sha256: &str,
        ) -> anyhow::Result<HostKeyInfo> {
            unreachable!("doctor does not trust hosts")
        }

        fn run(
            &self,
            _target: &SshTarget<'_>,
            _auth: &AuthMaterial,
            _command: &str,
        ) -> anyhow::Result<RunResult> {
            unreachable!("doctor does not run commands")
        }

        fn put(
            &self,
            _target: &SshTarget<'_>,
            _auth: &AuthMaterial,
            _local: &Path,
            _remote: &str,
        ) -> anyhow::Result<TransferResult> {
            unreachable!("doctor does not transfer files")
        }

        fn get(
            &self,
            _target: &SshTarget<'_>,
            _auth: &AuthMaterial,
            _remote: &str,
            _local: &Path,
            _overwrite: bool,
        ) -> anyhow::Result<TransferResult> {
            unreachable!("doctor does not transfer files")
        }
    }

    #[derive(Default)]
    struct NoopPrompter;

    impl Prompter for NoopPrompter {
        fn confirm(&mut self, _prompt: &str) -> anyhow::Result<bool> {
            unreachable!("doctor does not prompt")
        }

        fn password(&mut self, _prompt: &str) -> anyhow::Result<String> {
            unreachable!("doctor does not prompt")
        }

        fn password_stdin(&mut self) -> anyhow::Result<String> {
            unreachable!("doctor does not read stdin")
        }
    }

    #[test]
    fn session_only_config_routes_runtime_to_session_backend() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("servers.json");
        let config = SshwConfig {
            credential_backend: CredentialBackend::SessionOnly,
            ..SshwConfig::default()
        };
        save_config(&path, &config).unwrap();
        let home = ResolvedHome::from_config_path(&path);
        let registry = temp.path().join("profiles.json");
        let audit = NoopAudit;
        let ctx = ExecContext {
            home: &home,
            registry_path: &registry,
            policy_forced: false,
            audit: &audit,
        };
        let mut prompter = NoopPrompter;

        let output = execute_for_runtime_selecting_backend(
            Cli::try_parse_from(["sshw", "doctor", "--json"]).unwrap(),
            &ctx,
            &NamedCredentialStore("native-probe"),
            || NamedCredentialStore("session-probe"),
            &NoopSsh,
            &mut prompter,
        );

        let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(json["credential_backend"], json!("session-probe"));
    }

    #[test]
    fn native_config_does_not_construct_session_backend() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("servers.json");
        save_config(&path, &SshwConfig::default()).unwrap();
        let home = ResolvedHome::from_config_path(&path);
        let registry = temp.path().join("profiles.json");
        let audit = NoopAudit;
        let ctx = ExecContext {
            home: &home,
            registry_path: &registry,
            policy_forced: false,
            audit: &audit,
        };
        let session_constructed = Cell::new(false);
        let mut prompter = NoopPrompter;

        let output = execute_for_runtime_selecting_backend(
            Cli::try_parse_from(["sshw", "doctor", "--json"]).unwrap(),
            &ctx,
            &NamedCredentialStore("native-probe"),
            || {
                session_constructed.set(true);
                NamedCredentialStore("session-probe")
            },
            &NoopSsh,
            &mut prompter,
        );

        let json: serde_json::Value = serde_json::from_str(output.stdout.trim()).unwrap();
        assert_eq!(json["credential_backend"], json!("native-probe"));
        assert!(
            !session_constructed.get(),
            "native homes must not read or clear SSHW_PASSWORD"
        );
    }

    #[test]
    fn timeout_override_preserves_default_and_supports_explicit_opt_out() {
        assert_eq!(operation_timeout_override(None), None);
        assert_eq!(operation_timeout_override(Some(0)), Some(None));
        assert_eq!(
            operation_timeout_override(Some(12)),
            Some(Some(Duration::from_secs(12)))
        );
    }

    #[test]
    fn explicit_home_resolution_does_not_load_corrupt_registry() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("profiles.json"), "{").unwrap();
        let home = temp.path().join("ad-hoc");
        let cli = Cli::try_parse_from(["sshw", "--home", home.to_str().unwrap(), "list"]).unwrap();

        let (resolved, registry_path) = resolve_runtime_with_base(&cli, temp.path(), None).unwrap();

        assert_eq!(resolved.root, home);
        assert_eq!(registry_path, temp.path().join("profiles.json"));
    }

    #[test]
    fn doctor_falls_back_only_when_the_registry_is_invalid() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("profiles.json"),
            r#"{"version":1,"default":"legacy","profiles":{"legacy":{"id":"p_legacy","home":"relative/home"}}}"#,
        )
        .unwrap();

        let doctor = Cli::try_parse_from(["sshw", "doctor", "--json"]).unwrap();
        let (resolved, _) = resolve_runtime_with_base(&doctor, temp.path(), None).unwrap();
        assert_eq!(resolved.root, temp.path().join("profiles").join("default"));

        let explicit_home = temp.path().join("explicit");
        let conflicting = Cli::try_parse_from([
            "sshw",
            "--home",
            explicit_home.to_str().unwrap(),
            "--profile",
            "legacy",
            "doctor",
        ])
        .unwrap();
        assert!(resolve_runtime_with_base(&conflicting, temp.path(), None).is_err());

        let list = Cli::try_parse_from(["sshw", "list"]).unwrap();
        assert!(resolve_runtime_with_base(&list, temp.path(), None).is_err());

        std::fs::write(
            temp.path().join("profiles.json"),
            r#"{"version":1,"default":null,"profiles":{}}"#,
        )
        .unwrap();
        let unknown = Cli::try_parse_from(["sshw", "--profile", "missing", "doctor"]).unwrap();
        assert!(resolve_runtime_with_base(&unknown, temp.path(), None).is_err());
    }

    #[test]
    fn profile_remove_reaches_the_recovery_loader() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("profiles.json"), "{").unwrap();
        let remove = Cli::try_parse_from(["sshw", "profile", "remove", "legacy"]).unwrap();

        let (resolved, _) = resolve_runtime_with_base(&remove, temp.path(), None).unwrap();

        assert_eq!(resolved.root, temp.path().join("profiles").join("default"));
    }

    #[test]
    fn all_profile_commands_use_the_global_profile_audit_path() {
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join("profiles.json");
        let active =
            ResolvedHome::ad_hoc(&temp.path().join("active"), "active test home".to_string());
        let expected = temp
            .path()
            .join("profiles")
            .join("default")
            .join("audit.jsonl");
        let profile_home = temp.path().join("prod");
        let commands = [
            Cli::try_parse_from([
                "sshw",
                "--home",
                profile_home.to_str().unwrap(),
                "profile",
                "add",
                "prod",
            ])
            .unwrap(),
            Cli::try_parse_from(["sshw", "profile", "default", "prod"]).unwrap(),
            Cli::try_parse_from(["sshw", "profile", "remove", "prod"]).unwrap(),
        ];

        for cli in commands {
            assert_eq!(runtime_audit_path(&cli, &active, &registry), expected);
        }

        let list = Cli::try_parse_from(["sshw", "list"]).unwrap();
        assert_eq!(
            runtime_audit_path(&list, &active, &registry),
            active.audit_path
        );
    }
}

#[cfg(test)]
mod parse_error_tests {
    use super::*;
    use crate::output::ErrorKind;
    use std::io::{self, Write};

    fn parse_err(args: &[&str]) -> clap::Error {
        Cli::try_parse_from(args).unwrap_err()
    }

    #[test]
    fn usage_error_is_exit_9_on_stderr_without_json() {
        let out = parse_error_output(parse_err(&["sshw", "--definitely-not-a-flag"]), false);
        assert_eq!(out.exit_code, ErrorKind::Usage.exit_code());
        assert_eq!(out.exit_code, 9);
        assert!(out.stdout.is_empty());
        assert!(!out.stderr.is_empty());
    }

    #[test]
    fn usage_error_emits_json_envelope_with_usage_kind() {
        let out = parse_error_output(parse_err(&["sshw", "--definitely-not-a-flag"]), true);
        assert_eq!(out.exit_code, 9);
        assert!(out.stderr.is_empty());
        let value: serde_json::Value = serde_json::from_str(out.stdout.trim()).unwrap();
        assert_eq!(value["ok"], json!(false));
        assert_eq!(value["error"]["kind"], json!("usage"));
        assert_eq!(value["error"]["exit_code"], json!(9));
        assert!(value["error"]["message"].as_str().is_some());
    }

    #[test]
    fn help_request_exits_zero_to_stdout() {
        let out = parse_error_output(parse_err(&["sshw", "--help"]), false);
        assert_eq!(out.exit_code, 0);
        assert!(!out.stdout.is_empty());
        assert!(out.stderr.is_empty());
    }

    #[test]
    fn raw_json_detection_stops_at_the_end_of_options_marker() {
        assert!(json_requested_in_args_iter(["run", "--json"]));
        assert!(!json_requested_in_args_iter(["run", "--", "--json"]));
    }

    struct BrokenPipeWriter;

    impl Write for BrokenPipeWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed pipe"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn broken_pipe_preserves_an_intended_failure_exit() {
        let output = CommandOutput {
            stdout: "payload".to_string(),
            stderr: String::new(),
            exit_code: 7,
        };
        let result = write_command_output(&output, &mut BrokenPipeWriter, &mut Vec::new());

        assert_eq!(output_exit_code(output.exit_code, result), 7);
    }

    #[test]
    fn broken_pipe_is_normal_termination_for_successful_output() {
        let output = CommandOutput {
            stdout: "payload".to_string(),
            stderr: String::new(),
            exit_code: 0,
        };
        let result = write_command_output(&output, &mut BrokenPipeWriter, &mut Vec::new());

        assert_eq!(output_exit_code(output.exit_code, result), 0);
    }

    #[test]
    fn non_pipe_output_failure_is_an_io_error() {
        let result = Err(io::Error::other("console unavailable"));

        assert_eq!(output_exit_code(0, result), ErrorKind::Io.exit_code());
    }
}

#[cfg(test)]
mod sudo_command_tests {
    use super::{shell_quote, sudo_command};

    /// Inverse of `shell_quote` for the forms it produces. Used to peel the
    /// outer `sh -c '<script>'` wrapper so the inner script can be inspected.
    /// `shell_quote` replaces every `'` with `'"'"'`, so reversing that on the
    /// stripped body reconstructs the original exactly.
    fn shell_unquote(quoted: &str) -> String {
        let inner = quoted
            .strip_prefix('\'')
            .and_then(|rest| rest.strip_suffix('\''))
            .expect("shell_quote output is single-quoted");
        inner.replace("'\"'\"'", "'")
    }

    #[test]
    fn shell_quote_round_trips_metacharacters_through_single_quotes() {
        // Metacharacters land inside a single-quoted literal (inert to sh) and
        // embedded single quotes use the POSIX '"'"' escape. If quoting ever
        // weakens, these exact strings change and the test fails.
        let cases = [
            ("root", "'root'"),
            ("id -u", "'id -u'"),
            ("a'b", "'a'\"'\"'b'"),
            ("'; reboot #", "''\"'\"'; reboot #'"),
            ("$(reboot)", "'$(reboot)'"),
            ("`reboot`", "'`reboot`'"),
            ("a && b", "'a && b'"),
        ];
        for (input, expected) in cases {
            assert_eq!(shell_quote(input), expected, "input: {input}");
        }
    }

    #[test]
    fn sudo_command_separates_password_stdin_from_target() {
        let assembled = sudo_command("id -u", "root");
        // The whole thing runs under one `sh -c '<script>'`.
        assert!(assembled.starts_with("sh -c '"), "got: {assembled}");
        assert!(assembled.ends_with('\''));
        // Password is consumed from stdin for `sudo -S -v` auth only...
        assert!(assembled.contains("IFS= read -r sshw_sudo_password"));
        assert!(assembled.contains("sudo -S -p"));
        // ...and the target runs non-interactively with stdin detached, so the
        // password line can never reach the target command's stdin.
        assert!(assembled.contains("sudo -n -p"));
        assert!(assembled.contains("< /dev/null"));
    }

    #[test]
    fn sudo_command_keeps_injected_user_and_command_quoted() {
        // Inject shell metacharacters into both user and command.
        let assembled = sudo_command("id; reboot", "ro'ot");
        let script = shell_unquote(assembled.strip_prefix("sh -c ").expect("sh -c prefix"));

        // User and command appear only via their quoted forms, so a `;` or an
        // embedded quote cannot split off a new command in the inner script.
        assert!(script.contains(&format!("-u {}", shell_quote("ro'ot"))));
        assert!(script.contains(&format!("sh -lc {}", shell_quote("id; reboot"))));
        // The raw injected command must not appear unquoted after `sh -lc `.
        assert!(!script.contains("sh -lc id; reboot"));
    }
}
