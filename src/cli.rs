use crate::audit::{self, AuditRecord, AuditSink, AuditStatus, FileAuditSink, NoopAudit};
use crate::config::{
    AuthConfig, CredentialBackend, ServerConfig, SshwConfig, load_config, save_config,
};
use crate::credentials::keyring_store::KeyringCredentialStore;
use crate::credentials::session_store::SessionOnlyStore;
use crate::credentials::{AuthMaterial, CredentialStore, CredentialStoreHealth};
use crate::home::{CredentialNamespace, ResolvedHome, generate_profile_id, sshw_base_dir};
use crate::output::{
    ErrorKind, ErrorResponse, RunOutput, ServerOutput, filter_startup_stderr_noise, redact_secrets,
};
use crate::policy::{Policy, describe_policy, resolve_policy};
use crate::profile::{
    ProfileEntry, ProfileRegistry, load_registry, resolve_home_with_registry, save_registry,
};
use crate::safety::{SafetyDecision, classify_command, classify_remote_write_path};
use crate::sandbox::{NoopSandbox, PolicyOnlySandbox, Sandbox, SandboxDecision};
use crate::ssh::SshClient;
use crate::ssh::ssh2_client::Ssh2Client;
use anyhow::Context;
use clap::Parser;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::Duration;

mod model;
mod prompt;

pub use model::{
    AddArgs, AuthArg, Cli, Command, DefaultArgs, DoctorArgs, GetArgs, ListArgs, ProfileAddArgs,
    ProfileArgs, ProfileCommand, ProfileDefaultArgs, ProfileListArgs, ProfileRemoveArgs,
    ProfileShowArgs, PutArgs, RemoveArgs, RunArgs, ShowArgs, TrustArgs,
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
/// profile registry. Grows in later milestones (policy, audit).
pub struct ExecContext<'a> {
    pub home: &'a ResolvedHome,
    pub registry_path: &'a Path,
    /// The `--policy` flag: force policy enforcement for this invocation.
    pub policy_forced: bool,
    pub audit: &'a dyn AuditSink,
}

pub fn run() -> i32 {
    let cli = Cli::parse();
    let json_errors = cli.command.wants_json_errors();
    let (home, registry_path) = match resolve_runtime(&cli) {
        Ok(resolved) => resolved,
        Err(err) => return print_output(error_output(&err, json_errors)),
    };
    // Connection setup keeps the fixed connect timeout; the operation phase
    // uses the optional `--timeout` (0/absent = no timeout).
    let op_timeout = cli
        .timeout
        .and_then(|secs| (secs > 0).then(|| Duration::from_secs(secs)));
    let ssh = Ssh2Client::default()
        .with_known_hosts(home.known_hosts_path.clone())
        .with_op_timeout(op_timeout);
    let mut prompter = TerminalPrompter;
    let audit = FileAuditSink::new(home.audit_path.clone());
    let ctx = ExecContext {
        home: &home,
        registry_path: &registry_path,
        policy_forced: cli.policy,
        audit: &audit,
    };

    // Select the credential backend from the home's config (default native).
    let backend = load_config(&home.config_path)
        .map(|config| config.credential_backend)
        .unwrap_or_default();
    let output = match backend {
        CredentialBackend::Native => {
            execute_for_runtime_with(cli, &ctx, &KeyringCredentialStore, &ssh, &mut prompter)
        }
        CredentialBackend::SessionOnly => execute_for_runtime_with(
            cli,
            &ctx,
            &SessionOnlyStore::from_env(),
            &ssh,
            &mut prompter,
        ),
    };

    print_output(output)
}

fn resolve_runtime(cli: &Cli) -> anyhow::Result<(ResolvedHome, PathBuf)> {
    let sshw_base = sshw_base_dir()?;
    let registry_path = sshw_base.join("profiles.json");
    let registry = load_registry(&registry_path)?;
    let env_home = std::env::var_os("SSHW_HOME").filter(|value| !value.is_empty());
    let home = resolve_home_with_registry(
        cli.home.as_deref(),
        env_home.as_deref(),
        cli.profile.as_deref(),
        &registry,
        &sshw_base,
    )?;
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
    let mut config = load_config(config_path)?;

    let descriptor = audit_descriptor(&command, &config);
    // Captured before `command` is consumed by dispatch: used to remap a remote
    // command's exit code after auditing the real status.
    let is_run = matches!(&command, Command::Run(_));
    let run_json = matches!(&command, Command::Run(args) if args.json);

    let result = match command {
        Command::Add(args) => add_server(
            args,
            config_path,
            &ctx.home.namespace,
            credentials,
            prompter,
            &mut config,
        ),
        Command::List(args) => list_servers(args, &config),
        Command::Show(args) => show_server(args, &config),
        Command::Default(args) => default_server(args, config_path, &mut config),
        Command::Trust(args) => trust_server(args, ssh, prompter, &config),
        Command::Run(args) => {
            let sandbox = build_sandbox(&ctx.home.policy_path, ctx.policy_forced)?;
            run_remote(args, sandbox.as_ref(), credentials, ssh, &config)
        }
        Command::Put(args) => {
            let sandbox = build_sandbox(&ctx.home.policy_path, ctx.policy_forced)?;
            put_file(args, sandbox.as_ref(), credentials, ssh, &config)
        }
        Command::Get(args) => {
            let sandbox = build_sandbox(&ctx.home.policy_path, ctx.policy_forced)?;
            get_file(args, sandbox.as_ref(), credentials, ssh, &config)
        }
        Command::Remove(args) => {
            remove_server(args, config_path, credentials, prompter, &mut config)
        }
        Command::Doctor(args) => doctor(
            args,
            ctx.home,
            ctx.registry_path,
            ctx.policy_forced,
            credentials,
            &config,
        ),
        Command::Profile(args) => run_profile(args, ctx.registry_path, home_flag.as_deref()),
    };

    if let Some((action, server, detail)) = descriptor {
        let (status, exit_code) = match &result {
            Ok(output) => (AuditStatus::Ok, output.exit_code),
            Err(err) => (
                AuditStatus::Error,
                ErrorResponse::from_error(err).error.exit_code,
            ),
        };
        // Best-effort: an audit write failure must not fail the operation.
        let _ = ctx.audit.record(&AuditRecord {
            action: action.to_string(),
            server,
            detail,
            status,
            exit_code,
        });
    }

    // Remap a remote command's non-zero exit (recorded above) so it cannot be
    // confused with sshw's own operational exit codes.
    result.map(|output| remap_remote_nonzero_exit(output, is_run, run_json))
}

/// Remap a remote command's non-zero exit to [`crate::output::REMOTE_NONZERO_EXIT_CODE`]
/// so it can never collide with sshw's operational exit codes (1-7). Applied
/// after auditing, which records the real remote status. In non-JSON mode a
/// human-readable note carries the real status; JSON output already includes
/// `exit_status`.
fn remap_remote_nonzero_exit(mut output: CommandOutput, is_run: bool, json: bool) -> CommandOutput {
    if is_run && output.exit_code != 0 {
        if !json {
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
fn audit_descriptor(
    command: &Command,
    config: &SshwConfig,
) -> Option<(&'static str, Option<String>, Option<String>)> {
    let default = || config.default.clone();
    match command {
        Command::Add(a) => Some(("add", Some(a.name.clone()), None)),
        Command::Remove(a) => Some(("remove", Some(a.name.clone()), None)),
        Command::Trust(a) => Some(("trust", Some(a.name.clone()), None)),
        Command::Default(a) => Some(("default", a.name.clone().or_else(default), None)),
        Command::Run(a) => {
            let (server, command) = match a.target.as_slice() {
                [name, command] => (Some(name.clone()), Some(command.clone())),
                [command] => (default(), Some(command.clone())),
                _ => (default(), None),
            };
            // Record only the program name, never the full argument string, so
            // secrets passed inline (e.g. `mysql -phunter2`) are not persisted.
            let program = command
                .as_deref()
                .and_then(|c| c.split_whitespace().next())
                .map(str::to_string);
            Some(("run", server, program))
        }
        Command::Put(a) => {
            let (server, detail) = match a.target.as_slice() {
                [name, _local, remote] => (Some(name.clone()), Some(remote.clone())),
                [_local, remote] => (default(), Some(remote.clone())),
                _ => (default(), None),
            };
            Some(("put", server, detail))
        }
        Command::Get(a) => {
            let (server, detail) = match a.target.as_slice() {
                [name, remote, _local] => (Some(name.clone()), Some(remote.clone())),
                [remote, _local] => (default(), Some(remote.clone())),
                _ => (default(), None),
            };
            Some(("get", server, detail))
        }
        _ => None,
    }
}

fn build_sandbox(policy_path: &Path, forced: bool) -> anyhow::Result<Box<dyn Sandbox>> {
    match resolve_policy(policy_path, forced)? {
        Policy::Disabled => Ok(Box::new(NoopSandbox)),
        Policy::Enabled(rules) => Ok(Box::new(PolicyOnlySandbox::new(rules))),
    }
}

fn add_server<C, P>(
    args: AddArgs,
    config_path: &Path,
    namespace: &CredentialNamespace,
    credentials: &C,
    prompter: &mut P,
    config: &mut SshwConfig,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
    P: Prompter,
{
    let previous_server = config.servers.get(&args.name).cloned();
    if previous_server.is_some()
        && !args.force
        && !prompter.confirm(&format!("update existing server '{}'? [y/N] ", args.name))?
    {
        return Err(anyhow::anyhow!("add cancelled"));
    }

    let auth = match args.auth {
        AuthArg::Password => {
            let credential = namespace.credential_key(&args.name);
            let password = prompter.password("SSH password: ")?;
            if password.is_empty() {
                return Err(anyhow::anyhow!("password cannot be empty"));
            }
            credentials.set_password(&credential, &args.user, &password)?;
            AuthConfig::Password { credential }
        }
        AuthArg::Agent => AuthConfig::Agent,
    };

    let new_server = ServerConfig {
        host: args.host,
        port: args.port,
        user: args.user,
        auth,
    };
    let stale_credential = stale_password_credential(previous_server.as_ref(), &new_server);
    config.servers.insert(args.name.clone(), new_server);

    if config.default.is_none() {
        config.default = Some(args.name.clone());
    }

    save_config(config_path, config)?;
    if let Some((credential, user)) = stale_credential {
        credentials.delete_password(&credential, &user)?;
    }

    let mut message = format!(
        "{} {}\n",
        if previous_server.is_some() {
            "updated"
        } else {
            "added"
        },
        args.name
    );
    if matches!(args.auth, AuthArg::Password) && !credentials.is_persistent() {
        message.push_str(
            "warning: this credential backend does not persist passwords; supply SSHW_PASSWORD at run time\n",
        );
    }
    Ok(ok(message))
}

fn list_servers(args: ListArgs, config: &SshwConfig) -> anyhow::Result<CommandOutput> {
    let servers = server_outputs(config);
    if args.json {
        return Ok(ok(format!("{}\n", serde_json::to_string(&servers)?)));
    }

    let mut stdout = String::new();
    for server in servers {
        let marker = if server.is_default { "*" } else { " " };
        stdout.push_str(&format!(
            "{marker} {} {}:{} user={} auth={}\n",
            server.name,
            server.host,
            server.port,
            server.user,
            auth_label(&server.auth)
        ));
    }
    Ok(ok(stdout))
}

fn show_server(args: ShowArgs, config: &SshwConfig) -> anyhow::Result<CommandOutput> {
    let server = get_server(config, &args.name)?;
    let output = ServerOutput::from_config(
        &args.name,
        server,
        config.default.as_deref() == Some(args.name.as_str()),
    );

    if args.json {
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    Ok(ok(format!(
        "{}\n  host: {}\n  port: {}\n  user: {}\n  auth: {}\n",
        output.name,
        output.host,
        output.port,
        output.user,
        auth_label(&output.auth)
    )))
}

fn default_server(
    args: DefaultArgs,
    config_path: &Path,
    config: &mut SshwConfig,
) -> anyhow::Result<CommandOutput> {
    let Some(name) = args.name else {
        let name = config
            .default
            .as_ref()
            .ok_or_else(no_default_server_error)?;
        return Ok(ok(format!("{name}\n")));
    };

    if !config.servers.contains_key(&name) {
        return Err(unknown_server(&name));
    }

    config.default = Some(name.clone());
    save_config(config_path, config)?;
    Ok(ok(format!("default set to {name}\n")))
}

fn trust_server<S, P>(
    args: TrustArgs,
    ssh: &S,
    prompter: &mut P,
    config: &SshwConfig,
) -> anyhow::Result<CommandOutput>
where
    S: SshClient,
    P: Prompter,
{
    let server = get_server(config, &args.name)?;
    let host_key = ssh.host_key(server)?;
    let prompt = format!(
        "trust {} {} {}? [y/N] ",
        args.name, host_key.algorithm, host_key.fingerprint_sha256
    );
    if !args.yes && !prompter.confirm(&prompt)? {
        return Err(anyhow::anyhow!("trust cancelled"));
    }

    let trusted = ssh.trust_host(&args.name, server, &host_key.fingerprint_sha256)?;
    Ok(ok(format!(
        "trusted {} {} {}\n",
        args.name, trusted.algorithm, trusted.fingerprint_sha256
    )))
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
    let RunArgs { target, json, yes } = args;
    let (server_name, command) = resolve_run_target(target, config)?;

    match classify_command(&command, yes) {
        SafetyDecision::Allow => {}
        SafetyDecision::Block { reason } => return Err(anyhow::anyhow!("{reason}")),
    }

    if let SandboxDecision::Deny { reason } = sandbox.check_command(&command) {
        return Err(anyhow::anyhow!("{reason}"));
    }

    let server = get_server(config, &server_name)?;
    let auth = resolve_auth(server, credentials)?;
    let result = ssh.run(server, &auth, &command)?;
    let exit_code = result.exit_status;
    let stdout = redact_secrets(&result.stdout);
    let stderr = redact_secrets(&filter_startup_stderr_noise(&result.stderr));

    if json {
        let output = RunOutput {
            server: server_name,
            command: redact_secrets(&command),
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

fn put_file<C, S>(
    args: PutArgs,
    sandbox: &dyn Sandbox,
    credentials: &C,
    ssh: &S,
    config: &SshwConfig,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
    S: SshClient,
{
    let PutArgs { target, yes } = args;
    let (server_name, local, remote) = resolve_put_target(target, config)?;

    match classify_remote_write_path(&remote, yes) {
        SafetyDecision::Allow => {}
        SafetyDecision::Block { reason } => return Err(anyhow::anyhow!("{reason}")),
    }

    if let SandboxDecision::Deny { reason } = sandbox.check_put(&remote) {
        return Err(anyhow::anyhow!("{reason}"));
    }

    let server = get_server(config, &server_name)?;
    let auth = resolve_auth(server, credentials)?;
    let result = ssh.put(server, &auth, &local, &remote)?;
    Ok(ok(format!(
        "uploaded {} bytes from {} to {}\n",
        result.bytes, result.source, result.destination
    )))
}

fn get_file<C, S>(
    args: GetArgs,
    sandbox: &dyn Sandbox,
    credentials: &C,
    ssh: &S,
    config: &SshwConfig,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
    S: SshClient,
{
    let GetArgs { target, yes } = args;
    let (server_name, remote, local) = resolve_get_target(target, config)?;

    let server = get_server(config, &server_name)?;
    if let SandboxDecision::Deny { reason } = sandbox.check_get(&remote) {
        return Err(anyhow::anyhow!("{reason}"));
    }

    if local.exists() && !yes {
        return Err(anyhow::anyhow!(
            "local file already exists: {}; pass --yes to overwrite",
            local.display()
        ));
    }

    let auth = resolve_auth(server, credentials)?;
    let result = ssh.get(server, &auth, &remote, &local, yes)?;
    Ok(ok(format!(
        "downloaded {} bytes from {} to {}\n",
        result.bytes, result.source, result.destination
    )))
}

fn remove_server<C, P>(
    args: RemoveArgs,
    config_path: &Path,
    credentials: &C,
    prompter: &mut P,
    config: &mut SshwConfig,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
    P: Prompter,
{
    let server = get_server(config, &args.name)?.clone();
    if !args.yes && !prompter.confirm(&format!("remove server '{}'? [y/N] ", args.name))? {
        return Err(anyhow::anyhow!("removal cancelled"));
    }

    config.servers.remove(&args.name);
    if config.default.as_deref() == Some(args.name.as_str()) {
        config.default = config.servers.keys().next().cloned();
    }

    if let AuthConfig::Password { credential } = server.auth {
        credentials.delete_password(&credential, &server.user)?;
    }

    save_config(config_path, config)?;
    Ok(ok(format!("removed {}\n", args.name)))
}

fn doctor<C>(
    args: DoctorArgs,
    home: &ResolvedHome,
    registry_path: &Path,
    policy_forced: bool,
    credentials: &C,
    config: &SshwConfig,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
{
    let config_path = home.config_path.as_path();
    let policy = describe_policy(&home.policy_path, policy_forced);
    let audit_writable = audit::is_writable(&home.audit_path);
    let health = credentials
        .health_check()
        .unwrap_or_else(|err| CredentialStoreHealth {
            backend: std::env::consts::OS.to_string(),
            available: false,
            message: format!("credential store unavailable: {err}"),
        });
    let missing_credentials = missing_credentials(credentials, config);

    if args.json {
        let output = json!({
            "home": home.root,
            "home_source": home.description,
            "registry_path": registry_path,
            "config_path": config_path,
            "config_exists": config_path.exists(),
            "known_hosts_path": home.known_hosts_path,
            "policy_path": home.policy_path,
            "policy_present": policy.present,
            "policy_valid": policy.valid,
            "policy_enabled": policy.enabled,
            "audit_path": home.audit_path,
            "audit_writable": audit_writable,
            "credential_namespace": home.namespace.token(),
            "os": std::env::consts::OS,
            "credential_backend": health.backend,
            "credential_available": health.available,
            "credential_message": health.message,
            "missing_credentials": missing_credentials,
        });
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    let mut stdout = format!(
        "home: {}\nhome source: {}\nregistry path: {}\nconfig path: {}\nconfig exists: {}\nknown_hosts path: {}\npolicy path: {}\npolicy present: {}\npolicy valid: {}\npolicy enabled: {}\naudit path: {}\naudit writable: {}\ncredential namespace: {}\nos: {}\ncredential backend: {}\ncredential available: {}\ncredential message: {}\n",
        home.root.display(),
        home.description,
        registry_path.display(),
        config_path.display(),
        config_path.exists(),
        home.known_hosts_path.display(),
        home.policy_path.display(),
        policy.present,
        policy.valid,
        policy.enabled,
        home.audit_path.display(),
        audit_writable,
        home.namespace.token(),
        std::env::consts::OS,
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

fn run_profile(
    args: ProfileArgs,
    registry_path: &Path,
    home_flag: Option<&Path>,
) -> anyhow::Result<CommandOutput> {
    let mut registry = load_registry(registry_path)?;
    match args.command {
        ProfileCommand::Add(a) => profile_add(a, home_flag, registry_path, &mut registry),
        ProfileCommand::List(a) => profile_list(a, &registry),
        ProfileCommand::Show(a) => profile_show(a, &registry),
        ProfileCommand::Default(a) => profile_default(a, registry_path, &mut registry),
        ProfileCommand::Remove(a) => profile_remove(a, registry_path, &mut registry),
    }
}

fn profile_add(
    args: ProfileAddArgs,
    home_flag: Option<&Path>,
    registry_path: &Path,
    registry: &mut ProfileRegistry,
) -> anyhow::Result<CommandOutput> {
    let home = home_flag.ok_or_else(|| anyhow::anyhow!("profile add requires --home <path>"))?;
    if registry.profiles.contains_key(&args.name) && !args.force {
        return Err(anyhow::anyhow!(
            "profile '{}' already exists; pass --force to overwrite",
            args.name
        ));
    }

    let id = generate_profile_id(&args.name, home);
    registry.profiles.insert(
        args.name.clone(),
        ProfileEntry {
            id,
            home: home.to_path_buf(),
        },
    );
    if registry.default.is_none() {
        registry.default = Some(args.name.clone());
    }

    save_registry(registry_path, registry)?;
    Ok(ok(format!(
        "added profile {} -> {}\n",
        args.name,
        home.display()
    )))
}

fn profile_list(
    args: ProfileListArgs,
    registry: &ProfileRegistry,
) -> anyhow::Result<CommandOutput> {
    if args.json {
        let entries: Vec<_> = registry
            .profiles
            .iter()
            .map(|(name, entry)| {
                json!({
                    "name": name,
                    "id": entry.id,
                    "home": entry.home,
                    "is_default": registry.default.as_deref() == Some(name),
                })
            })
            .collect();
        return Ok(ok(format!("{}\n", serde_json::to_string(&entries)?)));
    }

    let mut stdout = String::new();
    for (name, entry) in &registry.profiles {
        let marker = if registry.default.as_deref() == Some(name) {
            "*"
        } else {
            " "
        };
        stdout.push_str(&format!(
            "{marker} {name} id={} home={}\n",
            entry.id,
            entry.home.display()
        ));
    }
    Ok(ok(stdout))
}

fn profile_show(
    args: ProfileShowArgs,
    registry: &ProfileRegistry,
) -> anyhow::Result<CommandOutput> {
    let entry = registry
        .profiles
        .get(&args.name)
        .ok_or_else(|| anyhow::anyhow!("unknown profile '{}'", args.name))?;
    let is_default = registry.default.as_deref() == Some(args.name.as_str());

    if args.json {
        let output = json!({
            "name": args.name,
            "id": entry.id,
            "home": entry.home,
            "is_default": is_default,
        });
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    Ok(ok(format!(
        "{}\n  id: {}\n  home: {}\n  default: {}\n",
        args.name,
        entry.id,
        entry.home.display(),
        is_default
    )))
}

fn profile_default(
    args: ProfileDefaultArgs,
    registry_path: &Path,
    registry: &mut ProfileRegistry,
) -> anyhow::Result<CommandOutput> {
    if !registry.profiles.contains_key(&args.name) {
        return Err(anyhow::anyhow!("unknown profile '{}'", args.name));
    }

    registry.default = Some(args.name.clone());
    save_registry(registry_path, registry)?;
    Ok(ok(format!("default profile set to {}\n", args.name)))
}

fn profile_remove(
    args: ProfileRemoveArgs,
    registry_path: &Path,
    registry: &mut ProfileRegistry,
) -> anyhow::Result<CommandOutput> {
    if registry.profiles.remove(&args.name).is_none() {
        return Err(anyhow::anyhow!("unknown profile '{}'", args.name));
    }
    if registry.default.as_deref() == Some(args.name.as_str()) {
        registry.default = registry.profiles.keys().next().cloned();
    }

    save_registry(registry_path, registry)?;
    Ok(ok(format!(
        "removed profile {} (home directory and credentials left intact)\n",
        args.name
    )))
}

fn resolve_auth<C>(server: &ServerConfig, credentials: &C) -> anyhow::Result<AuthMaterial>
where
    C: CredentialStore,
{
    match &server.auth {
        AuthConfig::Password { credential } => {
            let password = credentials
                .get_password(credential, &server.user)
                .with_context(|| {
                    format!(
                        "missing credential entry for {} and user {}",
                        credential, server.user
                    )
                })?;
            Ok(AuthMaterial::Password(password))
        }
        AuthConfig::Agent => Ok(AuthMaterial::Agent),
    }
}

fn resolve_run_target(
    target: Vec<String>,
    config: &SshwConfig,
) -> anyhow::Result<(String, String)> {
    match target.as_slice() {
        [command] => Ok((default_server_name(config)?, command.clone())),
        [name, command] => Ok((name.clone(), command.clone())),
        _ => Err(anyhow::anyhow!("run expects [name] <command>")),
    }
}

fn resolve_put_target(
    target: Vec<String>,
    config: &SshwConfig,
) -> anyhow::Result<(String, PathBuf, String)> {
    match target.as_slice() {
        [local, remote] => Ok((
            default_server_name(config)?,
            PathBuf::from(local),
            remote.clone(),
        )),
        [name, local, remote] => Ok((name.clone(), PathBuf::from(local), remote.clone())),
        _ => Err(anyhow::anyhow!("put expects [name] <local> <remote>")),
    }
}

fn resolve_get_target(
    target: Vec<String>,
    config: &SshwConfig,
) -> anyhow::Result<(String, String, PathBuf)> {
    match target.as_slice() {
        [remote, local] => Ok((
            default_server_name(config)?,
            remote.clone(),
            PathBuf::from(local),
        )),
        [name, remote, local] => Ok((name.clone(), remote.clone(), PathBuf::from(local))),
        _ => Err(anyhow::anyhow!("get expects [name] <remote> <local>")),
    }
}

fn default_server_name(config: &SshwConfig) -> anyhow::Result<String> {
    config.default.clone().ok_or_else(no_default_server_error)
}

fn no_default_server_error() -> anyhow::Error {
    anyhow::anyhow!(
        "no default server configured; run 'sshw default <name>' to set one or pass an explicit server name"
    )
}

fn get_server<'a>(config: &'a SshwConfig, name: &str) -> anyhow::Result<&'a ServerConfig> {
    config.servers.get(name).ok_or_else(|| unknown_server(name))
}

fn unknown_server(name: &str) -> anyhow::Error {
    anyhow::anyhow!("unknown server '{name}'")
}

fn server_outputs(config: &SshwConfig) -> Vec<ServerOutput> {
    config
        .servers
        .iter()
        .map(|(name, server)| {
            ServerOutput::from_config(name, server, config.default.as_deref() == Some(name))
        })
        .collect()
}

fn missing_credentials<C>(credentials: &C, config: &SshwConfig) -> Vec<String>
where
    C: CredentialStore,
{
    config
        .servers
        .iter()
        .filter_map(|(name, server)| match &server.auth {
            AuthConfig::Password { credential } => credentials
                .get_password(credential, &server.user)
                .err()
                .map(|_| name.clone()),
            AuthConfig::Agent => None,
        })
        .collect()
}

fn stale_password_credential(
    previous_server: Option<&ServerConfig>,
    new_server: &ServerConfig,
) -> Option<(String, String)> {
    let previous = previous_server?;
    let AuthConfig::Password {
        credential: previous_credential,
    } = &previous.auth
    else {
        return None;
    };

    match &new_server.auth {
        AuthConfig::Password { credential }
            if credential == previous_credential && new_server.user == previous.user =>
        {
            None
        }
        _ => Some((previous_credential.clone(), previous.user.clone())),
    }
}

fn auth_label(auth: &crate::output::AuthOutput) -> &'static str {
    match auth {
        crate::output::AuthOutput::Password { .. } => "password",
        crate::output::AuthOutput::Agent => "agent",
    }
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
    print!("{}", output.stdout);
    eprint!("{}", output.stderr);
    output.exit_code
}
