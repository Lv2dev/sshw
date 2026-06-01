use crate::audit::{self, AuditRecord, AuditSink, AuditStatus, FileAuditSink, NoopAudit};
use crate::config::{AuthConfig, CredentialBackend, ServerConfig, SshwConfig, load_config};
use crate::credentials::keyring_store::KeyringCredentialStore;
use crate::credentials::session_store::SessionOnlyStore;
use crate::credentials::{AuthMaterial, CredentialStore, CredentialStoreHealth};
use crate::home::{ResolvedHome, sshw_base_dir};
use crate::output::{
    ErrorKind, ErrorResponse, RunOutput, filter_startup_stderr_noise, redact_secrets,
};
use crate::policy::{Policy, describe_policy, resolve_policy};
use crate::profile::{load_registry, resolve_home_with_registry};
use crate::safety::{SafetyDecision, classify_command};
use crate::sandbox::{NoopSandbox, PolicyOnlySandbox, Sandbox, SandboxDecision};
use crate::ssh::SshClient;
use crate::ssh::ssh2_client::{Ssh2Client, runtime_library_versions};
use anyhow::Context;
use clap::Parser;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::Duration;

mod model;
mod profile;
mod prompt;
mod server;
mod transfer;

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
        Command::Add(args) => server::add_server(
            args,
            config_path,
            &ctx.home.namespace,
            credentials,
            prompter,
            &mut config,
        ),
        Command::List(args) => server::list_servers(args, &config),
        Command::Show(args) => server::show_server(args, &config),
        Command::Default(args) => server::default_server(args, config_path, &mut config),
        Command::Trust(args) => server::trust_server(args, ssh, prompter, &config),
        Command::Run(args) => {
            let sandbox = build_sandbox(&ctx.home.policy_path, ctx.policy_forced)?;
            run_remote(args, sandbox.as_ref(), credentials, ssh, &config)
        }
        Command::Put(args) => {
            let sandbox = build_sandbox(&ctx.home.policy_path, ctx.policy_forced)?;
            transfer::put_file(args, sandbox.as_ref(), credentials, ssh, &config)
        }
        Command::Get(args) => {
            let sandbox = build_sandbox(&ctx.home.policy_path, ctx.policy_forced)?;
            transfer::get_file(args, sandbox.as_ref(), credentials, ssh, &config)
        }
        Command::Remove(args) => {
            server::remove_server(args, config_path, credentials, prompter, &mut config)
        }
        Command::Doctor(args) => doctor(
            args,
            ctx.home,
            ctx.registry_path,
            ctx.policy_forced,
            credentials,
            &config,
        ),
        Command::Profile(args) => {
            profile::run_profile(args, ctx.registry_path, home_flag.as_deref())
        }
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
            ok: true,
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
    let library_versions = runtime_library_versions();

    if args.json {
        let output = json!({
            "ok": true,
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
        "home: {}\nhome source: {}\nregistry path: {}\nconfig path: {}\nconfig exists: {}\nknown_hosts path: {}\npolicy path: {}\npolicy present: {}\npolicy valid: {}\npolicy enabled: {}\naudit path: {}\naudit writable: {}\ncredential namespace: {}\nos: {}\nlibssh2 version: {}\nopenssl version: {}\ncredential backend: {}\ncredential available: {}\ncredential message: {}\n",
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

/// Whether `--json` appears in the process arguments. Parsing already failed by
/// the time this is consulted, so the raw args are scanned directly to decide
/// how to format a clap usage error.
fn json_requested_in_args() -> bool {
    std::env::args().skip(1).any(|arg| arg == "--json")
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
mod parse_error_tests {
    use super::*;
    use crate::output::ErrorKind;

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
}
