use crate::config::{
    AuthConfig, ServerConfig, SshwConfig, default_config_path, load_config, save_config,
};
use crate::credentials::keyring_store::KeyringCredentialStore;
use crate::credentials::{AuthMaterial, CredentialStore, CredentialStoreHealth};
use crate::output::{RunOutput, ServerOutput, filter_startup_stderr_noise};
use crate::safety::{SafetyDecision, classify_command};
use crate::ssh::SshClient;
use crate::ssh::ssh2_client::Ssh2Client;
use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::json;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(
    name = "sshw",
    version,
    about = "Operate configured SSH servers without exposing secrets"
)]
pub struct Cli {
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
    pub name: String,
    pub command: String,
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct PutArgs {
    pub name: String,
    pub local: PathBuf,
    pub remote: String,
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct GetArgs {
    pub name: String,
    pub remote: String,
    pub local: PathBuf,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

pub trait Prompter {
    fn confirm(&mut self, prompt: &str) -> anyhow::Result<bool>;
    fn password(&mut self, prompt: &str) -> anyhow::Result<String>;
}

pub fn run() -> anyhow::Result<i32> {
    let cli = Cli::parse();
    let config_path = default_config_path()?;
    let credentials = KeyringCredentialStore;
    let ssh = Ssh2Client;
    let mut prompter = TerminalPrompter;
    let output = execute(cli, &config_path, &credentials, &ssh, &mut prompter)?;

    print!("{}", output.stdout);
    eprint!("{}", output.stderr);
    Ok(output.exit_code)
}

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
    let mut config = load_config(config_path)?;

    match cli.command {
        Command::Add(args) => add_server(args, config_path, credentials, prompter, &mut config),
        Command::List(args) => list_servers(args, &config),
        Command::Show(args) => show_server(args, &config),
        Command::Default(args) => default_server(args, config_path, &mut config),
        Command::Trust(args) => trust_server(args, ssh, prompter, &config),
        Command::Run(args) => run_remote(args, credentials, ssh, &config),
        Command::Put(args) => put_file(args, credentials, ssh, &config),
        Command::Get(args) => get_file(args, credentials, ssh, &config),
        Command::Remove(args) => {
            remove_server(args, config_path, credentials, prompter, &mut config)
        }
        Command::Doctor(args) => doctor(args, config_path, credentials, &config),
    }
}

fn add_server<C, P>(
    args: AddArgs,
    config_path: &Path,
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
            let credential = format!("sshw:{}", args.name);
            let password = prompter.password("SSH password: ")?;
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

    Ok(ok(format!(
        "{} {}\n",
        if previous_server.is_some() {
            "updated"
        } else {
            "added"
        },
        args.name
    )))
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
            .ok_or_else(|| anyhow::anyhow!("no default server configured"))?;
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
    credentials: &C,
    ssh: &S,
    config: &SshwConfig,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
    S: SshClient,
{
    match classify_command(&args.command, args.yes) {
        SafetyDecision::Allow => {}
        SafetyDecision::Block { reason } => return Err(anyhow::anyhow!("{reason}")),
    }

    let server = get_server(config, &args.name)?;
    let auth = resolve_auth(server, credentials)?;
    let result = ssh.run(server, &auth, &args.command)?;
    let exit_code = result.exit_status;
    let stderr = filter_startup_stderr_noise(&result.stderr);

    if args.json {
        let output = RunOutput {
            server: args.name,
            command: args.command,
            exit_status: result.exit_status,
            stdout: result.stdout,
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
        stdout: result.stdout,
        stderr,
        exit_code,
    })
}

fn put_file<C, S>(
    args: PutArgs,
    credentials: &C,
    ssh: &S,
    config: &SshwConfig,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
    S: SshClient,
{
    if args.remote.starts_with("/etc/") && !args.yes {
        return Err(anyhow::anyhow!("writing to /etc requires --yes"));
    }

    let server = get_server(config, &args.name)?;
    let auth = resolve_auth(server, credentials)?;
    let result = ssh.put(server, &auth, &args.local, &args.remote)?;
    Ok(ok(format!(
        "uploaded {} bytes from {} to {}\n",
        result.bytes, result.source, result.destination
    )))
}

fn get_file<C, S>(
    args: GetArgs,
    credentials: &C,
    ssh: &S,
    config: &SshwConfig,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
    S: SshClient,
{
    let server = get_server(config, &args.name)?;
    if args.local.exists() && !args.yes {
        return Err(anyhow::anyhow!(
            "local file already exists: {}; pass --yes to overwrite",
            args.local.display()
        ));
    }

    let auth = resolve_auth(server, credentials)?;
    let result = ssh.get(server, &auth, &args.remote, &args.local, args.yes)?;
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
    config_path: &Path,
    credentials: &C,
    config: &SshwConfig,
) -> anyhow::Result<CommandOutput>
where
    C: CredentialStore,
{
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
            "config_path": config_path,
            "config_exists": config_path.exists(),
            "os": std::env::consts::OS,
            "credential_backend": health.backend,
            "credential_available": health.available,
            "credential_message": health.message,
            "missing_credentials": missing_credentials,
        });
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    let mut stdout = format!(
        "config path: {}\nconfig exists: {}\nos: {}\ncredential backend: {}\ncredential available: {}\ncredential message: {}\n",
        config_path.display(),
        config_path.exists(),
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

struct TerminalPrompter;

impl Prompter for TerminalPrompter {
    fn confirm(&mut self, prompt: &str) -> anyhow::Result<bool> {
        eprint!("{prompt}");
        io::stderr().flush()?;

        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        Ok(matches!(
            answer.trim().to_ascii_lowercase().as_str(),
            "y" | "yes"
        ))
    }

    fn password(&mut self, prompt: &str) -> anyhow::Result<String> {
        Ok(rpassword::prompt_password(prompt)?)
    }
}
