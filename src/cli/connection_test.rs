use super::{CommandOutput, TestArgs, get_server, ok, resolve_auth, select_account};
use crate::config::SshwConfig;
use crate::credentials::CredentialStore;
use crate::error::ResultErrorKindExt;
use crate::output::{ErrorKind, redact_secrets};
use crate::sandbox::{Sandbox, SandboxDecision};
use crate::ssh::{SshClient, SshTarget};
use serde_json::json;
use std::time::Instant;

pub(super) fn test_connection<C: CredentialStore, S: SshClient>(
    args: TestArgs,
    sandbox: &dyn Sandbox,
    store: &C,
    ssh: &S,
    config: &SshwConfig,
) -> anyhow::Result<CommandOutput> {
    let server = get_server(config, &args.name)?;
    let (user, account) = select_account(&args.name, server, args.user.as_deref())?;
    if let SandboxDecision::Deny { reason } =
        sandbox.check_account(&args.name, user, user == server.default_user)
    {
        return Err(super::policy_recovery::denial(
            reason,
            super::policy_recovery::Rule::Account(args.name.clone(), user.into()),
        ));
    }
    let auth = resolve_auth(&args.name, account, user, store)?;
    let started = Instant::now();
    let key = ssh
        .test_connection(&SshTarget::new(server, user), &auth)
        .with_error_kind(ErrorKind::Ssh)?;
    let duration = started.elapsed().as_millis();
    if args.json {
        return Ok(ok(format!(
            "{}\n",
            json!({"ok":true,"server":redact_secrets(&args.name),"user":redact_secrets(user),
            "host":redact_secrets(&server.host),"port":server.port,"connection_tested":true,"host_key_verified":true,
            "authenticated":true,"command_executed":false,"algorithm":redact_secrets(&key.algorithm),
            "fingerprint_sha256":redact_secrets(&key.fingerprint_sha256),"duration_ms":duration})
        )));
    }
    Ok(ok(format!(
        "connection verified: {} / {} at {}:{}\nhost key: {} {}\nlogin authenticated ({} ms); no remote command executed\n",
        super::hints::redacted_argument(&args.name),
        super::hints::redacted_argument(user),
        super::hints::redacted_argument(&server.host),
        server.port,
        redact_secrets(&key.algorithm),
        redact_secrets(&key.fingerprint_sha256),
        duration
    )))
}
