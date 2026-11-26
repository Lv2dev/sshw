//! Explicit endpoint-only edit; credentials and host approvals are never moved.
use super::{CommandOutput, EndpointArgs, Prompter, get_server, hints::redacted_argument, ok};
use crate::config::{
    ConfigRevision, SshwConfig, save_config_if_unchanged, validate_server_endpoint,
};
use crate::error::{ResultErrorKindExt, app_error, saved_mutation_error};
use crate::output::{ConfigMutationOutput, ErrorKind};
use serde_json::json;
use std::path::Path;

pub(super) fn update_endpoint<P: Prompter>(
    args: EndpointArgs,
    path: &Path,
    revision: &ConfigRevision,
    config: &mut SshwConfig,
    prompter: &mut P,
) -> anyhow::Result<CommandOutput> {
    if args.host.is_none() && args.port.is_none() {
        return Err(app_error(
            ErrorKind::Usage,
            "endpoint requires --host or --port",
        ));
    }
    let server = get_server(config, &args.name)?;
    let previous_host = server.host.clone();
    let previous_port = server.port;
    let host = args.host.unwrap_or_else(|| previous_host.clone());
    let port = args.port.unwrap_or(previous_port);
    validate_server_endpoint(&args.name, &host, port).with_error_kind(ErrorKind::Config)?;
    let changed = host != previous_host || port != previous_port;
    if changed {
        if !args.yes && !prompter.confirm(&format!(
            "change endpoint for '{}' from {}:{} to {}:{} (accounts and passwords are preserved; the destination host key must be verified)? [y/N] ",
            redacted_argument(&args.name),redacted_argument(&previous_host),previous_port,redacted_argument(&host),port,
        )).with_error_kind(ErrorKind::Config)? {
            return Err(app_error(ErrorKind::Config,"endpoint update cancelled"));
        }
        let server = config
            .servers
            .get_mut(&args.name)
            .expect("validated server");
        server.host = host.clone();
        server.port = port;
        save_config_if_unchanged(path,config,revision).with_error_kind(ErrorKind::Config).map_err(|error| {
            if crate::storage::write_was_published(&error) {
                saved_mutation_error(ErrorKind::Config,error.context("the new endpoint was published but save durability could not be confirmed; inspect sshw show using the same settings before retrying. Credentials and host approvals were preserved"),ConfigMutationOutput {
                    config_applied:true,failed_stage:"config_save",action:"endpoint_updated",server:args.name.clone(),account:None,default_change:None,
                })
            } else { error }
        })?;
    }
    if args.json {
        return Ok(ok(format!(
            "{}\n",
            json!({"ok":true,"action":"endpoint_updated","server":redacted_argument(&args.name),
            "previous_host":redacted_argument(&previous_host),"previous_port":previous_port,"host":redacted_argument(&host),"port":port,
            "changed":changed,"change":if changed {"updated"} else {"unchanged"},"credentials_changed":false,"host_key_verified":false})
        )));
    }
    Ok(ok(format!(
        "endpoint {}: {}:{}{}\n{}",
        redacted_argument(&args.name),
        redacted_argument(&host),
        port,
        if changed { "" } else { " (unchanged)" },
        if changed {
            "accounts and passwords preserved; verify the destination with sshw trust/test before running commands\n"
        } else {
            ""
        }
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuthConfig, ServerConfig, load_config, load_config_with_revision, save_config,
    };
    use std::collections::BTreeMap;
    struct Input;
    impl Prompter for Input {
        fn confirm(&mut self, _: &str) -> anyhow::Result<bool> {
            Ok(true)
        }
        fn password(&mut self, _: &str) -> anyhow::Result<String> {
            panic!("no password input")
        }
        fn password_stdin(&mut self) -> anyhow::Result<String> {
            panic!("no password input")
        }
    }
    #[test]
    fn endpoint_checks_revision_and_reports_published_durability_failure() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("servers.json");
        let original = SshwConfig {
            servers: BTreeMap::from([(
                "web".into(),
                ServerConfig::single_account("192.0.2.10", 22, "deploy", AuthConfig::Agent),
            )]),
            ..Default::default()
        };
        save_config(&path, &original).unwrap();
        let (mut config, revision) = load_config_with_revision(&path).unwrap();
        let mut external = original.clone();
        external.servers.get_mut("web").unwrap().port = 2222;
        save_config(&path, &external).unwrap();
        let args = || EndpointArgs {
            name: "web".into(),
            host: None,
            port: Some(10022),
            yes: true,
            json: true,
        };
        let error = update_endpoint(args(), &path, &revision, &mut config, &mut Input).unwrap_err();
        assert!(!crate::storage::write_was_published(&error));
        assert_eq!(load_config(&path).unwrap(), external);
        let (mut config, revision) = load_config_with_revision(&path).unwrap();
        crate::storage::fail_next_parent_sync();
        let error = update_endpoint(args(), &path, &revision, &mut config, &mut Input).unwrap_err();
        assert!(crate::storage::write_was_published(&error));
        let response = crate::output::ErrorResponse::from_error(&error);
        let mutation = response.mutation.unwrap();
        assert_eq!(mutation.action, "endpoint_updated");
        assert!(mutation.config_applied);
        assert_eq!(mutation.failed_stage, "config_save");
        assert_eq!(load_config(&path).unwrap().servers["web"].port, 10022);
    }
}
