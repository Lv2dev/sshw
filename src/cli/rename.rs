//! Move a server alias without changing its endpoint or delegating new authority.

use super::{CommandOutput, RenameArgs, hints::redacted_argument, ok, unknown_server};
use crate::config::{
    AuthConfig, ConfigRevision, SshwConfig, save_config_if_unchanged,
    validate_config_credential_references,
};
use crate::credentials::CredentialStore;
use crate::error::{
    ResultErrorKindExt, app_error, credential_cleanup_error, redacted_error_detail,
    saved_mutation_error,
};
use crate::home::{CredentialPurpose, ResolvedHome, validate_server_name};
use crate::output::{ConfigMutationOutput, DefaultChange, ErrorKind};
use crate::policy::{load_policy_with_revision, save_policy_if_unchanged};
use serde_json::json;
use zeroize::Zeroizing;

struct CredentialMove {
    purpose: CredentialPurpose,
    user: String,
    old: String,
    new: String,
}

pub(super) fn rename_server<C: CredentialStore>(
    args: RenameArgs,
    home: &ResolvedHome,
    revision: &ConfigRevision,
    credentials: &C,
    config: &SshwConfig,
) -> anyhow::Result<CommandOutput> {
    validate_server_name(&args.name).with_error_kind(ErrorKind::Config)?;
    validate_server_name(&args.new_name).with_error_kind(ErrorKind::Config)?;
    let original = config
        .servers
        .get(&args.name)
        .ok_or_else(|| unknown_server(&args.name))?;
    if args.name == args.new_name {
        return rename_output(&args, false, false, None, false);
    }
    if config.servers.contains_key(&args.new_name) {
        return Err(app_error(
            ErrorKind::Config,
            format!(
                "server '{}' already exists; choose an unused name (rename never overwrites another server)",
                redacted_argument(&args.new_name)
            ),
        ));
    }
    let (mut policy, policy_revision) =
        load_policy_with_revision(&home.policy_path).with_error_kind(ErrorKind::Policy)?;
    if policy.as_ref().is_some_and(|file| {
        file.allow_accounts
            .iter()
            .any(|rule| rule.server == args.new_name)
    }) {
        return Err(app_error(
            ErrorKind::Policy,
            format!(
                "account policy already refers to destination server '{}'; choose another name or remove those rules before renaming",
                redacted_argument(&args.new_name)
            ),
        ));
    }
    let mut policy_changed = false;
    if let Some(file) = policy.as_mut() {
        for rule in &mut file.allow_accounts {
            if rule.server == args.name {
                rule.server.clone_from(&args.new_name);
                policy_changed = true;
            }
        }
    }

    let mut renamed = original.clone();
    let mut moves = Vec::new();
    for (login_user, account) in &mut renamed.accounts {
        if let AuthConfig::Password { credential } = &mut account.auth {
            let new = home.namespace.new_account_credential_key(
                CredentialPurpose::Login,
                &args.new_name,
                login_user,
            );
            moves.push(CredentialMove {
                purpose: CredentialPurpose::Login,
                user: login_user.clone(),
                old: credential.clone(),
                new: new.clone(),
            });
            *credential = new;
        }
        if let Some(privilege) = account.privilege.as_mut()
            && let Some(credential) = privilege.credential.as_mut()
        {
            let new = home.namespace.new_account_credential_key(
                CredentialPurpose::Privilege,
                &args.new_name,
                login_user,
            );
            // The service key belongs to the login account, but the credential backend's
            // username is the privilege target (e.g. root), as in privilege set/run.
            moves.push(CredentialMove {
                purpose: CredentialPurpose::Privilege,
                user: privilege.user.clone(),
                old: credential.clone(),
                new: new.clone(),
            });
            *credential = new;
        }
    }
    let mut next = config.clone();
    next.servers.remove(&args.name);
    next.servers.insert(args.new_name.clone(), renamed);
    if next.default.as_deref() == Some(args.name.as_str()) {
        next.default = Some(args.new_name.clone());
    }
    let default_change =
        DefaultChange::between("server", config.default.clone(), next.default.clone());
    let mut attempted = 0;
    let prepared = (|| {
        validate_config_credential_references(&next, &home.namespace)
            .with_error_kind(ErrorKind::Config)?;
        for entry in &moves {
            let password = Zeroizing::new(
                credentials
                    .get_password_for(entry.purpose, &entry.old, &entry.user)
                    .map_err(|error| copy_error(error, "read", &args, entry))
                    .with_error_kind(ErrorKind::Auth)?,
            );
            attempted += 1;
            credentials
                .set_password_for(entry.purpose, &entry.new, &entry.user, &password)
                .map_err(|error| copy_error(error, "store", &args, entry))
                .with_error_kind(ErrorKind::Auth)?;
        }
        // A backend call may take time. Do not publish a new name against policy
        // state that changed while its credentials were being copied.
        let (_, current_policy) =
            load_policy_with_revision(&home.policy_path).with_error_kind(ErrorKind::Policy)?;
        if current_policy != policy_revision {
            return Err(app_error(
                ErrorKind::Policy,
                "policy file changed concurrently; inspect it and retry the rename",
            ));
        }
        save_config_if_unchanged(&home.config_path, &next, revision)
            .with_error_kind(ErrorKind::Config)
    })();
    if let Err(error) = prepared {
        if crate::storage::write_was_published(&error) {
            // The new configuration may already reference the copied secrets.
            return Err(saved_mutation_error(ErrorKind::Config, error.context(
                "the new name was published but durability confirmation failed; inspect the saved server and account policy using the same home/profile before retrying; copied and original credentials were retained"
            ), mutation(&args, "config_save", default_change)));
        }
        return Err(match cleanup(credentials, &moves[..attempted], true) {
            Some(cleanup_error) => error.context(format!(
                "rename was not applied; temporary credential cleanup also failed: {}",
                redacted_error_detail(&cleanup_error)
            )),
            None => error,
        });
    }

    // Publish the alias first. With policy enforcement, non-default accounts
    // are denied until rules follow; no destination grants existed at the snapshot.
    let policy_result = if policy_changed {
        save_policy_if_unchanged(
            &home.policy_path,
            policy.as_ref().expect("changed policy exists"),
            &policy_revision,
        )
        .with_error_kind(ErrorKind::Policy)
    } else {
        Ok(())
    };
    let cleanup_error = cleanup(credentials, &moves, false);
    if let Err(error) = policy_result {
        let mut error = error.context(
            "the server rename is already applied; inspect sshw policy show using the same home/profile and move its allow_accounts rules from the old name to the new name before using non-default accounts; do not retry the old name"
        );
        if let Some(cleanup_error) = cleanup_error {
            error = error.context(format!(
                "obsolete credential cleanup also failed: {}",
                redacted_error_detail(&cleanup_error)
            ));
        }
        return Err(saved_mutation_error(
            ErrorKind::Policy,
            error,
            mutation(&args, "policy_update", default_change),
        ));
    }
    if let Some(error) = cleanup_error {
        return Err(credential_cleanup_error(
            error,
            "renamed",
            &args.new_name,
            None,
            default_change,
        ));
    }
    rename_output(
        &args,
        true,
        policy_changed,
        default_change,
        !moves.is_empty() && !credentials.is_persistent(),
    )
}

fn mutation(
    args: &RenameArgs,
    stage: &'static str,
    default_change: Option<DefaultChange>,
) -> ConfigMutationOutput {
    ConfigMutationOutput {
        config_applied: true,
        failed_stage: stage,
        action: "renamed",
        server: args.new_name.clone(),
        account: None,
        default_change,
    }
}

fn copy_error(
    error: anyhow::Error,
    stage: &str,
    args: &RenameArgs,
    entry: &CredentialMove,
) -> anyhow::Error {
    let detail = redacted_error_detail(&error);
    error.context(format!(
        "cannot {stage} {:?} credential for user '{}' while renaming '{}' to '{}': {detail}; check the credential backend using the same home/profile; session_only requires SSHW_PASSWORD and/or SSHW_PRIVILEGE_PASSWORD",
        entry.purpose, redacted_argument(&entry.user), redacted_argument(&args.name), redacted_argument(&args.new_name)
    ))
}

fn cleanup<C: CredentialStore>(
    credentials: &C,
    entries: &[CredentialMove],
    copied: bool,
) -> Option<anyhow::Error> {
    let mut first = None;
    for entry in entries {
        let key = if copied { &entry.new } else { &entry.old };
        if let Err(error) = credentials.delete_password_for(entry.purpose, key, &entry.user) {
            let absent = error.chain().any(|cause| {
                matches!(
                    cause.downcast_ref::<keyring_core::Error>(),
                    Some(keyring_core::Error::NoEntry)
                )
            });
            if !absent {
                first.get_or_insert(error);
            }
        }
    }
    first
}

fn rename_output(
    args: &RenameArgs,
    changed: bool,
    policy_changed: bool,
    default_change: Option<DefaultChange>,
    ephemeral: bool,
) -> anyhow::Result<CommandOutput> {
    let previous = redacted_argument(&args.name);
    let current = redacted_argument(&args.new_name);
    let warning = "this credential backend does not persist passwords; supply SSHW_PASSWORD and/or SSHW_PRIVILEGE_PASSWORD at run time";
    if args.json {
        let mut output = json!({"ok":true,"action":"renamed","previous_server":previous,"server":current,"changed":changed,"change":if changed {"renamed"} else {"unchanged"},"policy_changed":policy_changed});
        if let Some(change) = default_change {
            output["default_change"] = serde_json::to_value(change.redacted())?;
        }
        if ephemeral {
            output["warning"] = warning.into();
        }
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }
    let mut message = if changed {
        format!("renamed server '{previous}' -> '{current}'\n")
    } else {
        format!("server '{current}' (unchanged)\n")
    };
    if let Some(change) = default_change {
        message.push_str(&change.human_message());
    }
    if ephemeral {
        message.push_str(&format!("warning: {warning}\n"));
    }
    Ok(ok(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ServerConfig, load_config_with_revision, save_config};
    use crate::credentials::session_store::SessionOnlyStore;
    use crate::output::ErrorResponse;

    #[test]
    fn published_config_error_keeps_both_credential_generations_and_reports_applied_name() {
        let temp = tempfile::tempdir().unwrap();
        let home = ResolvedHome::ad_hoc(temp.path(), "fixture".into());
        let old =
            home.namespace
                .new_account_credential_key(CredentialPurpose::Login, "old", "deploy");
        let store = SessionOnlyStore::new();
        store
            .set_password_for(CredentialPurpose::Login, &old, "deploy", "fixture-login")
            .unwrap();
        let mut config = SshwConfig {
            default: Some("old".into()),
            ..SshwConfig::default()
        };
        config.servers.insert(
            "old".into(),
            ServerConfig::single_account(
                "192.0.2.10",
                22,
                "deploy",
                AuthConfig::Password {
                    credential: old.clone(),
                },
            ),
        );
        save_config(&home.config_path, &config).unwrap();
        let (_, revision) = load_config_with_revision(&home.config_path).unwrap();
        crate::storage::fail_next_parent_sync();
        let error = rename_server(
            RenameArgs {
                name: "old".into(),
                new_name: "new".into(),
                json: true,
            },
            &home,
            &revision,
            &store,
            &config,
        )
        .unwrap_err();
        assert!(crate::storage::write_was_published(&error));
        let response = ErrorResponse::from_error(&error);
        assert_eq!(response.error.kind, ErrorKind::Config);
        let mutation = response.mutation.unwrap();
        assert!(mutation.config_applied);
        assert_eq!(mutation.server, "new");
        assert_eq!(mutation.failed_stage, "config_save");
        let (saved, _) = load_config_with_revision(&home.config_path).unwrap();
        assert_eq!(saved.default.as_deref(), Some("new"));
        let AuthConfig::Password { credential: new } =
            &saved.servers["new"].accounts["deploy"].auth
        else {
            panic!()
        };
        for key in [&old, new] {
            assert_eq!(
                store
                    .get_password_for(CredentialPurpose::Login, key, "deploy")
                    .unwrap(),
                "fixture-login"
            );
        }
    }
}
