//! `sshw profile` subcommand handlers.
//!
//! These operate on the global [`ProfileRegistry`] (`profiles.json`), a distinct
//! domain from the per-home `SshwConfig` that the server commands use. Split out
//! of `cli.rs` so registry handling lives apart from server/transfer dispatch.

use super::{
    CommandOutput, ProfileAddArgs, ProfileArgs, ProfileCommand, ProfileDefaultArgs,
    ProfileListArgs, ProfileRemoveArgs, ProfileRenameArgs, ProfileShowArgs, ok,
};
use crate::error::ResultErrorKindExt;
use crate::home::{ResolvedHome, generate_profile_id};
use crate::output::{DefaultChange, ErrorKind, redact_secrets};
use crate::profile::{
    ProfileEntry, ProfileRegistry, RegistryRevision, load_registry_for_removal_with_revision,
    load_registry_with_revision, profile_registration_hint, save_registry_if_unchanged,
    unknown_profile, validate_home_directory, validate_profile_name,
};
use serde_json::json;
use std::fs;
use std::path::Path;

pub(super) fn run_profile(
    args: ProfileArgs,
    registry_path: &Path,
    home_flag: Option<&Path>,
) -> anyhow::Result<CommandOutput> {
    run_profile_inner(args, registry_path, home_flag).with_error_kind(ErrorKind::Config)
}

fn run_profile_inner(
    args: ProfileArgs,
    registry_path: &Path,
    home_flag: Option<&Path>,
) -> anyhow::Result<CommandOutput> {
    let _registry_lock = if profile_command_mutates_registry(&args.command) {
        Some(crate::storage::acquire_exclusive_lock(
            &registry_path.with_file_name(".profiles.lock"),
        )?)
    } else {
        None
    };
    let (mut registry, revision) = match &args.command {
        ProfileCommand::Remove(args) => {
            load_registry_for_removal_with_revision(registry_path, &args.name)?
        }
        _ => load_registry_with_revision(registry_path)?,
    };
    match args.command {
        ProfileCommand::Add(a) => {
            profile_add(a, home_flag, registry_path, &revision, &mut registry)
        }
        ProfileCommand::List(a) => profile_list(a, &registry),
        ProfileCommand::Show(a) => profile_show(a, &registry),
        ProfileCommand::Default(a) => profile_default(a, registry_path, &revision, &mut registry),
        ProfileCommand::Remove(a) => profile_remove(a, registry_path, &revision, &mut registry),
        ProfileCommand::Rename(a) => profile_rename(a, registry_path, &revision, &mut registry),
    }
}

fn profile_command_mutates_registry(command: &ProfileCommand) -> bool {
    matches!(
        command,
        ProfileCommand::Add(_)
            | ProfileCommand::Default(_)
            | ProfileCommand::Remove(_)
            | ProfileCommand::Rename(_)
    )
}

fn profile_rename(
    args: ProfileRenameArgs,
    registry_path: &Path,
    revision: &RegistryRevision,
    registry: &mut ProfileRegistry,
) -> anyhow::Result<CommandOutput> {
    validate_profile_name(&args.name)?;
    validate_profile_name(&args.new_name)?;
    let entry = registry
        .profiles
        .get(&args.name)
        .cloned()
        .ok_or_else(|| unknown_profile(&args.name))?;
    let changed = args.name != args.new_name;
    if changed && registry.profiles.contains_key(&args.new_name) {
        return Err(anyhow::anyhow!(
            "profile '{}' already exists; choose an unused name, existing profiles are not overwritten",
            super::hints::redacted_argument(&args.new_name)
        ));
    }
    let previous_default = registry.default.clone();
    if changed {
        registry.profiles.remove(&args.name);
        registry
            .profiles
            .insert(args.new_name.clone(), entry.clone());
        if registry.default.as_deref() == Some(args.name.as_str()) {
            registry.default = Some(args.new_name.clone());
        }
        save_registry_if_unchanged(registry_path,registry,revision).map_err(|error| {
            if crate::storage::write_was_published(&error) {
                error.context(format!("profile rename was published as '{}', but save durability could not be confirmed; inspect `sshw profile list` before retrying or selecting the old name",super::hints::redacted_argument(&args.new_name)))
            } else {error}
        })?;
    }
    let default_change =
        DefaultChange::between("profile", previous_default, registry.default.clone());
    if args.json {
        let mut output = json!({"ok":true,"action":"renamed","previous_name":redact_secrets(&args.name),"name":redact_secrets(&args.new_name),"id":redact_secrets(&entry.id),"home":redact_secrets(&entry.home.display().to_string()),"namespace_changed":false,"is_default":registry.default.as_deref()==Some(args.new_name.as_str()),"changed":changed,"change":if changed {"renamed"} else {"unchanged"}});
        if let Some(change) = default_change {
            output["default_change"] = serde_json::to_value(change.redacted())?;
        }
        return Ok(ok(format!("{output}\n")));
    }
    let mut message = if changed {
        format!(
            "profile renamed {} -> {} (home and credential namespace preserved)\n",
            super::hints::redacted_argument(&args.name),
            super::hints::redacted_argument(&args.new_name)
        )
    } else {
        format!(
            "profile {} unchanged\n",
            super::hints::redacted_argument(&args.name)
        )
    };
    if let Some(change) = default_change {
        message.push_str(&change.human_message());
    }
    Ok(ok(message))
}

fn profile_add(
    args: ProfileAddArgs,
    home_flag: Option<&Path>,
    registry_path: &Path,
    revision: &RegistryRevision,
    registry: &mut ProfileRegistry,
) -> anyhow::Result<CommandOutput> {
    validate_profile_name(&args.name)?;
    let home = home_flag.ok_or_else(|| anyhow::anyhow!("profile add requires --home <path>"))?;
    let home = normalize_profile_home(home)?;
    if registry.profiles.contains_key(&args.name) && !args.force {
        return Err(anyhow::anyhow!(
            "profile '{}' already exists; pass --force to overwrite",
            args.name
        ));
    }

    let previous = registry.profiles.get(&args.name).cloned();
    let id = previous
        .as_ref()
        .filter(|entry| same_profile_home(&entry.home, &home))
        .map(|entry| entry.id.clone())
        .unwrap_or_else(|| generate_profile_id(&args.name, &home));
    validate_profile_target(&args.name, &home, &id)?;
    let namespace_changed = previous.as_ref().is_some_and(|entry| entry.id != id);
    let action = if previous.is_some() {
        "updated"
    } else {
        "added"
    };
    let warning = namespace_changed.then_some("home changed; a fresh credential namespace was created. Previous home and keyring entries are left intact; password credentials must be registered again when needed");
    let before = registry.clone();
    registry.profiles.insert(
        args.name.clone(),
        ProfileEntry {
            id: id.clone(),
            home: home.clone(),
        },
    );
    if registry.default.is_none() && before.profiles.is_empty() {
        registry.default = Some(args.name.clone());
    }

    let changed = *registry != before;
    if changed {
        save_registry_if_unchanged(registry_path, registry, revision)?;
    }
    if args.json {
        let mut output = json!({"ok":true,"action":action,"name":args.name,"home":home,"id":id,"namespace_changed":namespace_changed,
            "changed":changed,"change":if changed { action } else { "unchanged" }});
        if let Some(warning) = warning {
            output["warning"] = json!(warning);
        }
        if namespace_changed && let Some(previous) = &previous {
            output["previous_home"] = json!(redact_secrets(&previous.home.display().to_string()));
        }
        return Ok(ok(format!("{}\n", output)));
    }
    let mut message = if changed {
        format!("{action} profile {} -> {}\n", args.name, home.display())
    } else {
        format!("profile {} -> {} (unchanged)\n", args.name, home.display())
    };
    if let Some(warning) = warning {
        if let Some(previous) = &previous {
            message.push_str(&format!(
                "home changed: {} -> {}\n",
                redact_secrets(&previous.home.display().to_string()),
                redact_secrets(&home.display().to_string())
            ));
        }
        message.push_str(&format!("warning: {warning}\n"));
    } else if previous.is_some() {
        message.push_str("credential namespace unchanged\n");
    }
    Ok(ok(message))
}

fn same_profile_home(existing: &Path, requested: &Path) -> bool {
    if existing == requested {
        return true;
    }
    match (fs::canonicalize(existing), fs::canonicalize(requested)) {
        (Ok(existing), Ok(requested)) => existing == requested,
        _ => false,
    }
}

fn normalize_profile_home(home: &Path) -> anyhow::Result<std::path::PathBuf> {
    let absolute = std::path::absolute(home).map_err(|err| {
        anyhow::anyhow!(
            "profile add requires a valid --home path '{}': {err}",
            home.display()
        )
    })?;
    validate_home_directory(&absolute)?;
    match fs::canonicalize(&absolute) {
        Ok(canonical) => Ok(canonical),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(absolute),
        Err(err) => Err(anyhow::anyhow!(
            "failed to resolve profile home '{}': {err}",
            absolute.display()
        )),
    }
}

fn validate_profile_target(name: &str, home: &Path, id: &str) -> anyhow::Result<()> {
    inspect_profile_target(name, home, id).map_err(|error| {
        let detail = redact_secrets(&error.to_string());
        error.context(format!("cannot connect profile '{}' to target home {}: {detail}; profile registry was not changed", redact_secrets(name), redact_secrets(&home.display().to_string())))
    })
}

fn inspect_profile_target(name: &str, home: &Path, id: &str) -> anyhow::Result<()> {
    let target = ResolvedHome::profile(home.to_path_buf(), id, format!("profile '{name}'"));
    validate_home_directory(home).and_then(|()| super::load_active_config(&target).map(|_| ()))
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

    if registry.profiles.is_empty() {
        return Ok(ok(format!(
            "no named profiles registered\nnext: to register one, replace the home/name placeholders in `{}`; then select it with --profile=<name> (omit --home and unset SSHW_HOME). Named profiles are optional; normal home selection, including the built-in default home, remains available\n",
            profile_registration_hint("<name>")
        )));
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
        .ok_or_else(|| unknown_profile(&args.name))?;
    let is_default = registry.default.as_deref() == Some(args.name.as_str());

    if args.json {
        let output = json!({
            "ok": true,
            "name": args.name,
            "id": entry.id,
            "home": entry.home,
            "is_default": is_default,
        });
        return Ok(ok(format!("{}\n", serde_json::to_string(&output)?)));
    }

    Ok(ok(format!(
        "{}\n  id: {}\n  home: {}\n  default: {}\n  use --profile to retain this credential namespace; --home uses a separate namespace\n",
        args.name,
        entry.id,
        entry.home.display(),
        is_default
    )))
}

fn profile_default(
    args: ProfileDefaultArgs,
    registry_path: &Path,
    revision: &RegistryRevision,
    registry: &mut ProfileRegistry,
) -> anyhow::Result<CommandOutput> {
    if args.clear {
        let previous = registry.default.take();
        let changed = previous.is_some();
        let default_change = DefaultChange::between("profile", previous, None);
        if changed {
            save_registry_if_unchanged(registry_path, registry, revision).map_err(|error| {
                if crate::storage::write_was_published(&error) {
                    error.context("default profile was cleared, but save durability could not be confirmed; inspect `sshw profile list` before retrying")
                } else { error }
            })?;
        }
        if args.json {
            let mut output = json!({"ok":true,"action":"default","name":null,"changed":changed,
                "change":if changed { "cleared" } else { "unchanged" }});
            if let Some(change) = default_change {
                output["default_change"] = serde_json::to_value(change.redacted())?;
            }
            return Ok(ok(format!("{output}\n")));
        }
        return Ok(ok(format!(
            "{}; without an explicit home/profile selector, the built-in default home is used\n",
            if changed {
                "default profile cleared"
            } else {
                "no default profile configured (unchanged)"
            }
        )));
    }
    let name = args
        .name
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("profile default requires a name or --clear"))?;
    let entry = registry
        .profiles
        .get(name)
        .ok_or_else(|| unknown_profile(name))?;
    validate_profile_target(name, &entry.home, &entry.id)?;

    let changed = registry.default.as_deref() != Some(name);
    if changed {
        registry.default = Some(name.to_string());
        save_registry_if_unchanged(registry_path, registry, revision)?;
    }
    if args.json {
        return Ok(ok(format!(
            "{}\n",
            json!({"ok":true,"action":"default","name":args.name,"changed":changed,
                "change":if changed { "updated" } else { "unchanged" }})
        )));
    }
    Ok(ok(if changed {
        format!("default profile set to {name}\n")
    } else {
        format!("default profile already set to {name} (unchanged)\n")
    }))
}

fn profile_remove(
    args: ProfileRemoveArgs,
    registry_path: &Path,
    revision: &RegistryRevision,
    registry: &mut ProfileRegistry,
) -> anyhow::Result<CommandOutput> {
    let previous_default = registry.default.clone();
    if !registry.profiles.contains_key(&args.name) {
        return Err(unknown_profile(&args.name));
    }
    if args.clear_default && args.switch_default.is_some() {
        return Err(crate::error::app_error(
            ErrorKind::Usage,
            "--switch-default conflicts with --clear-default",
        ));
    }
    let explicit_default = args.switch_default.is_some() || args.clear_default;
    if explicit_default && registry.default.as_deref() != Some(args.name.as_str()) {
        return Err(crate::error::app_error(
            ErrorKind::Config,
            "--switch-default and --clear-default are only for removing the current default profile; omit them to remove another profile",
        ));
    }
    if let Some(replacement) = &args.switch_default {
        if replacement == &args.name {
            return Err(crate::error::app_error(
                ErrorKind::Config,
                "--switch-default must select a different registered profile",
            ));
        }
        let entry = registry
            .profiles
            .get(replacement)
            .ok_or_else(|| unknown_profile(replacement))?;
        validate_profile_target(replacement, &entry.home, &entry.id)?;
    }
    registry.profiles.remove(&args.name);
    if registry.default.as_deref() == Some(args.name.as_str()) {
        registry.default = if args.clear_default {
            None
        } else {
            args.switch_default
                .or_else(|| registry.profiles.keys().next().cloned())
        };
    }

    let default_change =
        DefaultChange::between("profile", previous_default, registry.default.clone());
    let target_warning = default_change.as_ref().and_then(|_| {
        if explicit_default { return None; }
        let name = registry.default.as_ref()?;
        let entry = registry.profiles.get(name)?;
        let error = inspect_profile_target(name, &entry.home, &entry.id).err()?;
        let message = format!(
            "cannot validate automatically selected default profile {}: {}; removal was completed, but commands using this profile may fail",
            super::hints::quote_local_argument(name),
            super::redacted_error_detail(&error)
        );
        let next_step = format!(
            "repair the settings/home at {}; inspect with sshw --profile={} doctor (unset SSHW_HOME and omit --home); or choose a valid profile from sshw profile list and run sshw profile default -- {}",
            super::hints::quote_local_argument(&entry.home.display().to_string()),
            super::hints::quote_local_argument(name),
            super::hints::quote_local_argument("<valid-profile>")
        );
        Some(json!({"name":redact_secrets(name),"home":redact_secrets(&entry.home.display().to_string()),
            "message":message,"next_step":next_step}))
    });
    save_registry_if_unchanged(registry_path, registry, revision).map_err(|error| {
        if crate::storage::write_was_published(&error) {
            error.context(format!(
                "profile '{}' was removed, but save durability could not be confirmed; inspect `sshw profile list` for the saved default before retrying",
                super::hints::redacted_argument(&args.name)
            ))
        } else { error }
    })?;
    if args.json {
        let mut output = json!({"ok":true,"action":"removed","name":redact_secrets(&args.name),"warning":"home and keyring entries left intact; re-adding requires credentials to be registered again"});
        if let Some(change) = default_change {
            output["default_change"] = serde_json::to_value(change.redacted())?;
        }
        if let Some(warning) = target_warning {
            output["default_target_warning"] = warning;
        }
        return Ok(ok(format!("{}\n", output)));
    }
    let mut message = format!(
        "removed profile {} (home and keyring entries left intact; re-adding creates a fresh credential namespace)\n",
        super::hints::redacted_argument(&args.name)
    );
    if let Some(change) = default_change {
        message.push_str(&change.human_message());
    }
    if let Some(warning) = target_warning {
        message.push_str(&format!(
            "warning: {}\nnext: {}\n",
            warning["message"].as_str().unwrap_or_default(),
            warning["next_step"].as_str().unwrap_or_default()
        ));
    }
    Ok(ok(message))
}

#[cfg(test)]
mod default_clear_tests {
    use super::*;
    use crate::profile::{ProfileEntry, save_registry};
    use std::collections::BTreeMap;

    #[test]
    fn profile_removal_selection_checks_revision_and_reports_published_state() {
        for clear in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("profiles.json");
            let registry = ProfileRegistry {
                default: Some("old".into()),
                profiles: ["old", "chosen"]
                    .into_iter()
                    .map(|name| {
                        (
                            name.into(),
                            ProfileEntry {
                                id: format!("p_{name}"),
                                home: temp.path().join(name),
                            },
                        )
                    })
                    .collect(),
                ..Default::default()
            };
            save_registry(&path, &registry).unwrap();
            let (mut snapshot, revision) = load_registry_with_revision(&path).unwrap();
            let mut external = registry.clone();
            external.default = None;
            save_registry(&path, &external).unwrap();
            let args = || ProfileRemoveArgs {
                name: "old".into(),
                switch_default: (!clear).then(|| "chosen".into()),
                clear_default: clear,
                json: true,
            };
            let error = profile_remove(args(), &path, &revision, &mut snapshot).unwrap_err();
            assert!(!crate::storage::write_was_published(&error));
            assert_eq!(crate::profile::load_registry(&path).unwrap(), external);
            save_registry(&path, &registry).unwrap();
            let (mut snapshot, revision) = load_registry_with_revision(&path).unwrap();
            crate::storage::fail_next_parent_sync();
            let error = profile_remove(args(), &path, &revision, &mut snapshot).unwrap_err();
            assert!(crate::storage::write_was_published(&error));
            assert!(error.to_string().contains("was removed"));
            assert!(error.to_string().contains("sshw profile list"));
            let saved = crate::profile::load_registry(&path).unwrap();
            assert!(!saved.profiles.contains_key("old"));
            assert_eq!(saved.default.as_deref(), (!clear).then_some("chosen"));
            assert_eq!(saved.profiles["chosen"], registry.profiles["chosen"]);
            assert!(!registry.profiles["old"].home.exists());
            assert!(!registry.profiles["chosen"].home.exists());
        }
    }

    #[test]
    fn profile_rename_checks_revision_and_describes_published_durability_failure() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("profiles.json");
        let entry = ProfileEntry {
            id: "p_stable".into(),
            home: temp.path().join("not-created"),
        };
        let registry = ProfileRegistry {
            default: Some("old".into()),
            profiles: BTreeMap::from([("old".into(), entry.clone())]),
            ..Default::default()
        };
        save_registry(&path, &registry).unwrap();
        let (mut snapshot, revision) = load_registry_with_revision(&path).unwrap();
        let mut external = registry.clone();
        external.default = None;
        save_registry(&path, &external).unwrap();
        let args = || ProfileRenameArgs {
            name: "old".into(),
            new_name: "new".into(),
            json: true,
        };
        let error = profile_rename(args(), &path, &revision, &mut snapshot).unwrap_err();
        assert!(!crate::storage::write_was_published(&error));
        assert_eq!(crate::profile::load_registry(&path).unwrap(), external);
        let (mut snapshot, revision) = load_registry_with_revision(&path).unwrap();
        crate::storage::fail_next_parent_sync();
        let error = profile_rename(args(), &path, &revision, &mut snapshot).unwrap_err();
        assert!(crate::storage::write_was_published(&error));
        assert!(error.to_string().contains("published as 'new'"));
        let saved = crate::profile::load_registry(&path).unwrap();
        assert_eq!(saved.profiles["new"], entry);
        assert!(saved.default.is_none());
        assert!(!saved.profiles.contains_key("old"));
        assert!(!entry.home.exists());
    }

    #[test]
    fn clear_preserves_ids_and_checks_cas_and_published_failure() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("profiles.json");
        let registry = ProfileRegistry {
            default: Some("prod".into()),
            profiles: BTreeMap::from([(
                "prod".into(),
                ProfileEntry {
                    id: "p_prod".into(),
                    home: temp.path().join("prod"),
                },
            )]),
            ..Default::default()
        };
        save_registry(&path, &registry).unwrap();
        let (mut snapshot, revision) = load_registry_with_revision(&path).unwrap();
        let mut external = registry.clone();
        external.profiles.get_mut("prod").unwrap().home = temp.path().join("external");
        save_registry(&path, &external).unwrap();
        let args = || ProfileDefaultArgs {
            name: None,
            clear: true,
            json: true,
        };
        let error = profile_default(args(), &path, &revision, &mut snapshot).unwrap_err();
        assert!(!crate::storage::write_was_published(&error));
        assert_eq!(crate::profile::load_registry(&path).unwrap(), external);
        let (mut snapshot, revision) = load_registry_with_revision(&path).unwrap();
        crate::storage::fail_next_parent_sync();
        let error = profile_default(args(), &path, &revision, &mut snapshot).unwrap_err();
        assert!(crate::storage::write_was_published(&error));
        assert!(error.to_string().contains("was cleared"));
        let actual = crate::profile::load_registry(&path).unwrap();
        assert!(actual.default.is_none());
        assert_eq!(actual.profiles, external.profiles);
    }
}
