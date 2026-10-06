//! `sshw profile` subcommand handlers.
//!
//! These operate on the global [`ProfileRegistry`] (`profiles.json`), a distinct
//! domain from the per-home `SshwConfig` that the server commands use. Split out
//! of `cli.rs` so registry handling lives apart from server/transfer dispatch.

use super::{
    CommandOutput, ProfileAddArgs, ProfileArgs, ProfileCommand, ProfileDefaultArgs,
    ProfileListArgs, ProfileRemoveArgs, ProfileShowArgs, ok,
};
use crate::error::ResultErrorKindExt;
use crate::home::{ResolvedHome, generate_profile_id};
use crate::output::{DefaultChange, ErrorKind, redact_secrets};
use crate::profile::{
    ProfileEntry, ProfileRegistry, RegistryRevision, load_registry_for_removal_with_revision,
    load_registry_with_revision, save_registry_if_unchanged, validate_home_directory,
    validate_profile_name,
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
    }
}

fn profile_command_mutates_registry(command: &ProfileCommand) -> bool {
    matches!(
        command,
        ProfileCommand::Add(_) | ProfileCommand::Default(_) | ProfileCommand::Remove(_)
    )
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
    if registry.default.is_none() {
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
    let entry = registry
        .profiles
        .get(&args.name)
        .ok_or_else(|| anyhow::anyhow!("unknown profile '{}'", args.name))?;
    validate_profile_target(&args.name, &entry.home, &entry.id)?;

    let changed = registry.default.as_deref() != Some(args.name.as_str());
    if changed {
        registry.default = Some(args.name.clone());
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
        format!("default profile set to {}\n", args.name)
    } else {
        format!("default profile already set to {} (unchanged)\n", args.name)
    }))
}

fn profile_remove(
    args: ProfileRemoveArgs,
    registry_path: &Path,
    revision: &RegistryRevision,
    registry: &mut ProfileRegistry,
) -> anyhow::Result<CommandOutput> {
    let previous_default = registry.default.clone();
    if registry.profiles.remove(&args.name).is_none() {
        return Err(anyhow::anyhow!("unknown profile '{}'", args.name));
    }
    if registry.default.as_deref() == Some(args.name.as_str()) {
        registry.default = registry.profiles.keys().next().cloned();
    }

    let default_change =
        DefaultChange::between("profile", previous_default, registry.default.clone());
    let target_warning = default_change.as_ref().and_then(|_| {
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
    save_registry_if_unchanged(registry_path, registry, revision)?;
    if args.json {
        let mut output = json!({"ok":true,"action":"removed","name":args.name,"warning":"home and keyring entries left intact; re-adding requires credentials to be registered again"});
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
        args.name
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
