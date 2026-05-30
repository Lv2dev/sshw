//! `sshw profile` subcommand handlers.
//!
//! These operate on the global [`ProfileRegistry`] (`profiles.json`), a distinct
//! domain from the per-home `SshwConfig` that the server commands use. Split out
//! of `cli.rs` so registry handling lives apart from server/transfer dispatch.

use super::{
    CommandOutput, ProfileAddArgs, ProfileArgs, ProfileCommand, ProfileDefaultArgs,
    ProfileListArgs, ProfileRemoveArgs, ProfileShowArgs, ok,
};
use crate::home::generate_profile_id;
use crate::profile::{ProfileEntry, ProfileRegistry, load_registry, save_registry};
use serde_json::json;
use std::path::Path;

pub(super) fn run_profile(
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
            "ok": true,
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
