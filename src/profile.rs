use crate::home::{ResolvedHome, builtin_default_home, is_reserved_profile_id};
use crate::storage::write_owner_only_atomic;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

/// Global registry mapping profile names to their sshw home directories.
/// Lives at `<config_dir>/sshw/profiles.json`, independent of the active home.
const PROFILE_REGISTRY_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileRegistry {
    pub version: u32,
    pub default: Option<String>,
    pub profiles: BTreeMap<String, ProfileEntry>,
}

impl Default for ProfileRegistry {
    fn default() -> Self {
        Self {
            version: PROFILE_REGISTRY_VERSION,
            default: None,
            profiles: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileEntry {
    pub id: String,
    pub home: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryRevision(Option<Vec<u8>>);

pub fn load_registry(path: &Path) -> Result<ProfileRegistry> {
    load_registry_with_revision(path).map(|(registry, _revision)| registry)
}

pub fn load_registry_with_revision(path: &Path) -> Result<(ProfileRegistry, RegistryRevision)> {
    let Some(contents) = read_registry_contents(path)? else {
        return Ok((ProfileRegistry::default(), RegistryRevision(None)));
    };
    let registry = parse_registry(path, &contents)?;
    validate_registry(&registry).map_err(|err| {
        anyhow::anyhow!(
            "failed to load profile registry at {}: {err}",
            path.display()
        )
    })?;
    let revision = RegistryRevision(Some(contents.into_bytes()));
    Ok((registry, revision))
}

pub fn load_registry_for_removal_with_revision(
    path: &Path,
    target_name: &str,
) -> Result<(ProfileRegistry, RegistryRevision)> {
    let Some(contents) = read_registry_contents(path)? else {
        return Ok((ProfileRegistry::default(), RegistryRevision(None)));
    };
    let registry = parse_registry(path, &contents)?;
    let mut remainder = registry.clone();
    if remainder.profiles.remove(target_name).is_none() {
        validate_registry(&registry).map_err(|err| {
            anyhow::anyhow!(
                "failed to load profile registry at {}: {err}",
                path.display()
            )
        })?;
    }
    if remainder.default.as_deref() == Some(target_name) {
        remainder.default = remainder.profiles.keys().next().cloned();
    }
    validate_registry(&remainder).map_err(|err| {
        anyhow::anyhow!(
            "failed to load profile registry at {} after removing profile '{target_name}': {err}",
            path.display()
        )
    })?;
    let revision = RegistryRevision(Some(contents.into_bytes()));
    Ok((registry, revision))
}

fn parse_registry(path: &Path, contents: &str) -> Result<ProfileRegistry> {
    serde_json::from_str(contents).map_err(|err| {
        anyhow::anyhow!(
            "failed to load profile registry at {}: {err}",
            path.display()
        )
    })
}

fn read_registry_contents(path: &Path) -> Result<Option<String>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            match fs::symlink_metadata(path) {
                Err(metadata_err) if metadata_err.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(None);
                }
                Err(metadata_err) => {
                    return Err(anyhow::anyhow!(
                        "failed to load profile registry at {}: {metadata_err}",
                        path.display()
                    ));
                }
                Ok(_) => {
                    return Err(anyhow::anyhow!(
                        "failed to load profile registry at {}: {err}",
                        path.display()
                    ));
                }
            }
        }
        Err(err) => {
            return Err(anyhow::anyhow!(
                "failed to load profile registry at {}: {err}",
                path.display()
            ));
        }
    };
    Ok(Some(contents))
}

pub fn save_registry(path: &Path, registry: &ProfileRegistry) -> Result<()> {
    validate_registry(registry).map_err(|err| {
        anyhow::anyhow!(
            "failed to save profile registry at {}: {err}",
            path.display()
        )
    })?;
    let contents = serde_json::to_string_pretty(registry)?;
    write_owner_only_atomic(path, &contents)
}

pub fn save_registry_if_unchanged(
    path: &Path,
    registry: &ProfileRegistry,
    revision: &RegistryRevision,
) -> Result<()> {
    let current = read_registry_contents(path)
        .map_err(|err| {
            anyhow::anyhow!(
                "failed to save profile registry at {} while checking its revision: {err}",
                path.display()
            )
        })?
        .map(String::into_bytes);
    if current != revision.0 {
        return Err(anyhow::anyhow!(
            "failed to save profile registry at {}: registry changed concurrently; retry the command",
            path.display()
        ));
    }
    save_registry(path, registry)
}

fn validate_registry(registry: &ProfileRegistry) -> Result<()> {
    if registry.version != PROFILE_REGISTRY_VERSION {
        return Err(anyhow::anyhow!(
            "unsupported profile registry version {}; supported version is {PROFILE_REGISTRY_VERSION}",
            registry.version
        ));
    }
    if let Some(default) = registry.default.as_deref()
        && !registry.profiles.contains_key(default)
    {
        return Err(anyhow::anyhow!(
            "default profile '{default}' is not present in the registry"
        ));
    }

    let mut ids = BTreeMap::<&str, &str>::new();
    for (name, entry) in &registry.profiles {
        validate_profile_name(name)?;
        ensure_valid_profile_id(name, &entry.id)?;
        if !entry.home.is_absolute() {
            return Err(anyhow::anyhow!(
                "profile '{name}' home must be absolute; remove and re-add the profile with --home <absolute-path>"
            ));
        }
        if let Some(previous) = ids.insert(&entry.id, name) {
            return Err(anyhow::anyhow!(
                "profiles '{previous}' and '{name}' use duplicate credential namespace id '{}'",
                entry.id
            ));
        }
    }
    Ok(())
}

/// Resolve the active home using the full priority chain:
/// `--home` > `SSHW_HOME` > `--profile` > registry default > built-in default.
pub fn resolve_home_with_registry(
    home_flag: Option<&Path>,
    env_home: Option<&OsStr>,
    profile_flag: Option<&str>,
    registry: &ProfileRegistry,
    sshw_base: &Path,
) -> Result<ResolvedHome> {
    if home_flag.is_some() && profile_flag.is_some() {
        return Err(anyhow::anyhow!("cannot use --home and --profile together"));
    }

    if let Some(path) = home_flag {
        return Ok(ResolvedHome::ad_hoc(
            path,
            format!("--home {}", path.display()),
        ));
    }

    if let Some(env) = env_home {
        let path = Path::new(env);
        return Ok(ResolvedHome::ad_hoc(
            path,
            format!("SSHW_HOME {}", path.display()),
        ));
    }

    if let Some(name) = profile_flag {
        let entry = registry
            .profiles
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("unknown profile '{name}'"))?;
        ensure_valid_profile_id(name, &entry.id)?;
        return Ok(ResolvedHome::profile(
            entry.home.clone(),
            &entry.id,
            format!("profile {name}"),
        ));
    }

    if let Some(default_name) = registry.default.as_deref() {
        let entry = registry.profiles.get(default_name).ok_or_else(|| {
            anyhow::anyhow!("default profile '{default_name}' is not present in the registry")
        })?;
        ensure_valid_profile_id(default_name, &entry.id)?;
        return Ok(ResolvedHome::profile(
            entry.home.clone(),
            &entry.id,
            format!("default profile {default_name}"),
        ));
    }

    Ok(builtin_default_home(sshw_base))
}

pub fn validate_profile_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(anyhow::anyhow!("profile name cannot be empty"));
    }
    if name.chars().any(char::is_control) {
        return Err(anyhow::anyhow!(
            "profile name must not contain control characters"
        ));
    }
    Ok(())
}

fn ensure_valid_profile_id(name: &str, id: &str) -> Result<()> {
    if is_reserved_profile_id(id) {
        return Err(anyhow::anyhow!(
            "profile '{name}' has a reserved id '{id}'; remove and re-add the profile to regenerate it"
        ));
    }
    let valid = id.strip_prefix("p_").is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    });
    if !valid {
        return Err(anyhow::anyhow!(
            "profile '{name}' has an invalid credential namespace id '{id}'; remove and re-add the profile to regenerate it"
        ));
    }
    Ok(())
}
