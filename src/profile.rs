use crate::home::{ResolvedHome, builtin_default_home};
use crate::storage::write_owner_only_atomic;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

/// Global registry mapping profile names to their sshw home directories.
/// Lives at `<config_dir>/sshw/profiles.json`, independent of the active home.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileRegistry {
    pub version: u32,
    pub default: Option<String>,
    pub profiles: BTreeMap<String, ProfileEntry>,
}

impl Default for ProfileRegistry {
    fn default() -> Self {
        Self {
            version: 1,
            default: None,
            profiles: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileEntry {
    pub id: String,
    pub home: PathBuf,
}

pub fn load_registry(path: &Path) -> Result<ProfileRegistry> {
    if !path.exists() {
        return Ok(ProfileRegistry::default());
    }

    let contents = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&contents)?)
}

pub fn save_registry(path: &Path, registry: &ProfileRegistry) -> Result<()> {
    let contents = serde_json::to_string_pretty(registry)?;
    write_owner_only_atomic(path, &contents)
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
        return Ok(ResolvedHome::profile(
            entry.home.clone(),
            &entry.id,
            format!("default profile {default_name}"),
        ));
    }

    Ok(builtin_default_home(sshw_base))
}
