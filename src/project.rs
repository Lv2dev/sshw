//! Current-directory project settings: select whole server/policy resources independently.
use crate::error::{ResultErrorKindExt, app_error};
use crate::home::ResolvedHome;
use crate::output::ErrorKind;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ResourceMode {
    #[default]
    Auto,
    Local,
    Global,
}

/// A reproducible project selector, omitted rather than targeting a masked path.
pub(crate) fn command_prefix(directory: &Path) -> Option<String> {
    let directory = std::path::absolute(directory).ok()?;
    let value = directory.to_str()?;
    if value.chars().any(char::is_control)
        || crate::local_command::redacted_argument(value) != value
    {
        return None;
    }
    Some(format!(
        "sshw --project-dir={}",
        crate::local_command::quote_local_argument(value)
    ))
}

pub(crate) fn initialization_hint(directory: &Path, servers: bool, policy: bool) -> String {
    match command_prefix(directory) {
        Some(prefix) => format!(
            "initialize local project settings with `{prefix} project init{}{}`",
            if servers { " --servers-source local" } else { "" },
            if policy { " --policy-source local" } else { "" }
        ),
        None => "initialize the requested local resources in the selected project directory; no copyable command is available because its path is sensitive, contains controls, or cannot be represented".into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSettings {
    pub version: u32,
    #[serde(default)]
    pub servers: ResourceMode,
    #[serde(default)]
    pub policy: ResourceMode,
}
impl Default for ProjectSettings {
    fn default() -> Self {
        Self {
            version: 1,
            servers: ResourceMode::Auto,
            policy: ResourceMode::Auto,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourceSource {
    Local,
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectContext {
    pub root: PathBuf,
    pub servers: ResourceSource,
    pub policy: ResourceSource,
    #[serde(skip)]
    pub revision: Option<Vec<u8>>,
}
impl ProjectContext {
    pub fn needs_global(&self) -> bool {
        self.servers == ResourceSource::Global || self.policy == ResourceSource::Global
    }
}

pub fn discover(cwd: &Path) -> anyhow::Result<Option<ProjectContext>> {
    discover_with_baseline(cwd, false)
}

/// An explicit home/profile is a project command's initialization baseline.
/// A --project-dir example would discard that selection.
pub(crate) fn discover_with_baseline(
    cwd: &Path,
    preserve_baseline: bool,
) -> anyhow::Result<Option<ProjectContext>> {
    let root = cwd.join(".sshw");
    if !entry_present(&root)? {
        return Ok(None);
    }
    let metadata = fs::metadata(&root).with_error_kind(ErrorKind::Config)?;
    if !metadata.is_dir() {
        return Err(app_error(
            ErrorKind::Config,
            format!(
                "project settings path must be a directory: {}",
                crate::error::diagnostic_path(&root)
            ),
        ));
    }
    let (settings, revision) = load_settings(&root.join("project.json"))?;
    let servers = select(
        settings.servers,
        &root,
        LocalResource::Servers,
        preserve_baseline,
    )?;
    let policy = select(
        settings.policy,
        &root,
        LocalResource::Policy,
        preserve_baseline,
    )?;
    Ok(Some(ProjectContext {
        root,
        servers,
        policy,
        revision,
    }))
}

pub fn apply(global: &ResolvedHome, selection: ProjectContext) -> anyhow::Result<ResolvedHome> {
    let mut home = if selection.servers == ResourceSource::Local {
        ResolvedHome::ad_hoc(
            &selection.root,
            format!("project servers {}", selection.root.display()),
        )
    } else {
        global.clone()
    };
    if selection.policy == ResourceSource::Local {
        home.policy_path = selection.root.join("policy.json");
    } else {
        home.policy_path = global.policy_path.clone();
    }
    crate::profile::validate_home_directory(&home.root).with_error_kind(ErrorKind::Config)?;
    if let Some(parent) = home.policy_path.parent() {
        crate::profile::validate_home_directory(parent).with_error_kind(ErrorKind::Config)?;
    }
    home.audit_path = selection.root.join("audit.jsonl");
    home.description = format!(
        "{}; project {} (servers {:?}, policy {:?})",
        home.description,
        selection.root.display(),
        selection.servers,
        selection.policy
    );
    home.project = Some(selection);
    Ok(home)
}

pub fn resolve_automatic(cwd: &Path, base: &Path) -> anyhow::Result<Option<ResolvedHome>> {
    let Some(selection) = discover(cwd)? else {
        return Ok(None);
    };
    let global = if selection.needs_global() {
        global_home(base)?
    } else {
        crate::home::builtin_default_home(base)
    };
    apply(&global, selection).map(Some)
}

pub(crate) fn global_home(base: &Path) -> anyhow::Result<ResolvedHome> {
    let registry = crate::profile::load_registry(&base.join("profiles.json"))
        .with_error_kind(ErrorKind::Config)?;
    crate::profile::select_home_with_registry(None, None, None, &registry, base)
        .with_error_kind(ErrorKind::Config)
}

enum LocalResource {
    Servers,
    Policy,
}

fn select(
    mode: ResourceMode,
    project: &Path,
    resource: LocalResource,
    preserve_baseline: bool,
) -> anyhow::Result<ResourceSource> {
    if mode == ResourceMode::Global {
        return Ok(ResourceSource::Global);
    }
    let (source, file) = match resource {
        LocalResource::Servers => ("servers", "servers.json"),
        LocalResource::Policy => ("policy", "policy.json"),
    };
    let path = project.join(file);
    if entry_present(&path)? {
        return Ok(ResourceSource::Local);
    }
    if mode == ResourceMode::Local {
        let servers = matches!(resource, LocalResource::Servers);
        let hint = if preserve_baseline {
            format!(
                "from the project directory, rerun project init with --{source}-source local and the same home/profile selection"
            )
        } else {
            initialization_hint(project.parent().unwrap_or(project), servers, !servers)
        };
        let result = if servers {
            "Initialization starts an empty server list."
        } else {
            "Initialization copies the selected global policy, or starts with a disabled policy if none exists."
        };
        return Err(app_error(
            ErrorKind::Config,
            format!(
                "project selects local data but the file is missing: {}\nnext: {hint}. {result}\nTo inherit global settings, set the {source} source to global in .sshw/project.json.",
                crate::local_command::display_value(&path.display().to_string())
            ),
        ));
    }
    Ok(ResourceSource::Global)
}

pub(crate) fn entry_present(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(crate::error::persistence_error(
            error.into(),
            "inspect project settings",
            path,
            "check the project path and read permissions",
        ))
        .with_error_kind(ErrorKind::Config),
    }
}

pub(crate) fn ensure_writable(
    home: &ResolvedHome,
    servers: bool,
    policy: bool,
) -> anyhow::Result<()> {
    if let Some(project) = &home.project {
        if (servers && project.servers == ResourceSource::Global)
            || (policy && project.policy == ResourceSource::Global)
        {
            let hint = initialization_hint(
                project.root.parent().unwrap_or(&project.root),
                servers && project.servers == ResourceSource::Global,
                policy && project.policy == ResourceSource::Global,
            );
            return Err(app_error(
                ErrorKind::Config,
                format!(
                    "this project inherits the requested global settings; no changes were made. Use sshw --global for an intentional global change, or {hint}"
                ),
            ));
        }
        verify_selection(project)?;
    }
    Ok(())
}

pub(crate) fn verify_selection(project: &ProjectContext) -> anyhow::Result<()> {
    let cwd = project
        .root
        .parent()
        .ok_or_else(|| app_error(ErrorKind::Config, "invalid project root"))?;
    if discover(cwd)?.as_ref() != Some(project) {
        let inspect = command_prefix(cwd)
            .map(|prefix| format!("inspect `{prefix} project status` and retry"))
            .unwrap_or_else(|| "inspect settings in the selected project directory and retry; a copyable command is unavailable for this path".into());
        return Err(app_error(
            ErrorKind::Config,
            format!("project resource selection changed concurrently; {inspect}"),
        ));
    }
    Ok(())
}

pub(crate) fn acquire_write_locks(
    home: &ResolvedHome,
    servers: bool,
    policy: bool,
) -> anyhow::Result<Vec<crate::storage::ExclusiveFileLock>> {
    // Preserve the legacy facade/home locking contract. Split resource locks
    // belong to discovered projects; explicit homes may supply a custom policy
    // path whose write failure must retain the existing post-save reporting.
    if home.project.is_none() {
        return crate::storage::acquire_exclusive_lock(&home.root.join(".sshw.lock"))
            .map(|lock| vec![lock]);
    }
    let mut locks = Vec::new();
    if let Some(project) = &home.project {
        locks.push(crate::storage::acquire_exclusive_lock(
            &project.root.join(".project.lock"),
        )?);
        verify_selection(project)?;
    }
    let mut paths = std::collections::BTreeSet::new();
    for path in [
        servers.then_some(&home.config_path),
        policy.then_some(&home.policy_path),
    ]
    .into_iter()
    .flatten()
    {
        let parent = path.parent().unwrap_or(&home.root);
        let parent = std::fs::canonicalize(parent).or_else(|_| std::path::absolute(parent))?;
        paths.insert(parent.join(".sshw.lock"));
    }
    for path in paths {
        locks.push(crate::storage::acquire_exclusive_lock(&path)?);
    }
    if let Some(project) = &home.project {
        verify_selection(project)?;
    }
    Ok(locks)
}

pub fn sources(home: &ResolvedHome) -> serde_json::Value {
    let project = home.project.as_ref();
    serde_json::json!({
        "project_root": project.map(|p| &p.root),
        "servers": {
            "scope": project.map_or(ResourceSource::Global, |p| p.servers),
            "path": home.config_path
        },
        "policy": {
            "scope": project.map_or(ResourceSource::Global, |p| p.policy),
            "path": home.policy_path
        },
        "known_hosts": home.known_hosts_path,
        "audit": home.audit_path
    })
}

pub(crate) fn load_settings(path: &Path) -> anyhow::Result<(ProjectSettings, Option<Vec<u8>>)> {
    if !entry_present(path)? {
        return Ok((ProjectSettings::default(), None));
    }
    let bytes = fs::read(path)
        .map_err(|error| {
            crate::error::settings_error(
                error.into(),
                "failed to read project settings",
                path,
                "repair .sshw/project.json or use an explicit home/profile to bypass project discovery",
            )
        })
        .with_error_kind(ErrorKind::Config)?;
    let settings: ProjectSettings = serde_json::from_slice(&bytes)
        .map_err(|error| {
            crate::error::settings_error(
                error.into(),
                "failed to parse project settings",
                path,
                "use version 1 and servers/policy modes auto, local or global",
            )
        })
        .with_error_kind(ErrorKind::Config)?;
    if settings.version != 1 {
        return Err(app_error(
            ErrorKind::Config,
            format!(
                "unsupported project settings version {}; supported version is 1",
                settings.version
            ),
        ));
    }
    Ok((settings, Some(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn project_recovery_hints_omit_sensitive_control_and_non_utf8_selectors() {
        for value in ["token=scope-marker", "line\nbreak", "tab\tpath"] {
            let path = std::path::absolute(value).unwrap();
            assert!(command_prefix(&path).is_none());
            let hint = initialization_hint(&path, true, true);
            assert!(hint.contains("no copyable command"));
            assert!(!hint.contains("scope-marker"));
            assert!(!hint.contains("sshw project init"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            assert!(
                command_prefix(Path::new(std::ffi::OsStr::from_bytes(b"/tmp/invalid-\xff")))
                    .is_none()
            );
        }
    }
    #[test]
    fn project_selects_resources_independently_without_merging_or_changing_global_namespace() {
        let temp = tempfile::tempdir().unwrap();
        let global = ResolvedHome::profile(
            temp.path().join("global"),
            "p_global",
            "global profile".into(),
        );
        let cwd = temp.path().join("work");
        fs::create_dir(&cwd).unwrap();
        assert!(discover(&cwd).unwrap().is_none());
        let root = cwd.join(".sshw");
        fs::create_dir(&root).unwrap();
        for servers in [false, true] {
            for policy in [false, true] {
                for (name, present) in [("servers.json", servers), ("policy.json", policy)] {
                    let path = root.join(name);
                    if present {
                        fs::write(
                            path,
                            "selected data is parsed by the existing resource parser",
                        )
                        .unwrap();
                    } else if path.exists() {
                        fs::remove_file(path).unwrap();
                    }
                }
                let selected = discover(&cwd).unwrap().unwrap();
                let home = apply(&global, selected.clone()).unwrap();
                assert_eq!(
                    selected.servers,
                    if servers {
                        ResourceSource::Local
                    } else {
                        ResourceSource::Global
                    }
                );
                assert_eq!(
                    selected.policy,
                    if policy {
                        ResourceSource::Local
                    } else {
                        ResourceSource::Global
                    }
                );
                assert_eq!(
                    home.policy_path,
                    if policy {
                        root.join("policy.json")
                    } else {
                        global.policy_path.clone()
                    }
                );
                assert_eq!(
                    home.config_path,
                    if servers {
                        root.join("servers.json")
                    } else {
                        global.config_path.clone()
                    }
                );
                assert_eq!(
                    home.namespace,
                    if servers {
                        crate::home::CredentialNamespace::for_home(&root)
                    } else {
                        global.namespace.clone()
                    }
                );
                assert_eq!(
                    home.known_hosts_path,
                    if servers {
                        root.join("known_hosts")
                    } else {
                        global.known_hosts_path.clone()
                    }
                );
                assert_eq!(home.audit_path, root.join("audit.jsonl"));
            }
        }
        fs::write(
            root.join("project.json"),
            r#"{"version":1,"servers":"global","policy":"global"}"#,
        )
        .unwrap();
        assert_eq!(
            discover(&cwd).unwrap().unwrap().servers,
            ResourceSource::Global
        );
        let child = cwd.join("child");
        fs::create_dir(&child).unwrap();
        assert!(discover(&child).unwrap().is_none());
        assert!(!global.root.exists());
    }
    #[test]
    fn selected_missing_or_invalid_project_manifest_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join(".sshw");
        fs::write(&root, "not directory").unwrap();
        assert!(discover(temp.path()).is_err());
        fs::remove_file(&root).unwrap();
        fs::create_dir(&root).unwrap();
        for data in [
            "",
            "{}",
            r#"{"version":2}"#,
            r#"{"version":1,"unknown":true}"#,
            r#"{"version":1,"servers":"local"}"#,
        ] {
            fs::write(root.join("project.json"), data).unwrap();
            assert!(discover(temp.path()).is_err(), "{data}");
        }
    }
}
