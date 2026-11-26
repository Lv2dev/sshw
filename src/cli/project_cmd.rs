//! Explicit initialization/inspection of cwd project resources, never global writes.
use super::{CommandOutput, ExecContext, ProjectArgs, ProjectCommand, ProjectInitArgs, ok};
use crate::audit::{AuditRecord, AuditSink, AuditStatus, FileAuditSink};
use crate::error::{ResultErrorKindExt, app_error};
use crate::output::ErrorKind;
use crate::policy::PolicyState;
use crate::project::{ProjectSettings, ResourceMode};
use std::path::Path;

#[derive(serde::Serialize)]
struct PolicyStatus {
    #[serde(flatten)]
    policy: PolicyState,
    enable_command: Option<String>,
    next_step: Option<String>,
    message: Option<String>,
}

impl PolicyStatus {
    fn read(home: &crate::home::ResolvedHome, ctx: &ExecContext<'_>, global: bool) -> Self {
        let (policy, error) = PolicyState::inspect(&home.policy_path, ctx.policy_forced);
        let message = error.map(|error| crate::output::redact_secrets(&error.to_string()));
        let selected_ctx = ExecContext { home, ..*ctx };
        let prefix = super::policy_recovery::launcher(&selected_ctx, global);
        let mut enable_command = None;
        let next_step = if !policy.valid {
            Some("repair the selected policy file, then inspect project status again; operations fail closed until it is valid".into())
        } else if policy.saved_enabled != Some(true) {
            if let Some(project) = &home.project
                && project.policy == crate::project::ResourceSource::Global
            {
                Some(format!(
                    "the inherited policy is read-only here; {}",
                    crate::project::initialization_hint(
                        project.root.parent().unwrap_or(&project.root),
                        false,
                        true,
                    )
                ))
            } else if let Some(prefix) = prefix {
                if policy.present {
                    enable_command = Some(format!("{prefix} policy enable"));
                    Some(format!(
                        "after reviewing the allowlist, persist policy enforcement with `{}`",
                        enable_command.as_ref().unwrap()
                    ))
                } else {
                    Some(format!(
                        "create the selected policy with `{prefix} policy init`, review its allowlist, then explicitly run `{prefix} policy enable`"
                    ))
                }
            } else {
                Some("inspect and initialize/enable the selected policy using the same settings selection; no copyable command is available for this selection".into())
            }
        } else {
            None
        };
        Self {
            policy,
            enable_command,
            next_step,
            message,
        }
    }

    fn render(&self) -> String {
        let mut text = self.policy.render();
        if let Some(message) = &self.message {
            text.push_str(&format!("policy issue: {message}\n"));
        }
        if let Some(next) = &self.next_step {
            text.push_str(&format!("next: {next}\n"));
        }
        text
    }
}

pub(super) fn run(
    args: ProjectArgs,
    ctx: &ExecContext<'_>,
    directory: Option<&Path>,
    global: bool,
) -> anyhow::Result<CommandOutput> {
    let cwd = std::path::absolute(directory.unwrap_or(&std::env::current_dir()?))
        .with_error_kind(ErrorKind::Config)?;
    match args.command {
        ProjectCommand::Init(args) => initialize(args, ctx, &cwd),
        ProjectCommand::Status(args) => {
            let home = if ctx.home.project.is_some() {
                ctx.home.clone()
            } else if let Some(selection) =
                crate::project::discover_with_baseline(&cwd, !global && directory.is_none())?
            {
                crate::project::apply(ctx.home, selection)?
            } else {
                ctx.home.clone()
            };
            let policy_status = PolicyStatus::read(&home, ctx, global);
            let value = serde_json::json!({
                "ok": true, "project_present": home.project.is_some(),
                "directory": cwd, "sources": crate::project::sources(&home),
                "policy_status": policy_status
            });
            if args.json {
                return Ok(ok(format!("{value}\n")));
            }
            let sources = crate::project::sources(&home);
            Ok(ok(format!(
                "project: {}\nserver settings: {} ({})\npolicy settings: {} ({})\naudit: {}\n{}",
                cwd.display(),
                home.config_path.display(),
                sources["servers"]["scope"].as_str().unwrap_or("global"),
                home.policy_path.display(),
                sources["policy"]["scope"].as_str().unwrap_or("global"),
                home.audit_path.display(),
                policy_status.render()
            )))
        }
    }
    .with_error_kind(ErrorKind::Config)
}

fn initialization_settings(
    root: &Path,
    args: &ProjectInitArgs,
) -> anyhow::Result<(ProjectSettings, Option<Vec<u8>>, bool)> {
    let (mut settings, revision) = crate::project::load_settings(&root.join("project.json"))?;
    let original = settings.clone();
    if revision.is_none() {
        settings = ProjectSettings {
            version: 1,
            servers: if crate::project::entry_present(&root.join("servers.json"))? {
                ResourceMode::Auto
            } else {
                ResourceMode::Global
            },
            policy: if crate::project::entry_present(&root.join("policy.json"))? {
                ResourceMode::Auto
            } else {
                ResourceMode::Local
            },
        };
    }
    if let Some(mode) = args.servers {
        settings.servers = mode;
    }
    if let Some(mode) = args.policy {
        settings.policy = mode;
    }
    let changed = revision.is_none() || settings != original;
    Ok((settings, revision, changed))
}

fn selects_global(mode: ResourceMode, present: bool) -> bool {
    mode == ResourceMode::Global || (mode == ResourceMode::Auto && !present)
}

/// A local plan avoids resolving an unused global registry. Initialization
/// rechecks dependencies after locking, before copying or publishing data.
pub(super) fn local_initialization_home(
    args: &ProjectInitArgs,
    base: &Path,
    directory: &Path,
) -> anyhow::Result<Option<crate::home::ResolvedHome>> {
    let root = directory.join(".sshw");
    if !crate::project::entry_present(&root)? {
        return Ok(None);
    }
    crate::profile::validate_home_directory(&root).with_error_kind(ErrorKind::Config)?;
    let (settings, revision, _) = initialization_settings(&root, args)?;
    let servers_present = crate::project::entry_present(&root.join("servers.json"))?;
    let policy_present = crate::project::entry_present(&root.join("policy.json"))?;
    if selects_global(settings.servers, servers_present)
        || selects_global(settings.policy, policy_present)
        || !policy_present
    {
        return Ok(None);
    }
    crate::project::apply(
        &crate::home::builtin_default_home(base),
        crate::project::ProjectContext {
            root,
            servers: crate::project::ResourceSource::Local,
            policy: crate::project::ResourceSource::Local,
            revision,
        },
    )
    .map(Some)
}

pub(super) fn initialize(
    args: ProjectInitArgs,
    ctx: &ExecContext<'_>,
    cwd: &Path,
) -> anyhow::Result<CommandOutput> {
    let root = cwd.join(".sshw");
    crate::profile::validate_home_directory(&root).with_error_kind(ErrorKind::Config)?;
    let _project_lock = crate::storage::acquire_exclusive_lock(&root.join(".project.lock"))
        .with_error_kind(ErrorKind::Config)?;
    let _data_lock = crate::storage::acquire_exclusive_lock(&root.join(".sshw.lock"))
        .with_error_kind(ErrorKind::Config)?;
    let manifest = root.join("project.json");
    let (settings, revision, manifest_changed) = initialization_settings(&root, &args)?;
    let servers_path = root.join("servers.json");
    let policy_path = root.join("policy.json");
    let servers_present = crate::project::entry_present(&servers_path)?;
    let policy_present = crate::project::entry_present(&policy_path)?;
    let create_servers = settings.servers == ResourceMode::Local && !servers_present;
    let create_policy = settings.policy == ResourceMode::Local && !policy_present;
    if settings.servers != ResourceMode::Global
        && !create_servers
        && crate::project::entry_present(&servers_path)?
    {
        let local = crate::home::ResolvedHome::ad_hoc(&root, "project initialization".into());
        super::load_active_config(&local)?;
    }
    if settings.policy != ResourceMode::Global
        && !create_policy
        && crate::project::entry_present(&policy_path)?
    {
        crate::policy::load_policy_with_revision(&policy_path)
            .with_error_kind(ErrorKind::Policy)?;
    }
    let needs_global = selects_global(settings.servers, servers_present)
        || selects_global(settings.policy, policy_present)
        || create_policy;
    let baseline = if needs_global && ctx.home.project.is_some() {
        let base = ctx
            .registry_path
            .parent()
            .ok_or_else(|| app_error(ErrorKind::Config, "invalid profile registry path"))?;
        crate::project::global_home(base)?
    } else {
        ctx.home.clone()
    };
    // Snapshot only the requested, missing local policy; server secrets are never copied.
    let policy = if create_policy {
        Some(
            crate::policy::load_policy_with_revision(&baseline.policy_path)
                .with_error_kind(ErrorKind::Policy)?
                .0
                .unwrap_or_default(),
        )
    } else {
        None
    };
    let text = serde_json::to_string_pretty(&settings)?;
    let changed = manifest_changed || create_servers || create_policy;
    let result = (|| -> anyhow::Result<()> {
        if crate::project::load_settings(&manifest)?.1 != revision {
            return Err(app_error(
                ErrorKind::Config,
                "project settings changed concurrently; retry initialization",
            ));
        }
        // Publish explicit selection first. Concurrent readers fail closed while data is missing.
        if manifest_changed {
            crate::storage::write_owner_only_atomic(&manifest, &text)?;
        }
        if create_servers {
            crate::config::save_config_if_unchanged(
                &servers_path,
                &crate::config::SshwConfig::default(),
                &crate::config::ConfigRevision::missing(),
            )?;
        }
        if let Some(policy) = &policy {
            crate::policy::save_policy_if_unchanged(&policy_path, policy, &None)?;
        }
        Ok(())
    })()
    .map_err(|error| error.context(format!(
        "project initialization may be partially applied; inspect {} and rerun the original project init invocation with the same selectors and source options for project directory {}. Existing data and global settings were preserved",
        crate::error::diagnostic_path(&manifest), crate::error::diagnostic_path(cwd),
    )));
    let _ = FileAuditSink::new(root.join("audit.jsonl")).record(&AuditRecord {
        action: "project".into(),
        server: None,
        user: None,
        detail: Some(format!(
            "init;servers:{:?};policy:{:?}",
            settings.servers, settings.policy
        )),
        status: if result.is_ok() {
            AuditStatus::Ok
        } else {
            AuditStatus::Error
        },
        exit_code: result
            .as_ref()
            .err()
            .map(|e| crate::output::classify_error(e).exit_code())
            .unwrap_or(0),
    });
    result.with_error_kind(ErrorKind::Config)?;
    // Inspect only the selected policy, preserving init's metadata-only server behavior.
    let selection = crate::project::discover_with_baseline(cwd, true)?.ok_or_else(|| app_error(
        ErrorKind::Config, "project settings disappeared after initialization; inspect the selected project directory",
    ))?;
    let mut selected_home = baseline.clone();
    if selection.policy == crate::project::ResourceSource::Local {
        selected_home.policy_path = policy_path;
    }
    selected_home.project = Some(selection);
    let policy_status = PolicyStatus::read(&selected_home, ctx, false);
    if args.json {
        return Ok(ok(format!(
            "{}\n",
            serde_json::json!({"ok":true,"action":"project_initialized","root":root,"settings":settings,"changed":changed,"servers_created":create_servers,"policy_created":create_policy,"global_settings_changed":false,"policy_copied_from":if create_policy{Some(&baseline.policy_path)}else{None},"policy_status":policy_status})
        )));
    }
    Ok(ok(format!(
        "project settings {}: {}\nservers: {:?}; policy: {:?}\n{}global settings and credentials were preserved\n{}",
        if changed { "initialized" } else { "unchanged" },
        root.display(),
        settings.servers,
        settings.policy,
        if create_servers {
            "local server list starts empty; register local accounts with sshw add\n"
        } else {
            ""
        },
        policy_status.render()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_init_rechecks_global_dependencies_under_lock_without_falling_back() {
        let temp = tempfile::tempdir().unwrap();
        let cwd = temp.path().join("app");
        let root = cwd.join(".sshw");
        std::fs::create_dir_all(&root).unwrap();
        crate::config::save_config(
            &root.join("servers.json"),
            &crate::config::SshwConfig::default(),
        )
        .unwrap();
        std::fs::write(root.join("policy.json"), r#"{"enabled":false}"#).unwrap();
        let manifest = root.join("project.json");
        std::fs::write(
            &manifest,
            r#"{"version":1,"servers":"local","policy":"local"}"#,
        )
        .unwrap();
        let before = std::fs::read(&manifest).unwrap();
        let base = temp.path().join("base");
        std::fs::create_dir(&base).unwrap();
        let registry = base.join("profiles.json");
        std::fs::write(&registry, "broken global registry").unwrap();
        let args = || ProjectInitArgs {
            servers: None,
            policy: None,
            json: true,
        };
        let home = local_initialization_home(&args(), &base, &cwd)
            .unwrap()
            .unwrap();
        let audit = crate::audit::NoopAudit;
        let ctx = ExecContext {
            home: &home,
            registry_path: &registry,
            policy_forced: false,
            audit: &audit,
        };
        std::fs::remove_file(root.join("policy.json")).unwrap();
        assert!(initialize(args(), &ctx, &cwd).is_err());
        assert!(!root.join("policy.json").exists());
        assert_eq!(std::fs::read(&manifest).unwrap(), before);
        let global = temp.path().join("named-global");
        std::fs::create_dir(&global).unwrap();
        let policy = r#"{"enabled":true,"allow_commands":["uptime"]}"#;
        std::fs::write(global.join("policy.json"), policy).unwrap();
        crate::profile::save_registry(
            &registry,
            &crate::profile::ProfileRegistry {
                default: Some("prod".into()),
                profiles: std::collections::BTreeMap::from([(
                    "prod".into(),
                    crate::profile::ProfileEntry {
                        id: "p_prod".into(),
                        home: global.clone(),
                    },
                )]),
                ..Default::default()
            },
        )
        .unwrap();
        let output = initialize(args(), &ctx, &cwd).unwrap();
        let body: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(
            body["policy_copied_from"],
            global.join("policy.json").to_str().unwrap()
        );
        assert_eq!(body["policy_status"]["saved_enabled"], true);
        assert_eq!(
            std::fs::read_to_string(global.join("policy.json")).unwrap(),
            policy
        );
        assert_eq!(std::fs::read(&manifest).unwrap(), before);
        std::fs::write(
            &manifest,
            r#"{"version":1,"servers":"global","policy":"local"}"#,
        )
        .unwrap();
        let selected = std::fs::read(&manifest).unwrap();
        std::fs::write(&registry, "broken global registry").unwrap();
        assert!(initialize(args(), &ctx, &cwd).is_err());
        assert_eq!(std::fs::read(&manifest).unwrap(), selected);
    }
    #[test]
    fn inherited_policy_status_keeps_local_recovery_target_without_a_global_enable_command() {
        let temp = tempfile::tempdir().unwrap();
        let cwd = temp.path().join("app");
        std::fs::create_dir_all(cwd.join(".sshw")).unwrap();
        std::fs::write(
            cwd.join(".sshw/project.json"),
            r#"{"version":1,"servers":"global","policy":"global"}"#,
        )
        .unwrap();
        let global =
            crate::home::ResolvedHome::ad_hoc(&temp.path().join("global"), "global".into());
        std::fs::create_dir(&global.root).unwrap();
        let registry = temp.path().join("profiles.json");
        let audit = crate::audit::NoopAudit;
        let selection = crate::project::discover(&cwd).unwrap().unwrap();
        let home = crate::project::apply(&global, selection).unwrap();
        let ctx = ExecContext {
            home: &home,
            registry_path: &registry,
            policy_forced: false,
            audit: &audit,
        };
        for contents in [None, Some(r#"{"enabled":false}"#), Some("invalid policy")] {
            if let Some(contents) = contents {
                std::fs::write(&global.policy_path, contents).unwrap();
            }
            for forced in [false, true] {
                let ctx = ExecContext {
                    policy_forced: forced,
                    ..ctx
                };
                let status = PolicyStatus::read(&home, &ctx, false);
                assert!(status.enable_command.is_none());
                let next = status.next_step.as_deref().unwrap();
                if contents == Some("invalid policy") {
                    assert_eq!(status.policy.state, "blocked");
                    assert!(status.policy.enforced.is_none());
                    assert!(!next.contains("policy enable"));
                } else {
                    assert!(next.contains("--project-dir="), "{next}");
                    assert!(next.contains("--policy-source local"), "{next}");
                    assert!(!next.contains("--global policy enable"));
                }
            }
        }
        assert!(!home.audit_path.exists());
        assert!(!global.root.join(".sshw.lock").exists());
        assert!(!cwd.join(".sshw/.project.lock").exists());
    }

    #[test]
    fn initialization_published_failure_is_fail_closed_and_retry_finishes_without_global_writes() {
        let temp = tempfile::tempdir().unwrap();
        let cwd = temp.path().join("work");
        std::fs::create_dir(&cwd).unwrap();
        let global =
            crate::home::ResolvedHome::ad_hoc(&temp.path().join("global"), "global".into());
        let registry = temp.path().join("profiles.json");
        let audit = crate::audit::NoopAudit;
        let ctx = ExecContext {
            home: &global,
            registry_path: &registry,
            policy_forced: false,
            audit: &audit,
        };
        let args = || ProjectInitArgs {
            servers: Some(ResourceMode::Local),
            policy: Some(ResourceMode::Local),
            json: true,
        };
        crate::storage::fail_next_parent_sync();
        let error = initialize(args(), &ctx, &cwd).unwrap_err();
        assert!(crate::storage::write_was_published(&error));
        assert!(error.to_string().contains("partially applied"));
        assert!(crate::project::discover(&cwd).is_err());
        initialize(args(), &ctx, &cwd).unwrap();
        let selection = crate::project::discover(&cwd).unwrap().unwrap();
        assert_eq!(selection.servers, crate::project::ResourceSource::Local);
        assert!(!global.root.exists());
        let home = crate::project::apply(&global, selection).unwrap();
        let path = cwd.join(".sshw/project.json");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.push(b'\n');
        std::fs::write(path, bytes).unwrap();
        assert!(crate::project::ensure_writable(&home, true, true).is_err());
    }
}
