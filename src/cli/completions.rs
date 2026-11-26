//! Read-only native PowerShell completion; candidates are data, never commands.

use super::{Cli, CommandOutput, CompletionsArgs, load_active_config, ok};
use crate::home::{ResolvedHome, sshw_base_dir};
use crate::profile::{ProfileRegistry, load_registry, select_home_with_registry};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Arg, Command, CommandFactory};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};

const MAX_REQUEST: u64 = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    /// Literal arguments before the argument currently being completed; no executable.
    words: Vec<String>,
    word: String,
}

#[derive(Serialize)]
struct Candidate {
    value: String,
    description: String,
    kind: &'static str,
}

pub(super) fn run(args: &CompletionsArgs) -> anyhow::Result<CommandOutput> {
    if !args.query {
        return Ok(ok(include_str!("completions.ps1").into()));
    }
    anyhow::ensure!(
        !std::io::stdin().is_terminal(),
        "completion queries require piped data on stdin"
    );
    let mut encoded = String::new();
    std::io::stdin()
        .take(MAX_REQUEST + 1)
        .read_to_string(&mut encoded)?;
    anyhow::ensure!(
        encoded.len() <= MAX_REQUEST as usize,
        "completion request is too large"
    );
    let request: Request = serde_json::from_slice(&STANDARD.decode(encoded.trim())?)?;
    let base = sshw_base_dir()?;
    let env_home = std::env::var_os("SSHW_HOME").filter(|value| !value.is_empty());
    Ok(ok(format!(
        "{}\n",
        ascii_json(&suggestions(request, &base, env_home.as_deref()))?
    )))
}

fn ascii_json(candidates: &[Candidate]) -> anyhow::Result<String> {
    // Windows PowerShell 5.1 decodes native stdout with the console code page.
    // JSON Unicode escapes keep names lossless without changing console state.
    let json = serde_json::to_string(candidates)?;
    let mut escaped = String::with_capacity(json.len());
    for character in json.chars() {
        if character.is_ascii() {
            escaped.push(character);
        } else {
            for unit in character.encode_utf16(&mut [0; 2]) {
                write!(&mut escaped, "\\u{unit:04x}").expect("writing to String cannot fail");
            }
        }
    }
    Ok(escaped)
}

struct Context {
    command: Command,
    path: Vec<String>,
    positionals: Vec<String>,
    pending: Option<Arg>,
    used: BTreeSet<String>,
    home: Option<PathBuf>,
    profile: Option<String>,
    project_dir: Option<PathBuf>,
    literal: bool,
}

impl Context {
    fn parse(words: &[String]) -> Option<Self> {
        let mut command = Cli::command();
        command.build();
        let mut context = Self {
            command,
            path: Vec::new(),
            positionals: Vec::new(),
            pending: None,
            used: BTreeSet::new(),
            home: None,
            profile: None,
            project_dir: None,
            literal: false,
        };
        for word in words {
            if let Some(arg) = context.pending.take() {
                if word.starts_with('-') {
                    return None;
                }
                context.value(&arg, word);
            } else if !context.literal && word == "--" {
                context.literal = true;
            } else if !context.literal && word.starts_with('-') {
                let (flag, value) = word
                    .split_once('=')
                    .map_or((word.as_str(), None), |(flag, value)| (flag, Some(value)));
                let arg = context.option(flag)?.clone();
                context.used.insert(arg.get_id().to_string());
                if takes_value(&arg) {
                    if let Some(value) = value {
                        context.value(&arg, value);
                    } else {
                        context.pending = Some(arg);
                    }
                } else if value.is_some() {
                    return None;
                }
            } else if !context.literal
                && context.positionals.is_empty()
                && let Some(subcommand) = context.command.find_subcommand(word).cloned()
            {
                context.path.push(subcommand.get_name().into());
                context.command = subcommand;
            } else {
                context.positionals.push(word.clone());
            }
        }
        Some(context)
    }

    fn option(&self, flag: &str) -> Option<&Arg> {
        self.command.get_arguments().find(|arg| {
            if arg.is_hide_set() || self.conflicts_with_present_argument(arg) {
                return false;
            }
            if let Some(long) = flag.strip_prefix("--") {
                arg.get_long() == Some(long)
                    || arg
                        .get_visible_aliases()
                        .is_some_and(|aliases| aliases.contains(&long))
            } else {
                arg.get_short()
                    .is_some_and(|short| flag == format!("-{short}"))
            }
        })
    }

    fn conflicts_with_present_argument(&self, candidate: &Arg) -> bool {
        let present = |arg: &Arg| {
            self.used.contains(arg.get_id().as_str())
                || arg
                    .get_index()
                    .is_some_and(|index| self.positionals.len() >= index)
        };
        // Clap conflicts apply in both directions even when declared on one arg.
        self.command
            .get_arg_conflicts_with(candidate)
            .into_iter()
            .any(present)
            || self
                .command
                .get_arguments()
                .filter(|arg| present(arg))
                .any(|arg| {
                    self.command
                        .get_arg_conflicts_with(arg)
                        .into_iter()
                        .any(|other| other.get_id() == candidate.get_id())
                })
    }

    fn value(&mut self, arg: &Arg, value: &str) {
        match arg.get_id().as_str() {
            "home" => self.home = Some(value.into()),
            "profile" => self.profile = Some(value.into()),
            "project_dir" => self.project_dir = Some(value.into()),
            _ => {}
        }
    }

    fn home(&self, base: &Path, env_home: Option<&OsStr>) -> Option<ResolvedHome> {
        let global = self.used.contains("global");
        let env_home = if global || self.project_dir.is_some() {
            None
        } else {
            env_home
        };
        if self.home.is_none() && self.profile.is_none() && env_home.is_none() && !global {
            let cwd = self
                .project_dir
                .clone()
                .or_else(|| std::env::current_dir().ok())?;
            match crate::project::resolve_automatic(&cwd, base).ok()? {
                Some(home) => return Some(home),
                None if self.project_dir.is_some() => return None,
                None => {}
            }
        }
        let registry = if self.home.is_some() || env_home.is_some() {
            ProfileRegistry::default()
        } else {
            load_registry(&base.join("profiles.json")).ok()?
        };
        select_home_with_registry(
            self.home.as_deref(),
            env_home,
            self.profile.as_deref(),
            &registry,
            base,
        )
        .ok()
    }

    fn accounts(&self, base: &Path, env_home: Option<&OsStr>) -> Vec<String> {
        let Some(home) = self.home(base, env_home) else {
            return Vec::new();
        };
        let Ok(config) = load_active_config(&home) else {
            return Vec::new();
        };
        let path: Vec<_> = self.path.iter().map(String::as_str).collect();
        let fixed = match path.as_slice() {
            ["run"] | ["policy", "check"] => Some(1),
            ["put"] | ["policy", "check-put"] => Some(2),
            ["get"] | ["policy", "check-get"] => {
                Some(if self.used.contains("into") { 1 } else { 2 })
            }
            _ => None,
        };
        let name = if let Some(fixed) = fixed {
            // A remote command/source can equal a registered server name.
            // Use execution's argument-count rule, never a name-match guess.
            let Some((name, _)) = super::split_target(&self.positionals, fixed) else {
                return Vec::new();
            };
            name.or(config.default.as_deref())
        } else {
            self.positionals.first().map(String::as_str)
        };
        name.and_then(|name| config.servers.get(name))
            .map(|server| server.accounts.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn values(&self, arg: &Arg, base: &Path, env_home: Option<&OsStr>) -> Vec<String> {
        match arg.get_id().as_str() {
            "switch_default" if self.path.first().is_some_and(|name| name == "account") => self
                .accounts(base, env_home)
                .into_iter()
                .filter(|user| self.positionals.get(1) != Some(user))
                .collect(),
            "switch_default" if self.path.first().is_some_and(|name| name == "profile") => {
                profiles(base)
                    .into_iter()
                    .filter(|name| self.positionals.first() != Some(name))
                    .collect()
            }
            "switch_default" => self
                .home(base, env_home)
                .and_then(|home| load_active_config(&home).ok())
                .map(|config| {
                    config
                        .servers
                        .into_keys()
                        .filter(|name| self.positionals.first() != Some(name))
                        .collect()
                })
                .unwrap_or_default(),
            "profile" if self.home.is_none() && env_home.is_none() => profiles(base),
            "user"
                if matches!(
                    self.path.first().map(String::as_str),
                    Some("run" | "put" | "get" | "password" | "test" | "doctor")
                ) || matches!(self.path.as_slice(), [policy, check] if policy == "policy" && check.starts_with("check")) =>
            {
                self.accounts(base, env_home)
            }
            "account" if self.path.first().is_some_and(|name| name == "privilege") => {
                self.accounts(base, env_home)
            }
            _ => arg
                .get_possible_values()
                .into_iter()
                .filter(|value| !value.is_hide_set())
                .map(|value| value.get_name().into())
                .collect(),
        }
    }

    fn positional_values(&self, base: &Path, env_home: Option<&OsStr>) -> Vec<String> {
        if self.used.contains("clear") {
            return Vec::new();
        }
        let path: Vec<_> = self.path.iter().map(String::as_str).collect();
        match (path.as_slice(), self.positionals.len()) {
            (["profile", "show" | "default" | "remove" | "rename"], 0) => profiles(base),
            (["account", _], 1) | (["policy", "allow" | "remove", "account"], 1) => {
                self.accounts(base, env_home)
            }
            (
                [
                    "add" | "show" | "rename" | "endpoint" | "password" | "default" | "trust"
                    | "run" | "put" | "get" | "remove" | "doctor" | "test",
                ],
                0,
            )
            | (["account" | "privilege", _], 0)
            | (["policy", "check" | "check-put" | "check-get"], 0)
            | (["policy", "allow" | "remove", "account"], 0) => self
                .home(base, env_home)
                .and_then(|home| load_active_config(&home).ok())
                .map(|config| config.servers.into_keys().collect())
                .unwrap_or_default(),
            _ => self
                .command
                .get_positionals()
                .find(|arg| arg.get_index() == Some(self.positionals.len() + 1))
                .map(|arg| self.values(arg, base, env_home))
                .unwrap_or_default(),
        }
    }
}

fn takes_value(arg: &Arg) -> bool {
    arg.get_num_args()
        .is_some_and(|range| range.max_values() > 0)
}

fn profiles(base: &Path) -> Vec<String> {
    load_registry(&base.join("profiles.json"))
        .map(|registry| registry.profiles.into_keys().collect())
        .unwrap_or_default()
}

fn suggestions(request: Request, base: &Path, env_home: Option<&OsStr>) -> Vec<Candidate> {
    let Some(context) = Context::parse(&request.words) else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    let mut prefix = request.word.as_str();
    let mut value_flag = None;
    if let Some(arg) = &context.pending {
        candidates.extend(
            context
                .values(arg, base, env_home)
                .into_iter()
                .filter(|value| !value.starts_with('-'))
                .map(value_candidate),
        );
    } else if !context.literal
        && let Some((flag, value)) = request.word.split_once('=')
        && let Some(arg) = context.option(flag).filter(|arg| takes_value(arg))
    {
        prefix = value;
        value_flag = Some(flag);
        candidates.extend(
            context
                .values(arg, base, env_home)
                .into_iter()
                .map(value_candidate),
        );
    } else if !context.literal && request.word.starts_with('-') {
        for arg in context.command.get_arguments().filter(|arg| {
            !arg.is_hide_set()
                && !context.used.contains(arg.get_id().as_str())
                && !context.conflicts_with_present_argument(arg)
        }) {
            let description = arg.get_help().map(ToString::to_string).unwrap_or_default();
            let flags = arg
                .get_long()
                .into_iter()
                .chain(arg.get_visible_aliases().unwrap_or_default())
                .map(|long| format!("--{long}"))
                .chain(arg.get_short().map(|short| format!("-{short}")));
            for value in flags {
                candidates.push(Candidate {
                    value,
                    description: description.clone(),
                    kind: "ParameterName",
                });
            }
        }
    } else {
        if !context.literal && context.positionals.is_empty() {
            for command in context
                .command
                .get_subcommands()
                .filter(|command| !command.is_hide_set())
            {
                candidates.push(Candidate {
                    value: command.get_name().into(),
                    description: command
                        .get_about()
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                    kind: "ParameterValue",
                });
            }
        }
        candidates.extend(
            context
                .positional_values(base, env_home)
                .into_iter()
                .filter(|value| context.literal || !value.starts_with('-'))
                .map(value_candidate),
        );
    }
    let prefix = prefix.to_lowercase();
    let mut sorted = BTreeMap::new();
    for mut candidate in candidates {
        // Do not turn redacted placeholders into unusable completions or reveal
        // identifiers that normal diagnostic output treats as secret-looking.
        if candidate.value.to_lowercase().starts_with(&prefix)
            && !candidate.value.chars().any(char::is_control)
            && super::hints::redacted_argument(&candidate.value) == candidate.value
        {
            if let Some(flag) = value_flag {
                candidate.value = format!("{flag}={}", candidate.value);
            }
            sorted.insert(candidate.value.clone(), candidate);
        }
    }
    sorted.into_values().collect()
}

fn value_candidate(value: String) -> Candidate {
    Candidate {
        description: value.clone(),
        value,
        kind: "ParameterValue",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AccountConfig, AuthConfig, ServerConfig, SshwConfig, save_config};
    use crate::profile::{ProfileEntry, save_registry};

    #[test]
    fn completion_json_is_ascii_and_round_trips_korean_and_surrogate_pairs() {
        let name = "개발 서버 🦀";
        let encoded = ascii_json(&[value_candidate(name.into())]).unwrap();
        assert!(encoded.is_ascii());
        let decoded: Vec<serde_json::Value> = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded[0]["value"], name);
        assert_eq!(decoded[0]["description"], name);
    }

    fn query(words: &[&str], word: &str, base: &Path, env: Option<&OsStr>) -> Vec<String> {
        suggestions(
            Request {
                words: words.iter().map(|s| (*s).into()).collect(),
                word: word.into(),
            },
            base,
            env,
        )
        .into_iter()
        .map(|candidate| candidate.value)
        .collect()
    }

    #[test]
    fn project_completion_respects_explicit_sources_and_global_bypass() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("base");
        let cwd = temp.path().join("project");
        let global = crate::home::builtin_default_home(&base);
        config(&global.root, "global", "deploy");
        config(&cwd.join(".sshw"), "local", "ops");
        std::fs::write(cwd.join(".sshw/policy.json"), "{}").unwrap();
        let path = cwd.to_str().unwrap();
        assert_eq!(
            query(
                &["--project-dir", path, "run"],
                "",
                &base,
                Some(global.root.as_os_str())
            ),
            ["local"]
        );
        assert_eq!(
            query(&["--global", "run"], "", &base, Some(cwd.as_os_str())),
            ["global"]
        );
        std::fs::write(cwd.join(".sshw/project.json"), "invalid").unwrap();
        assert!(query(&["--project-dir", path, "run"], "", &base, None).is_empty());
        assert_eq!(query(&["--global", "run"], "", &base, None), ["global"]);
        assert!(query(&["--global"], "--project-dir", &base, None).is_empty());
        assert!(query(&["--project-dir", path], "--global", &base, None).is_empty());
        assert!(!cwd.join(".sshw/audit.jsonl").exists());
        assert!(!cwd.join(".sshw/.sshw.lock").exists());
    }

    #[test]
    fn completion_filters_conflicting_flags_in_both_directions_and_equals_values() {
        let temp = tempfile::tempdir().unwrap();
        config(temp.path(), "prod", "deploy");
        let path = temp.path().join("servers.json");
        let before = std::fs::read(&path).unwrap();
        let env = Some(temp.path().as_os_str());
        for (words, prefix) in [
            (vec!["run", "prod", "uptime", "--stream"], "--json"),
            (vec!["run", "prod", "uptime", "--json"], "--stream"),
            (
                vec!["remove", "prod", "--clear-default"],
                "--switch-default",
            ),
            (
                vec!["remove", "prod", "--switch-default", "other"],
                "--clear-default",
            ),
            (
                vec!["profile", "remove", "old", "--clear-default"],
                "--switch-default",
            ),
            (
                vec!["profile", "remove", "old", "--switch-default", "other"],
                "--clear-default",
            ),
            (
                vec!["privilege", "set", "prod", "--no-password"],
                "--password-stdin",
            ),
            (
                vec!["privilege", "set", "prod", "--password-stdin"],
                "--no-password",
            ),
            (vec!["default", "prod"], "--clear"),
            (vec!["profile", "default", "prod"], "--clear"),
            (
                vec!["remove", "old", "--clear-default"],
                "--switch-default=pro",
            ),
            (
                vec!["remove", "old", "--clear-default", "--switch-default"],
                "pro",
            ),
        ] {
            assert!(
                query(&words, prefix, temp.path(), env).is_empty(),
                "{words:?} {prefix}"
            );
        }
        for (words, prefix, expected) in [
            (vec!["run", "prod", "uptime", "--stream"], "--yes", "--yes"),
            (
                vec!["remove", "prod", "--clear-default"],
                "--json",
                "--json",
            ),
            (
                vec!["remove", "old"],
                "--switch-default=pro",
                "--switch-default=prod",
            ),
            (
                vec!["privilege", "set", "prod", "--no-password"],
                "--force",
                "--force",
            ),
        ] {
            assert_eq!(
                query(&words, prefix, temp.path(), env),
                [expected],
                "{words:?}"
            );
        }
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(!temp.path().join("audit.jsonl").exists());
        assert!(!temp.path().join(".sshw.lock").exists());
    }

    #[test]
    fn account_completion_uses_target_arity_even_when_source_matches_another_server() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("servers.json");
        let mut config = SshwConfig {
            default: Some("prod".into()),
            servers: BTreeMap::from([
                (
                    "prod".into(),
                    ServerConfig::single_account("192.0.2.10", 22, "deploy", AuthConfig::Agent),
                ),
                (
                    "report".into(),
                    ServerConfig::single_account("192.0.2.11", 22, "auditor", AuthConfig::Agent),
                ),
            ]),
            ..Default::default()
        };
        save_config(&path, &config).unwrap();
        let before = std::fs::read(&path).unwrap();
        let env = Some(temp.path().as_os_str());
        for words in [
            vec!["run", "report", "--user"],
            vec!["put", "report", "/dest", "--user"],
            vec!["get", "report", "local", "--user"],
            vec!["get", "report", "--into", ".", "--user"],
            vec!["policy", "check", "report", "--user"],
            vec!["policy", "check-put", "report", "/dest", "--user"],
            vec!["policy", "check-get", "report", "local", "--user"],
            vec!["policy", "check-get", "report", "--into=.", "--user"],
        ] {
            assert_eq!(query(&words, "", temp.path(), env), ["deploy"], "{words:?}");
        }
        for words in [
            vec!["run", "report", "id", "--user"],
            vec!["put", "report", "source", "/dest", "--user"],
            vec!["get", "report", "/source", "local", "--user"],
            vec!["get", "report", "/source", "--into", ".", "--user"],
            vec!["policy", "check", "report", "id", "--user"],
            vec!["policy", "check-put", "report", "source", "/dest", "--user"],
            vec![
                "policy",
                "check-get",
                "report",
                "/source",
                "local",
                "--user",
            ],
            vec![
                "policy",
                "check-get",
                "report",
                "/source",
                "--into=.",
                "--user",
            ],
            vec!["doctor", "report", "--user"],
            vec!["test", "report", "--user"],
            vec!["password", "report", "--user"],
            vec!["privilege", "show", "report", "--account"],
        ] {
            assert_eq!(
                query(&words, "", temp.path(), env),
                ["auditor"],
                "{words:?}"
            );
        }
        for words in [
            vec!["run", "missing", "id", "--user"],
            vec!["get", "missing", "/source", "--into", ".", "--user"],
            vec!["put", "report", "--user"],
            vec!["get", "--user"],
        ] {
            assert!(query(&words, "", temp.path(), env).is_empty(), "{words:?}");
        }
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(!temp.path().join("audit.jsonl").exists());
        assert!(!temp.path().join(".sshw.lock").exists());
        config.default = None;
        save_config(&path, &config).unwrap();
        assert!(
            query(
                &["get", "report", "--into", ".", "--user"],
                "",
                temp.path(),
                env
            )
            .is_empty()
        );
        assert_eq!(
            query(
                &["get", "report", "/source", "--into", ".", "--user"],
                "",
                temp.path(),
                env
            ),
            ["auditor"]
        );
    }

    #[test]
    fn transfer_check_help_and_completion_only_offer_supported_options() {
        let temp = tempfile::tempdir().unwrap();
        for (name, supported, unsupported) in [
            ("check-put", "--atomic", "--into"),
            ("check-get", "--into", "--atomic"),
        ] {
            let mut root = Cli::command();
            root.build();
            let check = root
                .find_subcommand_mut("policy")
                .unwrap()
                .find_subcommand_mut(name)
                .unwrap();
            let help = check.render_long_help().to_string();
            assert!(help.contains(supported));
            assert!(!help.contains(unsupported), "{name}: {help}");
            assert_eq!(
                query(&["policy", name], supported, temp.path(), None),
                [supported]
            );
            assert!(query(&["policy", name], unsupported, temp.path(), None).is_empty());
        }
    }

    fn config(home: &Path, name: &str, user: &str) {
        let mut server = ServerConfig::single_account("192.0.2.10", 22, user, AuthConfig::Agent);
        server.accounts.insert(
            "ops account".into(),
            AccountConfig {
                auth: AuthConfig::Agent,
                privilege: None,
            },
        );
        save_config(
            &home.join("servers.json"),
            &SshwConfig {
                default: Some(name.into()),
                servers: BTreeMap::from([(name.into(), server)]),
                ..Default::default()
            },
        )
        .unwrap();
    }

    #[test]
    fn completion_uses_cli_definition_without_loading_a_home_or_exposing_query() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("missing-base");
        assert_eq!(query(&["default"], "--cl", &base, None), ["--clear"]);
        assert_eq!(
            query(&["profile", "default"], "--cl", &base, None),
            ["--clear"]
        );
        assert!(query(&["default", "web"], "--cl", &base, None).is_empty());
        assert!(query(&["default", "--clear"], "", &base, None).is_empty());
        assert!(query(&["profile", "default", "--clear"], "", &base, None).is_empty());
        assert_eq!(
            query(&["put"], "--pro", &base, None),
            ["--profile", "--progress", "--project-dir"]
        );
        assert_eq!(query(&["get"], "--prog", &base, None), ["--progress"]);
        assert_eq!(query(&[], "pa", &base, None), ["password"]);
        assert_eq!(query(&["run"], "--us", &base, None), ["--user"]);
        assert_eq!(query(&["run"], "--ele", &base, None), ["--elevate"]);
        assert_eq!(query(&["account"], "a", &base, None), ["add"]);
        assert_eq!(query(&["policy", "allow"], "a", &base, None), ["account"]);
        assert_eq!(
            query(&["add", "web", "--auth"], "a", &base, None),
            ["agent"]
        );
        assert_eq!(
            query(&["privilege", "set", "web"], "--method=s", &base, None),
            ["--method=su", "--method=sudo"]
        );
        assert_eq!(query(&["completions"], "p", &base, None), ["powershell"]);
        assert!(
            !query(&["completions", "powershell"], "--", &base, None).contains(&"--query".into())
        );
        assert!(!base.exists());
    }

    #[test]
    fn completion_respects_home_environment_named_and_default_profile_namespaces() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("base");
        let named = temp.path().join("named");
        let explicit = temp.path().join("explicit");
        config(&named, "prod named", "named-user");
        config(&explicit, "prod explicit", "explicit-user");
        save_registry(
            &base.join("profiles.json"),
            &ProfileRegistry {
                version: 1,
                default: Some("production".into()),
                profiles: BTreeMap::from([(
                    "production".into(),
                    ProfileEntry {
                        id: "p_production".into(),
                        home: named.clone(),
                    },
                )]),
            },
        )
        .unwrap();
        assert_eq!(query(&["run"], "prod", &base, None), ["prod named"]);
        assert_eq!(
            query(&["run"], "prod", &base, Some(explicit.as_os_str())),
            ["prod explicit"]
        );
        assert_eq!(
            query(&["run", "--profile", "production"], "prod", &base, None),
            ["prod named"]
        );
        let selected = format!("--home={}", explicit.display());
        assert_eq!(
            query(&["run", &selected], "prod", &base, None),
            ["prod explicit"]
        );
        assert_eq!(query(&["--profile"], "pro", &base, None), ["production"]);
        assert_eq!(
            query(
                &["profile", "remove", "old", "--switch-default"],
                "pro",
                &base,
                None
            ),
            ["production"]
        );
        assert!(
            query(
                &["profile", "remove", "production", "--switch-default"],
                "pro",
                &base,
                None
            )
            .is_empty()
        );
        assert_eq!(
            query(&["remove", "old", "--switch-default"], "prod", &base, None),
            ["prod named"]
        );
        assert!(
            query(
                &["remove", "prod named", "--switch-default"],
                "prod",
                &base,
                None
            )
            .is_empty()
        );
        assert_eq!(
            query(&["profile", "rename"], "pro", &base, None),
            ["production"]
        );
        assert!(query(&["profile", "rename", "production"], "pro", &base, None).is_empty());
        assert_eq!(
            query(
                &[
                    "account",
                    "remove",
                    "prod named",
                    "named-user",
                    "--switch-default"
                ],
                "op",
                &base,
                None
            ),
            ["ops account"]
        );
        assert!(
            query(
                &[
                    "account",
                    "remove",
                    "prod named",
                    "named-user",
                    "--switch-default"
                ],
                "named",
                &base,
                None
            )
            .is_empty()
        );
        assert_eq!(
            query(&["profile", "show"], "pro", &base, None),
            ["production"]
        );
        assert!(query(&["run", "--profile", "missing"], "prod", &base, None).is_empty());
        assert!(
            query(
                &["run", "--profile", "production"],
                "prod",
                &base,
                Some(explicit.as_os_str())
            )
            .is_empty()
        );
        assert!(
            query(
                &["run", &selected, "--profile", "production"],
                "prod",
                &base,
                None
            )
            .is_empty()
        );
    }

    #[test]
    fn completion_selects_registered_accounts_and_never_suggests_free_text_commands() {
        let temp = tempfile::tempdir().unwrap();
        config(temp.path(), "prod", "deploy");
        let env = Some(temp.path().as_os_str());
        for words in [
            vec!["run", "prod", "--user"],
            vec!["run", "uptime", "--user"],
            vec!["password", "prod", "--user"],
            vec!["privilege", "set", "prod", "--account"],
            vec!["account", "show", "prod"],
            vec!["policy", "allow", "account", "prod"],
            vec!["policy", "check", "prod", "id", "--user"],
        ] {
            assert_eq!(
                query(&words, "ops", temp.path(), env),
                ["ops account"],
                "{words:?}"
            );
        }
        assert_eq!(
            query(&["run", "prod"], "prod", temp.path(), env),
            Vec::<String>::new()
        );
        assert!(
            query(
                &["privilege", "set", "prod", "--user"],
                "",
                temp.path(),
                env
            )
            .is_empty()
        );
        assert!(query(&["account", "show", "unknown"], "", temp.path(), env).is_empty());
        assert!(query(&["run", "--bogus"], "prod", temp.path(), env).is_empty());
    }

    #[test]
    fn completion_is_literal_read_only_and_suppresses_invalid_or_sensitive_metadata() {
        let temp = tempfile::tempdir().unwrap();
        config(temp.path(), "prod;$(example)", "deploy");
        let config_path = temp.path().join("servers.json");
        let before = std::fs::read(&config_path).unwrap();
        let mtime = std::fs::metadata(&config_path).unwrap().modified().unwrap();
        let env = Some(temp.path().as_os_str());
        assert_eq!(
            query(&["remove"], "PROD;", temp.path(), env),
            ["prod;$(example)"]
        );
        assert_eq!(std::fs::read(&config_path).unwrap(), before);
        assert_eq!(
            std::fs::metadata(&config_path).unwrap().modified().unwrap(),
            mtime
        );
        assert!(!temp.path().join("audit.jsonl").exists());
        assert!(!temp.path().join(".sshw.lock").exists());
        config(temp.path(), "token=private-marker", "deploy");
        assert!(query(&["run"], "", temp.path(), env).is_empty());
        config(temp.path(), "-production", "deploy");
        assert!(query(&["run"], "", temp.path(), env).is_empty());
        assert_eq!(
            query(&["run", "--"], "-p", temp.path(), env),
            ["-production"]
        );
        std::fs::write(config_path, "invalid config").unwrap();
        assert!(query(&["run"], "", temp.path(), env).is_empty());
    }
}
