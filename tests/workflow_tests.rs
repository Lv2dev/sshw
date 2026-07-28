use std::fs;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;

const RUST_TOOLCHAIN_ACTION: &str =
    "dtolnay/rust-toolchain@2c7215f132e9ebf062739d9130488b56d53c060c";
const WORKFLOWS: &[&str] = &[
    ".github/workflows/ci.yml",
    ".github/workflows/fuzz.yml",
    ".github/workflows/release.yml",
    ".github/workflows/security.yml",
];

fn repository_file(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_workflow(relative: &str) -> String {
    fs::read_to_string(repository_file(relative))
        .unwrap_or_else(|err| panic!("failed to read {relative}: {err}"))
        .replace("\r\n", "\n")
}

fn step_block<'a>(lines: &'a [&str], step_index: usize) -> Vec<&'a str> {
    let step_indent = lines[step_index].len() - lines[step_index].trim_start().len();
    lines
        .iter()
        .skip(step_index + 1)
        .take_while(|line| {
            if line.trim().is_empty() {
                return true;
            }
            let indent = line.len() - line.trim_start().len();
            !(indent <= step_indent && line.trim_start().starts_with('-'))
        })
        .copied()
        .collect()
}

#[test]
fn rust_toolchain_action_uses_master_history_pin_and_explicit_toolchain() {
    let mut uses = 0;
    for relative in WORKFLOWS {
        let workflow = read_workflow(relative);
        let lines: Vec<_> = workflow.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            if !line.contains("dtolnay/rust-toolchain@") {
                continue;
            }
            uses += 1;
            assert!(
                line.contains(RUST_TOOLCHAIN_ACTION),
                "{relative} contains a rust-toolchain action outside the pinned master history: {line}"
            );
            let block = step_block(&lines, index);
            assert!(
                block
                    .iter()
                    .any(|line| line.trim_start().starts_with("toolchain:")),
                "{relative} rust-toolchain step must select an explicit toolchain: {line}"
            );
        }
    }
    assert!(uses > 0, "no rust-toolchain action steps were inspected");
}

#[test]
fn security_workflow_runs_locked_root_and_fuzz_audits_on_a_schedule() {
    let workflow = read_workflow(".github/workflows/security.yml");

    assert!(workflow.contains("  schedule:\n"));
    assert!(workflow.contains("permissions:\n  contents: read\n"));
    assert!(workflow.contains("cargo metadata --locked --format-version 1"));
    assert!(
        workflow
            .contains("cargo metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1")
    );
    assert!(workflow.contains("cargo deny --locked check"));
    assert!(workflow.contains("cargo deny --locked --manifest-path fuzz/Cargo.toml check"));
}

#[test]
fn integration_workflow_builds_password_fixture_once_with_bounded_retries() {
    let workflow = read_workflow(".github/workflows/ci.yml");
    assert!(workflow.contains("run: bash .github/scripts/run_ssh_integration.sh"));

    let script_path = repository_file(".github/scripts/run_ssh_integration.sh");
    assert!(
        script_path.is_file(),
        "integration test runner script is missing"
    );
    let script = read_workflow(".github/scripts/run_ssh_integration.sh");
    assert_eq!(
        script.matches("docker build").count(),
        1,
        "the fixture build must have one shared call site"
    );
    for marker in [
        "docker build --progress=plain",
        "timeout --signal=TERM --kill-after=10s",
        "SSHW_DOCKER_BUILD_TIMEOUT_SECONDS",
        "SSHW_DOCKER_BUILD_ATTEMPTS",
        "/etc/apt/sources.list.d/ubuntu.sources",
        "mirror+file:",
        "${ubuntu_mirror#mirror+file:}",
        "UBUNTU_MIRROR=$ubuntu_mirror",
        "trap cleanup EXIT",
        "SSHW_DOCKER_PASSWORD_IMAGE=\"$image_tag\"",
        "cargo test --test integration_ssh --locked -- --ignored --test-threads=1",
    ] {
        assert!(
            script.contains(marker),
            "integration test runner is missing {marker:?}"
        );
    }

    let harness = read_workflow("tests/integration_ssh.rs");
    assert!(harness.contains("std::env::var(\"SSHW_DOCKER_PASSWORD_IMAGE\")"));
    assert!(
        !harness.contains(".args([\"build\""),
        "the Rust harness must consume the shared prebuilt image"
    );
    assert!(
        !harness.contains(".args([\"rmi\""),
        "the wrapper owns shared image cleanup"
    );

    let dockerfile = read_workflow("tests/fixtures/password-sshd/Dockerfile");
    for marker in [
        "ARG UBUNTU_MIRROR",
        "Acquire::Retries=3",
        "Acquire::http::Timeout=20",
    ] {
        assert!(
            dockerfile.contains(marker),
            "password fixture Dockerfile is missing {marker:?}"
        );
    }
}

#[test]
fn release_publish_job_uses_protected_environment() {
    let workflow = read_workflow(".github/workflows/release.yml");
    let publish = workflow
        .split("\n  publish:\n")
        .nth(1)
        .expect("release workflow must contain a publish job");

    assert!(
        publish
            .lines()
            .any(|line| line == "    environment: release"),
        "release publish job must use the release environment"
    );
}

#[test]
fn release_workflow_installs_validation_components_and_recovers_exact_tags() {
    let workflow = read_workflow(".github/workflows/release.yml");

    for marker in [
        "  workflow_dispatch:\n",
        "  RELEASE_TAG: ${{ github.event_name == 'workflow_dispatch' && inputs.tag || github.ref_name }}",
        "  group: release-${{ github.event_name == 'workflow_dispatch' && inputs.tag || github.ref_name }}",
        "          components: rustfmt, clippy",
        "$env:RELEASE_TAG",
        r#"gh release create "$RELEASE_TAG""#,
    ] {
        assert!(
            workflow.contains(marker),
            "release workflow is missing recovery contract {marker:?}"
        );
    }
    assert_eq!(
        workflow
            .matches("          ref: refs/tags/${{ env.RELEASE_TAG }}")
            .count(),
        2,
        "verify and build must both checkout the exact release tag"
    );
    assert!(
        !workflow.contains("$GITHUB_REF_NAME"),
        "release commands must use the normalized release tag"
    );
}

#[test]
fn cargo_deny_rejects_unsound_advisories_in_transitive_dependencies() {
    let config = fs::read_to_string(repository_file("deny.toml")).unwrap();

    assert!(
        config
            .lines()
            .any(|line| line.trim() == "unsound = \"all\""),
        "deny.toml must gate unsound advisories across the full dependency graph"
    );
}

#[test]
fn base64_dependency_disables_default_unsafe_simd_feature() {
    let manifest = read_workflow("Cargo.toml");
    let dependency = manifest
        .lines()
        .find(|line| line.starts_with("base64 = "))
        .expect("base64 dependency is missing");

    assert!(dependency.contains("default-features = false"));
    assert!(dependency.contains(r#"features = ["std"]"#));
}

#[test]
fn release_packaging_is_deterministic_for_the_same_binary_and_epoch() {
    let script = repository_file(".github/scripts/package_release.py");
    assert!(script.is_file(), "release packaging script is missing");
    let workflow = read_workflow(".github/workflows/release.yml");
    assert!(workflow.contains("toolchain: \"1.97.0\""));
    assert!(workflow.contains("git show -s --format=%ct HEAD"));
    assert!(workflow.contains(".github/scripts/package_release.py"));
    assert!(!workflow.contains("Compress-Archive"));
    assert!(!workflow.contains("tar -czf"));

    let temp = tempfile::tempdir().unwrap();
    let binary = temp
        .path()
        .join(if cfg!(windows) { "sshw.exe" } else { "sshw" });
    fs::write(&binary, b"deterministic release fixture\n").unwrap();
    let python = if cfg!(windows) { "python" } else { "python3" };

    for extension in ["zip", "tar.gz"] {
        let first = temp.path().join(format!("first.{extension}"));
        let second = temp.path().join(format!("second.{extension}"));
        for archive in [&first, &second] {
            let status = ProcessCommand::new(python)
                .arg(&script)
                .arg("--binary")
                .arg(&binary)
                .arg("--archive")
                .arg(archive)
                .arg("--source-date-epoch")
                .arg("1700000000")
                .status()
                .unwrap_or_else(|err| {
                    panic!("Python 3 is required for release packaging tests ({python}): {err}")
                });
            assert!(status.success(), "packaging {extension} failed");
        }
        assert_eq!(
            fs::read(first).unwrap(),
            fs::read(second).unwrap(),
            "{extension} output changed for identical inputs"
        );
    }
}

#[test]
fn repository_governance_files_define_secure_contribution_paths() {
    for relative in [
        "CONTRIBUTING.md",
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/ISSUE_TEMPLATE/feature_request.yml",
        ".github/PULL_REQUEST_TEMPLATE.md",
        ".github/CODEOWNERS",
    ] {
        assert!(
            repository_file(relative).is_file(),
            "repository governance file is missing: {relative}"
        );
    }

    let contributing = read_workflow("CONTRIBUTING.md");
    assert!(contributing.contains("GitHub Security Advisory"));
    assert!(contributing.contains("cargo fmt --check"));
    assert!(contributing.contains("cargo clippy --locked --all-targets -- -D warnings"));
    assert!(contributing.contains("cargo test --locked"));
    assert!(contributing.contains("cargo deny --locked check"));
    assert!(contributing.contains("Python 3"));

    let bug_report = read_workflow(".github/ISSUE_TEMPLATE/bug_report.yml");
    assert!(bug_report.contains("Do not include real credentials"));
    assert!(bug_report.contains("GitHub Security Advisory"));

    let pull_request = read_workflow(".github/PULL_REQUEST_TEMPLATE.md");
    assert!(pull_request.contains("No real credentials or private infrastructure details"));
    assert!(pull_request.contains("Regression tests"));

    let codeowners = read_workflow(".github/CODEOWNERS");
    assert!(codeowners.lines().any(|line| line == "* @Lv2dev"));
}

#[test]
fn public_docs_cover_hardening_contracts_and_residual_risks() {
    let readme = read_workflow("README.md");
    for marker in [
        "DNS resolution, all resolved-address attempts, TCP setup, and the SSH handshake share one 15-second connection deadline.",
        "optional `causes` array",
        "`profile add`, `profile default`, `profile remove`",
        "policy setup failures",
        "deterministic archive metadata",
        "CONTRIBUTING.md",
        "Exceeding the 16 MiB limit fails the operation",
        "`profile add --force` preserves",
        "re-adding a removed profile creates a fresh credential namespace",
        "inactive policy file",
        "waits at most 5 seconds",
    ] {
        assert!(readme.contains(marker), "README is missing {marker:?}");
    }

    let security = read_workflow("SECURITY.md");
    for marker in [
        "## Residual Risk Register",
        "Next review: 2026-10-11",
        "resolver worker",
        "bit-for-bit reproducibility",
        "pre-existing releases",
        "Post-publish durability uncertainty",
        "Short exact secrets",
        "Profile namespace rebinding",
        "100 milliseconds",
        "MSRV-compatible advisory locks",
    ] {
        assert!(security.contains(marker), "SECURITY is missing {marker:?}");
    }

    let changelog = read_workflow("CHANGELOG.md");
    for marker in [
        "### Added",
        "### Changed",
        "### Security",
        "### Fixed",
        "### Documentation",
        "deterministic release archives",
        "full redacted cause chain",
    ] {
        assert!(
            changelog.contains(marker),
            "CHANGELOG is missing {marker:?}"
        );
    }
}

#[test]
fn atomic_state_writer_sets_permissions_before_publish_and_syncs_parent_after() {
    let source = read_workflow("src/storage.rs");
    let body = source
        .split("pub fn write_owner_only_atomic")
        .nth(1)
        .and_then(|rest| rest.split("fn temp_sibling_path").next())
        .expect("write_owner_only_atomic body is missing");
    let permission = body
        .find("set_owner_only(&temp_path)?")
        .expect("temp permissions must be finalized before publish");
    let publish = body
        .find("replace_atomic(&temp_path, path)?")
        .expect("atomic publish step is missing");
    let parent_sync = body
        .find("sync_parent_directory(path)")
        .expect("parent directory must be synced after publish");

    assert!(permission < publish, "permissions must precede visibility");
    assert!(
        publish < parent_sync,
        "parent sync must follow atomic publish"
    );
    assert!(
        !body.contains("set_owner_only(path)?"),
        "post-publish chmod can fail after the new state becomes visible"
    );
}
