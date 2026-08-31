# Changelog

All notable user-facing changes to `sshw` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Stable exit codes and the `--json` envelope are treated as the public contract.

## [Unreleased]

### Added
- Added `account add/list/show/default/remove` and registered-account selection via `run`/`put`/`get --user`; omitting `--user` preserves the server's default-account behavior.

### Changed
- Config schema v2 stores a `default_user` and account map per server, with account-specific authentication and privilege metadata. Schema v1 remains readable and is rewritten only after a successful state mutation.
- Run and transfer JSON success output and audit JSONL now include the selected login user, while `doctor` reports missing login credentials as `server/user` entries.

### Security
- New v3 credential identities bind home namespace, purpose, server, user, and generation independently; account mutation preserves the new-secret/config-publish/stale-secret-cleanup transaction and rejects cross-account references.
- Policy schema v2 adds structured `allow_accounts`; enabled legacy v1 policies permit only default accounts, and non-default account selection fails closed without an exact server/user rule.

## [0.11.0] - 2026-08-04

### Added
- Added a `remote:<absolute-path>` literal for `put` and `get`, allowing POSIX, Windows drive, and UNC remote absolute paths to survive Git Bash/MSYS argument conversion.

### Changed
- Raised the minimum supported Rust version from 1.88 to 1.89 and replaced the `fs2` advisory-lock dependency with Rust standard-library file locks while preserving the bounded audit and state-mutation lock behavior.

### Security
- Remote path literals are decoded before safety and policy checks, invalid or relative literal values fail closed as config errors, and audit/JSON/SSH use the same decoded path.
- Future crates.io releases use a short-lived GitHub Actions OIDC token from an exact-pinned official action; recovery runs skip an existing version only when its registry checksum matches the package rebuilt from the immutable release tag.

## [0.10.1] - 2026-08-01

### Added
- Added a crates.io distribution package named `sshw-agent` that installs the existing `sshw` executable and preserves the `sshw` library target.
- CI now packages the publishable source, installs the extracted package, and runs an installed-binary version smoke test on Linux, macOS, and Windows.

### Changed
- Restricted Cargo publishing to crates.io and reduced the `.crate` contents to source and user-facing build/license/security documents.
- Release tag validation now identifies the workspace root package by Cargo package id instead of depending on the historical package name.

### Documentation
- Documented `cargo install sshw-agent --locked`, the package/executable naming difference, MSRV, native build prerequisites, and the Linux Secret Service runtime requirement in English and Korean.

## [0.10.0] - 2026-07-28

### Added
- JSON failures now include an optional `causes` array with the full redacted cause chain while preserving the existing top-level `kind`, `message`, and `exit_code` contract.
- Remote operations now have a 900-second absolute default deadline and fail if retained stdout plus stderr exceeds 16 MiB; `--timeout 0` remains an explicit operation-deadline opt-out.
- A scheduled security workflow audits the locked root and fuzz dependency graphs, and repository governance now includes contribution guidance, issue/PR templates, and CODEOWNERS.

### Changed
- Config, profile-registry, and policy documents now use strict versioned schemas that reject unknown fields, unsupported versions, malformed names, forged profile ids, and invalid privilege or credential metadata. Present but inactive policy files are validated too.
- Credential identities are derived from the canonical home namespace and typed login/privilege purpose. Active-namespace v1 references remain readable; later `add`/`privilege set` updates rotate that target to a fresh v2 key after the config commit. Credential/config mutations use compensating cleanup without deleting a generation that a published-but-not-yet-durable config may reference.
- Cooperating processes now serialize home, profile, and audit mutations with bounded advisory locks; config and profile saves also reject stale loaded revisions. Re-applying `profile add --force` to the same normalized home preserves its credential namespace id.
- Release jobs pin Rust 1.97.0 and create deterministic release archives from normalized metadata and the release commit timestamp.

### Security
- Login and privilege session credentials use separate environment variables and typed lookups, are removed from the child environment after reading, and exact loaded login/privilege passwords are masked in run stdout, stderr, and the echoed JSON command.
- Overlapping exact login/privilege secrets are deduplicated and masked longest-first, preventing a longer secret's suffix from remaining after a shorter prefix is redacted.
- Config validation now rejects dangling default servers and privilege metadata without a matching server, preventing stale privilege credentials from being rebound when the same alias is added later.
- DNS resolution, all resolved-address connection attempts, TCP setup, and the SSH handshake now share one decreasing 15-second connection budget.
- Policy and profile mutations fail closed before side effects, profile mutation attempts and policy-setup failures are audited, and read-only commands avoid unnecessary credential-backend construction.
- `cargo-deny` now rejects unsound advisories across the full transitive graph; GitHub Actions use immutable SHA pins with explicit toolchains, publishing uses a protected release environment, and tag/release protections are enabled in repository settings.
- The direct `base64` dependency disables default features and enables only `std`, keeping the optional unsafe SIMD implementation out of the credential-namespace and fingerprint encoding paths.

### Fixed
- Global `profile add/default/remove` audit records now use one deterministic built-in-default-home log instead of moving between the added, current-default, and recovery homes.
- `doctor` now diagnoses an invalid profile registry instead of being blocked by it, and a legacy relative-home entry can be removed with targeted `profile remove` only when the remaining registry is valid; other profile and runtime paths remain fail-closed.
- `get` downloads into an owner-only staging file, validates SCP completion, refuses a final-path race unless overwrite was approved, atomically installs the result, and syncs the file and parent directory before success. Local staging/persist failures remain `io`/6 through the outer SSH boundary.
- `put` and state-file writes now verify remote/local completion and parent-directory durability where supported; state persistence finalizes permissions before visibility, distinguishes post-publish durability uncertainty, and keeps the prior file intact on interrupted replacement.
- SSH channel input now sends EOF/VEOF correctly, stdout and stderr are drained together, remote non-zero notes always start on a new line, and signal/missing-marker/timeout/output-limit failures map to typed errors.
- Piped output ending in a broken pipe no longer panics: successful output remains exit 0 while an intended failure keeps its original non-zero code. Other output I/O failures use exit code 6, and raw `--json` detection no longer scans past `--`.
- JSON and human output redact exact loaded login credentials in addition to privilege credentials, and remote failures preserve their full redacted cause chain for diagnostics.
- On Windows under Git Bash/MSYS, `put` and `get` SSH failures caused by automatic remote-path argument conversion now include an actionable `MSYS2_ARG_CONV_EXCL='*'` hint without changing the typed `ssh` error or exit code 5.

### Documentation
- README, `sshw --help`, and `SECURITY.md` now describe the total connection budget, operation bounds, audit coverage, JSON cause chains, deterministic packaging limits, and a dated residual-risk register.
- Added contributor and report templates that prohibit real credentials or private infrastructure data and document the complete local verification flow.
- README now documents safe Git Bash and PowerShell transfer paths and a shell-independent `git archive` workflow that excludes build output.

## [0.9.1] - 2026-07-06

### Documentation
- README and `sshw --help` now document the v0.9.0 JSON state-change commands, `add` update privilege cleanup, `--profile` home-resolution priority, and the sudo/`su` authentication failure exit-code difference.

### Security
- CI and release automation now verify release tags against `Cargo.toml`, check the fuzz package on pull requests, audit root and fuzz dependency graphs with locked resolution, and let Dependabot update the fuzz package dependencies.
- Config saves are now the source of truth for credential references: remove/clear operations persist config changes before deleting secrets, while add/set operations clean up newly-created credentials if the config save fails.
- The session-only backend no longer reuses `SSHW_PASSWORD` as an implicit fallback for privilege credentials; privilege passwords must be explicitly set for the session or stored in the native backend.

### Fixed
- Several config/auth failures now map to their documented stable exit codes instead of `unknown` (1): unavailable native credential backends are `auth`/4, corrupt `profiles.json`, cancelled state-change confirmations, and `add --password-stdin --auth agent` are `config`/3.
- `sshw run` now fails closed when the remote SSH channel reports signal termination without an exit status, and `sshw put` now rejects a non-zero remote scp sink exit status instead of reporting the upload as successful.
- The safety guard now allows harmless `sudo` mentions such as `echo sudo` or `man sudo` while still requiring `--yes` for command-position `sudo` invocations.

## [0.9.0] - 2026-07-06

### Added
- `sshw add`, `sshw trust`, `sshw remove`, `sshw privilege set`, and `sshw privilege clear` now accept `--json`, returning `"ok":true` state-change objects on success and the standard `{"ok":false,"error":...}` envelope on failure.

### Documentation
- `sshw --help` and README now tell coding agents to chain dependent `sshw`
  calls with `&&` instead of `;`, and to briefly back off after exit-code-5
  KEX/handshake failures during rapid repeated connections before retrying from
  the failed step; earlier successful steps should only be replayed when they
  are idempotent and safe, and repeated failures call for checking network,
  server, and host trust state.

### Security
- Updated the locked `anyhow` dependency to avoid RustSec advisory RUSTSEC-2026-0190.

## [0.8.1] - 2026-06-10

### Fixed
- Windows confirmation prompts now read from the console input device path used by `rpassword`, avoiding a Windows Terminal/PowerShell 7 ConPTY hang when commands such as `privilege set`, `privilege clear`, `server remove`, `trust`, `put`, or `get` ask for `[y/N]` confirmation.
- Remote stdout/stderr that contain non-UTF-8 bytes are now preserved with Unicode replacement characters instead of failing the completed SSH command with an `io` error and dropping all captured output.

## [0.8.0] - 2026-06-09

### Added
- `sshw run --as-root --yes` now executes `su` privilege escalation over a PTY for servers without `sudo`: the configured `su` password is injected at the prompt with PTY echo disabled and `LC_ALL=C`, and is never placed on the command line or in the audit detail.

### Security
- `su` command output is framed with markers that embed a per-execution random nonce, so the privileged command's own stdout cannot reproduce the framing to truncate the captured output or spoof its exit code. The pre-command su prompt wait is bounded so a missing or unrecognized password prompt cannot hang indefinitely.
- An `su` END marker without a well-formed exit-code suffix (no digits, a missing `__` terminator, or an `i32`-overflowing value) is now rejected as a fail-closed `ssh` error instead of being read as exit code `0`.

### Fixed
- `put` to a directory (a non-regular file), a stored multiline privilege password, and an `su` run whose output frame ends early now map to their documented exit codes (`io`/6, `auth`/4, `ssh`/5) instead of the generic `unknown` (1).

### Documentation
- `sshw --help` is now self-sufficient for agents: the long help adds SECURITY MODEL, EXIT CODES (the stable table), JSON OUTPUT (the `{"ok":...}` envelope and which subcommands take `--json`), and EXAMPLES sections, and every subcommand, flag, and value enum now carries help text (the put/get `[server] <local> <remote>` grammar, the run target grammar, which commands need `--yes`, sudo vs su, and that there is no `--password` flag). The `--policy` flag help and the SECURITY MODEL bullet now note that policy enforcement is also on automatically when policy.json sets `enabled: true`, not only when `--policy` is passed; the `--policy` help also clarifies that the `if requested` qualifier applies only to a missing file, while an invalid policy file always fails closed. The SECURITY MODEL bullet now states how to select the session-only credential backend (`credential_backend: session_only` in servers.json, fed via `SSHW_PASSWORD`). The `--home` help no longer claims it overrides `--profile` (passing both is a config error); it now states `--home` overrides `SSHW_HOME` and cannot be combined with `--profile`, matching the `--profile` help. Text-only; no new flags, commands, or JSON surface.

## [0.7.0] - 2026-06-03

### Added
- `sshw privilege set/show/clear` stores per-server privilege metadata while keeping sudo/root passwords in the active credential backend instead of `servers.json`.
- `sshw run --as-root --yes` executes commands through the configured privilege method. The current executable path supports `sudo`; `su` metadata can be stored but execution stays fail-closed until PTY prompt handling is implemented.
- Cargo-fuzz harnesses and a scheduled/manual fuzz smoke workflow now cover redaction and policy parsing/allowlist invariants.

### Security
- Sudo privilege passwords are consumed by a validation step before the target command runs, and the target command runs with stdin redirected from `/dev/null`, preventing the privilege secret from flowing into command stdin.
- Privilege passwords reject embedded LF/CR, are redacted from command output when exact matches appear, and privilege credentials are cleaned up when servers or privilege settings are removed/replaced.
- CI now audits both the root package and the separate `fuzz/` cargo package with cargo-deny.

### Documentation
- Removed the stale Windows non-ASCII `known_hosts` limitation from current security guidance; Windows Unicode paths are handled through Rust file I/O as of `v0.6.1`.

## [0.6.2] - 2026-06-01

### Added
- `sshw doctor` and `sshw doctor --json` now report the libssh2 version and OpenSSL linkage/version status used by the current build, helping users check installed binaries against native-library security advisories.

## [0.6.1] - 2026-06-01

### Fixed
- Windows non-ASCII `known_hosts` paths are now handled through Rust file I/O instead of libssh2 path-based known-host file APIs, so host trust and verification work when the sshw home path contains Unicode characters.

## [0.6.0] - 2026-06-01

### Added
- `sshw add --password-stdin` registers password-auth servers non-interactively by reading the initial password from stdin and storing it in the active credential backend.

### Security
- `--password-stdin` is limited to password auth, rejects `--auth agent`, strips one final LF/CRLF, rejects empty input, and keeps the password out of argv and shell history. `sshw` still intentionally does not provide `--password <value>`.

## [0.5.1] - 2026-05-31

### Added
- `run`, `show`, `doctor`, and `profile show` `--json` success responses now include `"ok":true`, matching `put`/`get` and the error envelope's `"ok":false` so consumers can branch on `ok`. `list`/`profile list` remain JSON arrays.
- Regression tests locking the error message → `ErrorKind` classification for the safety/auth/config/io markers.

### Changed
- Invalid CLI arguments now exit with the dedicated code `9` (`usage`) instead of colliding with `safety` (exit `2`). With `--json`, a usage error is emitted as the standard `{"ok":false,"error":{"kind":"usage",...}}` envelope on stdout; otherwise the parser message goes to stderr. `--help`/`--version` still print to stdout and exit `0`.
- CI: added `timeout-minutes` to the `msrv`/`audit` (CI) and `verify`/`build`/`publish` (release) jobs, a tag-scoped concurrency group for releases, and aligned the release `verify` clippy to `--all-targets`.

### Fixed
- `get` now verifies the downloaded byte count against the SCP-announced size and fails closed before persisting, so a truncated download can no longer overwrite (or create) the destination or be reported as success — symmetric with `put`.
- `put` caps the upload at the length declared to `scp_send`, so a local file that grows mid-transfer cannot write past the declared size.

### Documentation
- Documented the Windows non-ASCII home path `known_hosts` limitation, the precise scope of best-effort redaction, the session-only backend's lack of per-server credential isolation, the previously-undocumented `doctor` fields, and the `add`/`profile add` `--force` flag.

## [0.5.0] - 2026-05-31

### Added
- `put --json` and `get --json` emit stable success summaries (`{"ok":true,"server":...,"bytes":N}`).

### Changed
- `src/cli.rs` split into `cli/model.rs` (clap model) and `cli/prompt.rs` (prompter); non-interactive `confirm` (EOF/non-TTY) now returns a clear config error with a `--yes` hint, and the "no default server" error includes an actionable hint.
- CI clippy runs with `--all-targets`; the repo-wide `.cargo/config.toml` `jobs = 1` was removed (use `CARGO_BUILD_JOBS=1` locally if needed).

### Security
- The native keyring health probe uses a per-invocation nonce credential/secret and surfaces cleanup failures instead of ignoring them.
- Clarified in README/SECURITY that `allow_commands` delegates a program's whole remote capability.

## [0.4.4] - 2026-05-31

### Security
- The session-only backend removes `SSHW_PASSWORD` from the process environment immediately after reading it.

## [0.4.3] - 2026-05-30

### Added
- Release artifacts (platform archives and `SHA256SUMS`) are covered by GitHub Artifact Attestations; README/SECURITY document `gh attestation verify`.

### Fixed
- `SHA256SUMS` records flat file names so `sha256sum -c` works from the release download directory (supersedes the `v0.4.2` checksum path issue).

## [0.4.1] - 2026-05-30

### Fixed
- `run` drains stdout and stderr concurrently, fixing a potential deadlock on large stderr output. Added real-SSH integration test coverage.

## [0.4.0] - 2026-05-30

### Changed
- **Exit-code contract:** a successful `run` whose remote command exits non-zero now returns the dedicated code `8`, kept distinct from sshw's operational codes (1–7) so a remote status is never mistaken for an sshw failure. The real status is in `run --json` (`exit_status`).

### Security
- Added a `cargo-deny` supply-chain gate and an MSRV (1.88) CI job.

## [0.3.0] - 2026-05-30

### Changed
- Separated the operation timeout from the connect timeout. `run`/`put`/`get` now default to **no** operation timeout (matching `ssh`); use the global `--timeout <seconds>` to bound inactivity.

### Fixed
- `get` downloads are atomic (temp + persist), so a failed transfer never truncates an existing local file.
- `ssh2` library errors classify as `ssh` (exit `5`) instead of leaking to `unknown`.
- `put` reports actual transferred bytes and fails closed on a truncated upload.

## [0.2.0] - 2026-05-29

### Added
- Profile/home model: all state (`servers.json`, `known_hosts`, `policy.json`, `audit.jsonl`) is scoped under a profile home, with always-namespaced credential keys. `--home`/`SSHW_HOME`/`--profile` and `profile` subcommands.
- Optional policy enforcement (allowlists, fail-closed, exit `7`), append-only JSONL audit log, best-effort output/audit redaction, and an opt-in session-only credential backend.

## [0.1.5] - 2026-05-29

### Added
- Structured JSON error envelope (`{"ok":false,"error":{"kind","message","exit_code"}}`) with stable exit codes for agent consumption.
- Bilingual (English/Korean) README.

## [0.1.0] - 2026-05-29

- Initial public release: registered-server SSH `run`/`put`/`get` with secrets kept in the OS credential store, fail-closed `known_hosts` verification, and explicit `sshw trust`.

[Unreleased]: https://github.com/Lv2dev/sshw/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/Lv2dev/sshw/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/Lv2dev/sshw/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/Lv2dev/sshw/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/Lv2dev/sshw/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/Lv2dev/sshw/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/Lv2dev/sshw/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/Lv2dev/sshw/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/Lv2dev/sshw/compare/v0.6.2...v0.7.0
[0.6.2]: https://github.com/Lv2dev/sshw/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/Lv2dev/sshw/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/Lv2dev/sshw/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/Lv2dev/sshw/releases/tag/v0.5.1
[0.5.0]: https://github.com/Lv2dev/sshw/releases/tag/v0.5.0
[0.4.4]: https://github.com/Lv2dev/sshw/releases/tag/v0.4.4
[0.4.3]: https://github.com/Lv2dev/sshw/releases/tag/v0.4.3
[0.4.1]: https://github.com/Lv2dev/sshw/releases/tag/v0.4.1
[0.4.0]: https://github.com/Lv2dev/sshw/releases/tag/v0.4.0
[0.3.0]: https://github.com/Lv2dev/sshw/releases/tag/v0.3.0
[0.2.0]: https://github.com/Lv2dev/sshw/releases/tag/v0.2.0
[0.1.5]: https://github.com/Lv2dev/sshw/releases/tag/v0.1.5
[0.1.0]: https://github.com/Lv2dev/sshw/releases/tag/v0.1.0
