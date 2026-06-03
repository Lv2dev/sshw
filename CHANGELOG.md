# Changelog

All notable user-facing changes to `sshw` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Stable exit codes and the `--json` envelope are treated as the public contract.

## [Unreleased]

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

[Unreleased]: https://github.com/Lv2dev/sshw/compare/v0.6.2...HEAD
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
