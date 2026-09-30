# Changelog

All notable user-facing changes to `sshw` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Stable exit codes and the `--json` envelope are treated as the public contract.

## [Unreleased]

### 설정 변경 결과 안내
- 서버·계정·권한 설정 저장 후 이전 자격 증명 정리가 실패하면 설정은 이미 적용됐다는 사실과 원인을 표시합니다. JSON에 `mutation.config_applied`·`failed_stage`·변경 대상/작업을 추가하며 기존 auth/4와 오류 envelope, 저장 후 정리 순서를 유지합니다.
- 기본 서버·프로필 삭제로 기본값이 바뀌면 이전·새 값을 human 출력과 JSON `default_change`로 안내합니다. 마지막 항목 삭제의 기본값 없음, 등록된 기본 프로필이 없을 때 기본 home 선택도 설명합니다. 자동 기본값 선택과 프로필의 home/keyring 보존 경고는 유지합니다.
- 기본 서버 전환 후 자격 증명 정리에 실패해도 적용된 기본값 전환을 오류의 `mutation.default_change`에 보존합니다. 새 설명 필드와 원인에는 비밀 마스킹을 적용합니다. Rust API의 `ErrorResponse`에는 `mutation: Option<ConfigMutationOutput>` 필드가 추가됩니다.

### 정책 판정·변경 결과 안내
- `policy check/check-put/check-get`에서 정책 활성·비활성·`--policy` 강제 적용 상태, 매칭된 명령/경로/계정 규칙과 기본 계정의 암묵 허용을 표시합니다. 쉘 구문의 정확한 명령 규칙 요구, `..` 경로 차단, 원자적 업로드의 부모 경로 판정도 설명합니다.
- JSON에 `policy` 설명을 추가하며 기존 `allowed`·`reasons`·첫 실패 종료 코드를 유지합니다. 설명은 실제 검사와 같은 정책 snapshot과 matcher를 사용하고 비밀을 마스킹하며 자격 증명이나 SSH를 조회하지 않습니다.
- 정책 수정은 추가됨·이미 있음·삭제됨·항목 없음·상태 변경 여부를 구분하고 JSON에 `changed`·`change`를 표시합니다. 변경 없는 요청도 성공으로 처리하며 파일 저장을 생략해 기존 형식과 내용을 보존합니다. v1 정책은 실제 내용이 바뀔 때 v2로 저장합니다.

### CLI 사용 오류 처리
- `run`·`put`·`get`과 대응하는 policy 검사에서 필수 명령/경로 인자가 없으면 파싱 단계에서 usage/9로 거부합니다. 기본 서버 문법은 유지하며 잘못된 호출로 home이나 감사 파일을 만들지 않습니다.
- JSON 사용 오류 메시지에 누락된 필수 인자·허용 값·수정 제안을 보존합니다. 전체 사용 구문과 반복 도움말 문구는 생략하고, 입력 진단은 렌더링 전에 마스킹합니다. 명시적인 도움말·버전 요청은 기존처럼 성공으로 처리합니다.

### 명령 사전 검사 일치
- `policy check [server] "<command>"`가 `run`과 같은 기본 서버 선택·명령 인자 해석을 사용합니다. 기존 서버명 명시 호출도 유지합니다.
- 설정·정책 로딩과 공통 로컬 검사를 실제 실행 순서에 맞춰 첫 실패 이유와 종료 코드를 일치시킵니다. 실제 실행은 첫 오류에서 중단하고, 사전 검사는 추가 차단 이유를 계속 표시하며 자격 증명이나 SSH를 조회하지 않습니다.

### 다운로드 경로 검사·안내 수정
- 디렉터리를 로컬 파일 목적지로 지정하면 SSH 연결 전에 정확한 파일 경로를 지정하도록 안내합니다. `--yes`로 해결되지 않는 덮어쓰기 안내를 제거하고 `policy check-get`도 같은 판정을 사용합니다.
- 잘못된 로컬 경로 오류에 검사 작업·목적지·원인을 표시하며, 사전 검사에서 원인이 반복되는 현상을 제거합니다. Windows에서도 부모가 파일인 경로를 사전에 거부합니다.
- 기존 덮어쓰기·심볼릭 링크 교체·없는 부모 디렉터리 생성 동작을 유지하며, 임시 저장 후 목적지가 디렉터리로 바뀐 경우도 기존 내용을 보존하고 실패합니다.

### 권한 설정 개선
- `privilege set --no-password --user <target>`로 로그인 계정별 sudo 대상을 비밀번호 없이 등록할 수 있습니다. 이후 `run --as-root`는 해당 설정으로 `sudo -n`을 사용하며 일반 실행은 자동 승격하지 않습니다.
- 비밀번호 방식과의 전환, doctor, 계정·서버 삭제가 무비밀번호 상태를 지원합니다. `su` 또는 credential과 무비밀번호 상태를 섞은 설정은 거부하며, 기존 비밀번호는 설정 저장 성공 뒤에만 정리합니다.
- 권한 설정·조회·삭제 결과와 확인 질문에 로그인 계정과 승격 대상을 구분해 표시합니다. JSON은 기존 필드를 유지하면서 `no_password`를 추가하고 무비밀번호 설정의 `credential`은 null로 반환합니다.
- 기존 설정 파일은 그대로 읽고 비밀번호 방식으로 유지합니다. Rust API의 `PrivilegeConfig.credential`은 `Option<String>`으로 바뀌며 `no_password: bool`이 추가됩니다.

### 실행 오류 처리 수정
- 일반 실행·sudo의 타임아웃, 출력 제한 및 완료 확인 오류 이후 SSH 정리 대기를 짧게 제한합니다. 기본 출력·JSON·스트리밍에 동일하게 적용하며 원래 오류 종류와 부분 출력을 유지합니다.
- `run --stream` 실패 시 완료 미확정 안내와 함께 실제 원인을 표시합니다. 각 원인의 비밀을 먼저 마스킹하고 이미 출력한 내용은 반복하지 않습니다.

## [0.14.2] - 2026-09-27

### 원자적 업로드 오류 안내
- 임시 이름 준비·SFTP 초기화·생성·읽기/쓰기·크기 확인·권한 설정·닫기·교체의 실패 단계와 실제 원인, 목적지·임시 경로, 정리 상태를 함께 안내합니다.
- 원격 파일 생성이 확인되지 않으면 해당 경로를 자동 삭제하지 않습니다. 생성 응답이 유실된 경우도 별도로 재현해 기존 목적지와 미확정 파일이 보존되는지 검증했습니다.
- 원인을 단계 안내에 결합하기 전에 개별적으로 마스킹하며, 부분 쓰기마다 남은 deadline을 적용합니다. 기존 원자성·권한·exit code 계약은 유지합니다.

## [0.14.1] - 2026-09-27

### 전송 진단 수정
- 로컬 파일의 없음·권한 거부·일반 파일이 아닌 경우를 구분하고 원래 OS 오류를 보존합니다.
- 전송 사전 검사와 실제 실행이 공통 검사를 같은 순서로 수행하도록 맞췄습니다. `check-put`은 로컬 파일 읽기 가능 여부도 확인하고 JSON에서 접근 허용과 파일 준비 상태를 구분합니다.
- 원자적 교체 실패를 서버 미지원·권한 거부·경로/목적지 문제·저장 공간·연결/시간 초과로 구분해 안내합니다. 모호한 서버 오류는 원인을 단정하지 않으며 기존 원자성·일반 rename 후퇴 금지는 유지합니다.

## [0.14.0] - 2026-09-27

### 전송·실행 개선
- `put --atomic`으로 임시 파일 업로드 후 원자적으로 목적지를 교체할 수 있습니다. POSIX rename 확장이 없는 SFTP 서버에서는 일반 덮어쓰기로 후퇴하지 않습니다.
- `run --stream`으로 비밀을 마스킹한 완성된 줄을 실행 중에 확인할 수 있습니다. 일반 실행과 sudo를 지원하며 JSON·su PTY와의 조합은 실행 전에 거부합니다.
- `policy check-put/check-get`으로 전송 경로·계정·확인 옵션과 다운로드 덮어쓰기 조건을 연결 전에 검사할 수 있습니다.

## [0.13.0] - 2026-09-27

### 의존성과 알려진 보안 제한
- 배포 철회된 `libssh2-sys 0.3.2` 대신 공식 `0.3.3`을 사용합니다. `ssh2`는 기존 공식 패키지를 유지합니다.
- 이번 버전은 사용성 개선 릴리스이며 native SSH 보안 문제가 모두 해결된 버전이 아닙니다. `0.3.3`에는 일부 공개 보안 수정이 빠져 있습니다. 상세 영향과 제한은 [SECURITY.md](SECURITY.md#native-ssh-의존성의-알려진-보안-제한-0130)를 확인하세요.

### 사용성 개선
- 명시적 `--profile`과 `SSHW_HOME` 충돌을 오류로 알려 다른 환경이 조용히 선택되지 않도록 했습니다.
- 같은 endpoint의 `add` 갱신은 다른 계정과 privilege를 보존합니다. host/port를 바꾸거나 전체 재등록하려면 `--replace`가 필요합니다.
- 갱신 확인 오류가 실제 옵션인 `--force`를 안내하고, 기본 포트 22·빈 목록 안내·등록 후 다음 명령을 제공합니다.
- `policy init/show/enable/disable/allow/remove/check`로 정책을 관리하고 SSH 연결 없이 차단 이유를 확인할 수 있습니다.
- `--as-root`의 중복 `--yes` 요구를 제거했습니다. 위험 명령에는 여전히 `--yes`가 필요합니다. `--as-root --no-password`는 저장된 비밀번호 없이 sudo -n을 명시적으로 사용합니다.
- `put --mode 755` 등 일반 파일 권한을 지정할 수 있습니다. 기본값은 600입니다.
- `doctor`는 로컬 준비 상태·SSH agent·누락된 privilege credential과 다음 조치를 표시합니다. 실제 원격 연결 여부와 진단 성공을 구분합니다.
- default/account default/profile 변경에도 JSON을 지원하고, run JSON에 `command_succeeded`를 추가했습니다. 기존 `ok`·배열·exit code 계약은 유지합니다.
- 일반 run/sudo 실패에 redaction한 부분 출력과 완료 미확인 상태를 제공하고, TTY에 작업 시작 상태를 표시합니다.
- 배포 패키지 포함 경로를 루트에 고정해 하위 동명 문서가 섞이지 않도록 했습니다.

### Fixed
- On Windows, an exact libssh2 key-exchange failure during the initial handshake is retried with a fresh TCP connection and SSH session at most twice. All attempts share the existing 15-second connection deadline, and no retry occurs after host-key verification, authentication, or remote execution begins.

## [0.12.0] - 2026-09-01

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
