# sshw

[![CI](https://github.com/Lv2dev/sshw/actions/workflows/ci.yml/badge.svg)](https://github.com/Lv2dev/sshw/actions/workflows/ci.yml)

Languages: [English](#english) | [한국어](#한국어)

---

## English

`sshw` is a cross-platform Rust CLI for operating known SSH servers without placing SSH passwords, private keys, passphrases, or tokens in prompts, shell history, or plaintext config files.

It is designed for local coding agents that need delegated server access for simple deployment and maintenance tasks. It is a **sandbox-aware SSH wrapper**: it provides per-project profile isolation, an optional command/transfer policy, an audit log, and output redaction.

### Security Boundary

`sshw` reduces accidental secret exposure in chat, command lines, shell history, JSON config, and normal command output. It also provides:

- **Profile/home isolation** — config, `known_hosts`, policy, audit, and credential namespace are scoped per home.
- **Optional policy** — an allowlist for commands and file-transfer paths (off by default).
- **Audit log** — an append-only JSONL record of mutating/active operations.
- **Output redaction** — best-effort masking of secret-looking strings in `run` output.

It is **not a strong OS sandbox**. Specifically:

- It is delegated access. If an agent may run `sshw run`, it has the server authority of the configured account.
- A fully privileged local process running as the same OS user may access the OS credential store directly.
- The policy `allow_commands` list matches by **program name**, so allowlisting a program grants its full capability *including its arguments and any files it can read or write*. `allow_commands` is therefore a strictly stronger grant than `allow_get_paths`/`allow_put_paths`; only allowlist programs you trust with arbitrary arguments.
- Redaction and audit redaction are **best-effort**. They catch common forms (PEM keys, `keyword=value`, bearer tokens) but not every secret passed inline as a flag (`-p`, `-a`, positional tokens) or split across lines. Do not pass secrets inline on the command line; use stored credentials.

`sshw` never stores passwords, private keys, passphrases, or tokens in its config files. Password auth stores the password only through the native OS credential store (or, opt-in, a session-only in-memory backend). Agent auth stores no secret and uses the user's active SSH agent.

### Install From Source

```bash
cargo build --locked --release
```

The binary will be at `target/release/sshw` (`sshw.exe` on Windows).

### Release Builds

Tagged releases build GitHub release artifacts for `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`. Each release includes a `SHA256SUMS` file. Release workflows pin GitHub Actions by commit SHA.

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

### Storage Layout And Profiles

All state lives under per-project **homes**. A home directory contains:

```text
<home>/servers.json    server metadata (host, port, user, auth type, credential key)
<home>/known_hosts      trusted SSH host keys (OpenSSH format)
<home>/policy.json      optional policy (see Policy Enforcement)
<home>/audit.jsonl      append-only audit log
```

The global profile registry maps profile names to homes:

```text
<config_dir>/sshw/profiles.json            registry
<config_dir>/sshw/profiles/default/         built-in default profile home
```

`<config_dir>` is `%AppData%\sshw` on Windows, `~/Library/Application Support/sshw` on macOS, and `~/.config/sshw` on Linux.

Credential keyring entries are always namespaced so the same server name in different homes never collides:

```text
sshw:<profile-id>:<server>     for registered/built-in profiles
sshw:home_<hash>:<server>      for ad-hoc --home / SSHW_HOME
```

### Selecting A Home

Home selection priority, highest first:

1. `--home <path>` — a one-off / project-local home for this invocation.
2. `SSHW_HOME` — same, from the environment.
3. `--profile <name>` — a registered profile (errors if unknown).
4. the registry's default profile.
5. the built-in default profile home (`<config_dir>/sshw/profiles/default`).

`--home` and `--profile` cannot be combined (exit code 3).

```bash
sshw --home ./.sshw list
SSHW_HOME=./.sshw sshw list
sshw --profile prod run web "uptime"
```

### Managing Profiles

```bash
sshw profile add prod --home /srv/prod    # the home comes from the global --home flag
sshw profile list
sshw profile list --json
sshw profile show prod
sshw profile show prod --json
sshw profile default prod
sshw profile remove prod                  # removes the registry entry only; home dir and credentials are left intact
```

Each profile stores a stable id and its home path. The first profile added becomes the default.

### Password Auth

```bash
sshw add server-alpha --host 192.0.2.10 --port 2222 --user deploy
```

Password auth is the default. `sshw` prompts for the password with hidden input and stores it in the active credential backend under the home's namespace.

On Linux the native backend requires a working Secret Service provider (GNOME Keyring, KWallet). `sshw doctor` reports availability; `sshw` never falls back to plaintext storage.

### SSH Agent Auth

```bash
sshw add server-beta --host 192.0.2.11 --port 2222 --user deploy --auth agent
```

Agent auth stores no secret; it uses the active SSH agent.

### Credential Backends

The home's `servers.json` selects the credential backend via `credential_backend` (default `native`):

- `native` — the OS keyring (Windows Credential Manager, macOS Keychain, Linux Secret Service).
- `session_only` — never touches the keyring. `set_password` stays in memory for the process only; at run time the password is taken from the `SSHW_PASSWORD` environment variable. Suited to ephemeral/CI use. `add --auth password` warns that the password is not persisted.

An external-helper backend is a planned extension behind the same `CredentialStore` trait.

### Host Trust Flow

Host key verification fails closed; unknown or changed keys are not silently accepted. Trusted keys are stored in the active home's `known_hosts`.

```bash
sshw trust server-alpha
sshw trust server-alpha --yes
```

`trust` prints the algorithm and SHA256 fingerprint, confirms unless `--yes`, and re-verifies the fingerprint immediately before writing. If the key changes during the flow, it fails instead of storing the new key.

### Commands

```bash
sshw list [--json]
sshw show <name> [--json]
sshw default [<name>]
sshw trust <name> [--yes]
sshw run [<name>] "<command>" [--json] [--yes]
sshw put [<name>] <local> <remote> [--yes]
sshw get [<name>] <remote> <local> [--yes]
sshw remove <name> [--yes]
sshw doctor [--json]
sshw profile <add|list|show|default|remove> ...
```

Global flags (available on every command): `--home <path>`, `--profile <name>`, `--policy`, `--timeout <seconds>`.

`--timeout` sets an inactivity timeout (seconds) for the remote operation phase of `run`/`put`/`get` after the connection is established; `0` or omitting it means no operation timeout, so long-running or quiet commands are not killed (matching `ssh`). Connection setup always uses a fixed timeout regardless. Note: without `--timeout`, a remote that floods stderr while withholding stdout could make `run` block indefinitely (the stdout-then-stderr read is sequential); set `--timeout` in automated or untrusted contexts to bound this.

When the name is omitted for `run`/`put`/`get`, the configured default server is used.

### Safety Rails

Dangerous commands such as `rm -rf`, `sudo`, `chmod -R`, `chown -R`, `pm2 delete`, and obvious writes to `/etc` require `--yes`. `sshw get` will not overwrite an existing local file without `--yes`. `sshw put` creates remote files with owner-only permissions where the server honors SCP modes. These are safety rails, not a security sandbox.

### Policy Enforcement

Policy is **off by default**. Turn it on for an invocation with `--policy`, or persistently with `"enabled": true` in the home's `policy.json`:

```json
{
  "version": 1,
  "enabled": true,
  "allow_commands": ["uptime", "systemctl status *"],
  "allow_put_paths": ["/srv/app"],
  "allow_get_paths": ["/var/log"]
}
```

When enforcing, `run` commands must match `allow_commands` and `put`/`get` paths must be under `allow_put_paths`/`allow_get_paths`. A command containing shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `(`, `)`, `<`, `>`) only matches an **exact** allowlist entry. Transfer paths containing `..` are rejected. Denied operations return exit code 7 (`policy`).

Policy fails closed: with `--policy`, a missing policy file is an error, and a present-but-unparseable file is always an error.

See the Security Boundary note: `allow_commands` matches by program name and does not restrict arguments or file paths.

### Audit Log

Mutating/active operations (`add`, `remove`, `trust`, `default`, `run`, `put`, `get`) are appended to the home's `audit.jsonl`, one JSON object per line:

```json
{"time_ms":1700000000000,"action":"run","server":"web","status":"ok","exit_code":0,"detail":"uptime"}
```

`detail` for `run` is only the program name (not its arguments). Server names, paths, and details are redacted on a best-effort basis. Read-only commands (`list`, `show`, `doctor`, `profile`) are not audited. Audit writes are best-effort and never fail the operation; the file is owner-only on Unix (best-effort on Windows). Treat `audit.jsonl` as sensitive.

### Output Redaction

`run` stdout, stderr, and the echoed command are passed through best-effort redaction that masks PEM private-key blocks, `keyword=value`/`keyword: value` assignments for common secret keywords, and bearer tokens. This does not understand shell semantics: a secret passed as a flag value (`mysql -phunter2`) or split across lines may not be masked. Do not pass secrets inline; remote command output is otherwise returned verbatim.

### Doctor

```bash
sshw doctor
sshw doctor --json
```

`doctor` reports the resolved home and how it was selected, the config / known_hosts / policy / audit paths, the credential namespace, whether policy is present/valid/enabled, whether the audit log is writable, and the credential backend health.

### JSON Error Contract

Commands that support `--json` (`list`, `show`, `run`, `doctor`, `profile list`, `profile show`) return a structured error envelope on runtime failures:

```json
{"ok":false,"error":{"kind":"config","message":"unknown server 'missing'","exit_code":3}}
```

| Kind | Exit code | Meaning |
| --- | ---: | --- |
| `safety` | 2 | A safety rail blocked the operation, usually requiring `--yes`. |
| `config` | 3 | Config/registry/profile is missing, invalid, or references an unknown entry. |
| `auth` | 4 | Credential lookup or authentication setup failed. |
| `ssh` | 5 | SSH connection, host key, known_hosts, session, or transfer failed. |
| `io` | 6 | Local file or filesystem handling failed. |
| `policy` | 7 | A policy allowlist denied the operation, or policy enforcement failed closed. |
| `unknown` | 1 | The failure did not match a stable category. |

`put`, `get`, `add`, `trust`, `remove`, and `default` do not have a `--json` flag; they report human-readable errors on stderr with the same stable exit codes. Human output everywhere uses the same exit-code mapping.

These codes are sshw's own operational failures. When `run` connects and the remote command itself exits non-zero, sshw exits with code `8` — kept separate so a remote status can never be read as an sshw failure (e.g. a remote `grep` finding nothing). Exit `0` means the remote command succeeded. The real remote status is reported in `run --json` as `exit_status`, and in human mode as a `note: remote command exited with status N` line on stderr.

### File Permissions And Atomicity

New `servers.json`, `policy.json`, `audit.jsonl`, and the profile registry are created owner-only on platforms that support it. Config and registry writes are atomic (write-temp-then-rename). On Windows, permissions are best-effort (NTFS ACLs on the per-user directory provide the protection) and the atomic replace preserves the existing file if the write is interrupted.

Writes within a home are not coordinated across processes: there is no file locking, so two `sshw` processes mutating the same `servers.json`, registry, or policy concurrently will lose one update (last writer wins). Run mutating commands one at a time per home.

### Coding Agent Usage

```text
Use only the local sshw CLI for server operations.
Do not ask for, type, or print SSH passwords; do not pass secrets inline as command arguments.
Before making changes, run: sshw run <server> "hostname && whoami && pwd"
Before destructive or service-impacting commands, show the exact command list and wait for confirmation.
Prefer sshw run --json when parsing output.
Use sshw put and sshw get for file transfer.
```

### Development

```bash
cargo fmt --check
cargo clippy --locked -- -D warnings
cargo test --locked
cargo run --locked -- --help
cargo run --locked -- doctor
```

### Security Reports

Please report suspected vulnerabilities through GitHub Security Advisories. Do not place real hostnames, IP addresses, passwords, tokens, private keys, or passphrases in public issues.

### License

MIT

---

## 한국어

`sshw`는 SSH 비밀번호, 개인키, 패스프레이즈, 토큰을 프롬프트, 셸 히스토리, 평문 설정 파일에 남기지 않고 등록된 SSH 서버를 조작하기 위한 크로스플랫폼 Rust CLI입니다.

로컬 코딩 에이전트가 간단한 배포·유지보수 작업을 위임받아 수행할 때 쓰도록 설계했습니다. 강한 OS 샌드박스가 아니라 **sandbox-aware SSH wrapper**로서, 프로젝트별 profile 격리, 선택적 command/transfer policy, audit log, 출력 redaction을 제공합니다.

### 보안 경계

`sshw`는 채팅, 명령줄, 셸 히스토리, JSON 설정, 일반 출력에서 비밀이 실수로 노출되는 일을 줄이며, 추가로 다음을 제공합니다.

- **profile/home 격리** — config, `known_hosts`, policy, audit, credential namespace가 home 단위로 분리됩니다.
- **선택적 policy** — command 및 파일 전송 경로 allowlist(기본 off).
- **audit log** — 변경/실행 작업의 append-only JSONL 기록.
- **출력 redaction** — `run` 출력의 비밀 형태 문자열을 best-effort로 마스킹.

다만 **강한 OS 샌드박스가 아닙니다.**

- 위임된 접근 수단입니다. 에이전트가 `sshw run`을 쓸 수 있으면 설정된 계정의 서버 권한을 갖습니다.
- 같은 OS 사용자 권한의 완전한 로컬 프로세스는 OS credential store에 직접 접근할 수 있습니다.
- policy의 `allow_commands`는 **프로그램 이름**으로 매칭하므로, 어떤 프로그램을 allowlist에 넣으면 *그 프로그램의 인자와 읽고 쓸 수 있는 파일까지 포함한 전체 기능*을 허용하는 것입니다. 따라서 `allow_commands`는 `allow_get_paths`/`allow_put_paths`보다 강한 권한이며, 임의 인자를 신뢰할 수 있는 프로그램만 등록해야 합니다.
- redaction과 audit redaction은 **best-effort**입니다. 흔한 형태(PEM 키, `keyword=value`, bearer 토큰)는 잡지만, 플래그로 전달된 비밀(`-p`, `-a`, 위치 인자 토큰)이나 여러 줄에 걸친 비밀은 못 잡을 수 있습니다. 비밀을 명령줄에 인라인으로 넘기지 말고 저장된 credential을 사용하세요.

`sshw`는 비밀번호·개인키·패스프레이즈·토큰을 설정 파일에 저장하지 않습니다. password auth는 native OS credential store(또는 opt-in session-only in-memory backend)에만 저장하며, agent auth는 비밀을 저장하지 않고 사용자의 활성 SSH agent를 사용합니다.

### 소스에서 설치

```bash
cargo build --locked --release
```

바이너리는 `target/release/sshw`(Windows는 `sshw.exe`)에 생성됩니다.

### 릴리스 빌드

태그 릴리스는 `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`, `x86_64-apple-darwin`, `aarch64-apple-darwin`용 GitHub Release 산출물과 `SHA256SUMS`를 생성합니다. 릴리스 워크플로우는 GitHub Actions를 commit SHA로 pin합니다.

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

### 저장 구조와 profile

모든 상태는 프로젝트별 **home** 아래에 있습니다. home 디렉터리 구성:

```text
<home>/servers.json    서버 메타데이터(host, port, user, auth type, credential key)
<home>/known_hosts      신뢰한 SSH host key(OpenSSH 형식)
<home>/policy.json      선택적 policy(아래 Policy 참고)
<home>/audit.jsonl      append-only audit log
```

전역 profile registry는 profile 이름을 home에 매핑합니다.

```text
<config_dir>/sshw/profiles.json            registry
<config_dir>/sshw/profiles/default/         내장 default profile home
```

`<config_dir>`는 Windows `%AppData%\sshw`, macOS `~/Library/Application Support/sshw`, Linux `~/.config/sshw`입니다.

credential keyring 키는 항상 namespaced이므로, 서로 다른 home에서 같은 서버 이름을 써도 충돌하지 않습니다.

```text
sshw:<profile-id>:<server>     등록/내장 profile
sshw:home_<hash>:<server>      ad-hoc --home / SSHW_HOME
```

### home 선택

우선순위(높은 순):

1. `--home <path>` — 일회성/프로젝트 로컬 home.
2. `SSHW_HOME` — 환경변수로 동일.
3. `--profile <name>` — 등록된 profile(없으면 에러).
4. registry의 default profile.
5. 내장 default profile home(`<config_dir>/sshw/profiles/default`).

`--home`과 `--profile`은 함께 쓸 수 없습니다(exit code 3).

```bash
sshw --home ./.sshw list
SSHW_HOME=./.sshw sshw list
sshw --profile prod run web "uptime"
```

### profile 관리

```bash
sshw profile add prod --home /srv/prod    # home은 전역 --home 플래그에서 가져옵니다
sshw profile list
sshw profile list --json
sshw profile show prod
sshw profile show prod --json
sshw profile default prod
sshw profile remove prod                  # registry 항목만 제거. home 디렉터리와 credential은 보존
```

각 profile은 stable id와 home 경로를 저장합니다. 처음 추가한 profile이 default가 됩니다.

### 비밀번호 인증

```bash
sshw add server-alpha --host 192.0.2.10 --port 2222 --user deploy
```

비밀번호 인증이 기본값입니다. `sshw`는 숨김 입력으로 비밀번호를 받아 활성 credential backend의 home namespace 키로 저장합니다.

Linux의 native backend는 동작하는 Secret Service provider(GNOME Keyring, KWallet)가 필요합니다. `sshw doctor`가 가용성을 보고하며, 평문 저장으로 fallback하지 않습니다.

### SSH Agent 인증

```bash
sshw add server-beta --host 192.0.2.11 --port 2222 --user deploy --auth agent
```

agent auth는 비밀을 저장하지 않고 활성 SSH agent를 사용합니다.

### Credential 백엔드

home의 `servers.json`이 `credential_backend`(기본 `native`)로 백엔드를 선택합니다.

- `native` — OS keyring(Windows Credential Manager, macOS Keychain, Linux Secret Service).
- `session_only` — keyring을 쓰지 않습니다. `set_password`는 프로세스 메모리에만 유지되고, 실행 시 비밀번호는 `SSHW_PASSWORD` 환경변수에서 가져옵니다. ephemeral/CI에 적합합니다. `add --auth password`는 비밀번호가 영속되지 않는다고 경고합니다.

external-helper 백엔드는 동일한 `CredentialStore` trait 뒤의 후속 확장점입니다.

### Host Trust Flow

Host key 검증은 fail-closed이며, 알 수 없거나 변경된 key는 조용히 허용하지 않습니다. 신뢰한 key는 활성 home의 `known_hosts`에 저장됩니다.

```bash
sshw trust server-alpha
sshw trust server-alpha --yes
```

`trust`는 algorithm과 SHA256 fingerprint를 출력하고 `--yes`가 없으면 확인하며, 쓰기 직전에 fingerprint를 다시 검증합니다. 흐름 중 key가 바뀌면 새 key를 저장하지 않고 실패합니다.

### 명령

```bash
sshw list [--json]
sshw show <name> [--json]
sshw default [<name>]
sshw trust <name> [--yes]
sshw run [<name>] "<command>" [--json] [--yes]
sshw put [<name>] <local> <remote> [--yes]
sshw get [<name>] <remote> <local> [--yes]
sshw remove <name> [--yes]
sshw doctor [--json]
sshw profile <add|list|show|default|remove> ...
```

전역 플래그(모든 명령에서 사용): `--home <path>`, `--profile <name>`, `--policy`, `--timeout <seconds>`.

`--timeout`은 연결 수립 이후 `run`/`put`/`get`의 원격 작업 단계에 적용되는 무진행(inactivity) 타임아웃(초)입니다. `0`이거나 생략하면 작업 타임아웃이 없어, 오래 걸리거나 조용한 명령이 강제 종료되지 않습니다(`ssh`와 동일). 연결 수립 단계는 항상 고정 타임아웃을 사용합니다. 참고: `--timeout` 없이 원격이 stdout을 보류한 채 stderr를 가득 채우면 `run`이 무한 대기할 수 있습니다(stdout→stderr 순차 read). 자동화/비신뢰 환경에서는 `--timeout`으로 상한을 두세요.

### Safety Rails

`rm -rf`, `sudo`, `chmod -R`, `chown -R`, `pm2 delete`, `/etc`에 대한 명백한 쓰기 같은 위험 명령은 `--yes`가 필요합니다. `sshw get`은 `--yes` 없이 기존 로컬 파일을 덮어쓰지 않습니다. `sshw put`은 서버가 SCP mode를 존중하면 owner-only 권한으로 원격 파일을 만듭니다. 이것은 safety rail이지 보안 샌드박스가 아닙니다.

### Policy 적용

policy는 **기본 off**입니다. 호출별로 `--policy`로 켜거나, home의 `policy.json`에 `"enabled": true`로 영속 적용합니다.

```json
{
  "version": 1,
  "enabled": true,
  "allow_commands": ["uptime", "systemctl status *"],
  "allow_put_paths": ["/srv/app"],
  "allow_get_paths": ["/var/log"]
}
```

적용 시 `run` 명령은 `allow_commands`에, `put`/`get` 경로는 `allow_put_paths`/`allow_get_paths` 하위에 매칭돼야 합니다. 쉘 메타문자(`;`, `&`, `|`, `` ` ``, `$`, `(`, `)`, `<`, `>`)를 포함한 명령은 **정확히 일치하는** allowlist 항목에만 매칭됩니다. `..`를 포함한 전송 경로는 거부됩니다. 거부된 작업은 exit code 7(`policy`)을 반환합니다.

policy는 fail-closed입니다. `--policy`인데 파일이 없으면 에러이고, 파일이 있으나 파싱 불가면 항상 에러입니다.

보안 경계 참고: `allow_commands`는 프로그램 이름으로 매칭하며 인자나 파일 경로를 제한하지 않습니다.

### Audit Log

변경/실행 작업(`add`, `remove`, `trust`, `default`, `run`, `put`, `get`)은 home의 `audit.jsonl`에 줄당 JSON 객체로 append됩니다.

```json
{"time_ms":1700000000000,"action":"run","server":"web","status":"ok","exit_code":0,"detail":"uptime"}
```

`run`의 `detail`은 인자가 아닌 프로그램 이름만 기록합니다. 서버명·경로·detail은 best-effort로 redaction됩니다. read-only 명령(`list`, `show`, `doctor`, `profile`)은 기록하지 않습니다. audit 쓰기는 best-effort이며 작업을 실패시키지 않습니다. 파일은 Unix에서 owner-only(Windows는 best-effort)입니다. `audit.jsonl`은 민감 파일로 취급하세요.

### 출력 redaction

`run`의 stdout/stderr/echo된 command는 best-effort redaction을 거칩니다. PEM 개인키 블록, 흔한 비밀 keyword의 `keyword=value`/`keyword: value`, bearer 토큰을 마스킹합니다. 쉘 의미는 이해하지 못하므로, 플래그 값으로 전달된 비밀(`mysql -phunter2`)이나 여러 줄에 걸친 비밀은 마스킹되지 않을 수 있습니다. 비밀을 인라인으로 넘기지 마세요. 그 외 원격 출력은 그대로 반환됩니다.

### Doctor

```bash
sshw doctor
sshw doctor --json
```

`doctor`는 해석된 home과 선택 경위, config/known_hosts/policy/audit 경로, credential namespace, policy present/valid/enabled, audit 쓰기 가능 여부, credential backend 상태를 보고합니다.

### JSON 오류 계약

`--json`을 지원하는 명령(`list`, `show`, `run`, `doctor`, `profile list`, `profile show`)은 런타임 실패 시 구조화된 envelope를 반환합니다.

```json
{"ok":false,"error":{"kind":"config","message":"unknown server 'missing'","exit_code":3}}
```

| Kind | Exit code | 의미 |
| --- | ---: | --- |
| `safety` | 2 | safety rail이 차단(보통 `--yes` 필요). |
| `config` | 3 | config/registry/profile이 없거나 잘못됐거나 알 수 없는 항목 참조. |
| `auth` | 4 | credential 조회 또는 인증 준비 실패. |
| `ssh` | 5 | SSH 연결, host key, known_hosts, session, 전송 실패. |
| `io` | 6 | 로컬 파일/파일시스템 처리 실패. |
| `policy` | 7 | policy allowlist가 작업을 거부했거나 policy 적용이 fail-closed. |
| `unknown` | 1 | 안정 카테고리에 매핑되지 않은 실패. |

`put`, `get`, `add`, `trust`, `remove`, `default`에는 `--json` 플래그가 없으며, 동일한 안정 exit code로 stderr에 사람용 메시지를 출력합니다. human 출력도 같은 exit code 매핑을 사용합니다.

이 코드들은 sshw 자신의 운영 실패입니다. `run`이 연결에 성공하고 원격 명령 자체가 0이 아닌 코드로 끝나면 sshw는 exit code `8`을 반환합니다 — 원격 상태(예: 매치를 못 찾은 원격 `grep`)가 sshw 실패로 오인되지 않도록 분리한 코드입니다. exit `0`은 원격 명령 성공을 뜻합니다. 실제 원격 상태는 `run --json`의 `exit_status`로, human 모드에서는 stderr의 `note: remote command exited with status N` 줄로 보고됩니다.

### 파일 권한과 원자성

새로 만드는 `servers.json`, `policy.json`, `audit.jsonl`, profile registry는 지원 플랫폼에서 owner-only로 생성됩니다. config·registry 저장은 atomic(temp 작성 후 rename)입니다. Windows에서는 권한이 best-effort(사용자별 디렉터리의 NTFS ACL이 보호)이며, atomic 교체는 쓰기 중단 시 기존 파일을 보존합니다.

한 home 안의 쓰기는 프로세스 간 조율되지 않습니다. 파일 잠금이 없으므로 두 `sshw` 프로세스가 같은 `servers.json`·registry·policy를 동시에 변경하면 한쪽 변경이 손실됩니다(마지막에 쓴 쪽이 이김). 변경 명령은 home별로 한 번에 하나씩 실행하세요.

### 코딩 에이전트 사용 예

```text
Use only the local sshw CLI for server operations.
Do not ask for, type, or print SSH passwords; do not pass secrets inline as command arguments.
Before making changes, run: sshw run <server> "hostname && whoami && pwd"
Before destructive or service-impacting commands, show the exact command list and wait for confirmation.
Prefer sshw run --json when parsing output.
Use sshw put and sshw get for file transfer.
```

### 개발

```bash
cargo fmt --check
cargo clippy --locked -- -D warnings
cargo test --locked
cargo run --locked -- --help
cargo run --locked -- doctor
```

### 보안 제보

의심되는 취약점은 GitHub Security Advisories로 제보해 주세요. 공개 이슈에는 실제 hostname, IP, 비밀번호, 토큰, 개인키, 패스프레이즈를 남기지 마세요.

### 라이선스

MIT
