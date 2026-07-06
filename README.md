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
- The policy `allow_commands` list matches by **program name**, not by arguments. Allowlisting a program delegates that program's whole remote capability: its flags, files it can read/write, and any subprocesses it can spawn. Be careful with shells/interpreters (`sh`, `bash`, `python`, `perl`), file tools (`cat`, `tar`, `find`, `rsync`, `scp`), and privilege/process tools (`sudo`, service managers). `allow_commands` is therefore a strictly stronger grant than `allow_get_paths`/`allow_put_paths`; prefer narrow exact commands such as `uptime` or `systemctl status app`.
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

Release artifacts are also published with GitHub Artifact Attestations. Checksums verify file integrity; attestations verify build provenance (repository, workflow, commit, and event). From a directory containing the downloaded release assets:

```bash
gh release download vX.Y.Z --repo Lv2dev/sshw
sha256sum -c SHA256SUMS

for artifact in sshw-*.tar.gz sshw-*.zip SHA256SUMS; do
  gh attestation verify "$artifact" -R Lv2dev/sshw
done
```

### Storage Layout And Profiles

All state lives under per-project **homes**. A home directory contains:

```text
<home>/servers.json    server metadata (host, port, user, auth type, credential key, privilege metadata)
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
sshw:<profile-id>:privilege:<server>     privileged sudo/su credential metadata
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

For non-interactive registration, pipe the password from a secret manager:

```bash
secret-manager-read deploy/server-alpha | sshw add server-alpha --host 192.0.2.10 --port 2222 --user deploy --password-stdin
```

`--password-stdin` is valid only with password auth. It reads stdin once, strips one final LF or CRLF, rejects empty input, and avoids placing the password in argv or shell history. `sshw` intentionally does not provide `--password <value>`.

On Linux the native backend requires a working Secret Service provider (GNOME Keyring, KWallet). `sshw doctor` reports availability; `sshw` never falls back to plaintext storage.

### SSH Agent Auth

```bash
sshw add server-beta --host 192.0.2.11 --port 2222 --user deploy --auth agent
```

Agent auth stores no secret; it uses the active SSH agent.

### Credential Backends

The home's `servers.json` selects the credential backend via `credential_backend` (default `native`):

- `native` — the OS keyring (Windows Credential Manager, macOS Keychain, Linux Secret Service).
- `session_only` — never touches the keyring. `set_password` stays in memory for the process only; at run time the password is taken from the `SSHW_PASSWORD` environment variable and then removed from this process environment. Suited to ephemeral/CI use. Environment variables can still be visible before `sshw` starts or in the parent shell, so treat `SSHW_PASSWORD` as sensitive. `add --auth password` warns that the password is not persisted.

An external-helper backend is a planned extension behind the same `CredentialStore` trait.

### Privileged Commands

```bash
secret-manager-read root/server-alpha | sshw privilege set server-alpha --method sudo --password-stdin
sshw privilege show server-alpha
sshw privilege clear server-alpha --yes
sshw run server-alpha "systemctl restart app" --as-root --yes
```

`privilege set` stores only method, target user (default `root`), and credential key metadata in `servers.json`. The sudo/root password is stored in the active credential backend, never in CLI arguments or plaintext config. Without `--password-stdin`, `sshw` prompts with hidden input.

`run --as-root` is explicit and always requires `--yes`. It first applies the normal safety and policy checks to the original command, then uses `sudo -S` with the privilege password passed through SSH channel stdin. The password is never embedded in the remote command string or audit detail. If the target user has a `NOPASSWD` sudoers rule, the command runs regardless of whether the stored password is correct, since `sudo` never consumes it — keep the stored secret accurate, but do not rely on it as an extra gate in that configuration. A sudo password rejection is reported as the remote command's non-zero status (sshw exit `8`, with the real status in `run --json` as `exit_status`) because `sudo` ran remotely. `method=su` runs `su - <user> -c ...` over a PTY and injects the stored password at the `Password:` prompt (echo disabled, prompt forced to English via `LC_ALL=C`). The command's output and exit code are framed by markers and extracted exactly. It is more environment-sensitive than `sudo`; where the prompt is not recognized it fails closed via a timeout rather than hanging. A `su` prompt/auth failure before the completion marker is an sshw auth/setup failure and maps to exit code `4`.

### Host Trust Flow

Host key verification fails closed; unknown or changed keys are not silently accepted. Trusted keys are stored in the active home's `known_hosts`.

```bash
sshw trust server-alpha
sshw trust server-alpha --yes
```

`trust` prints the algorithm and SHA256 fingerprint, confirms unless `--yes`, and re-verifies the fingerprint immediately before writing. If the key changes during the flow, it fails instead of storing the new key.

### Commands

```bash
sshw add <name> --host <host> --port <port> --user <user> [--auth password|agent] [--password-stdin] [--force] [--json]
sshw list [--json]
sshw show <name> [--json]
sshw default [<name>]
sshw trust <name> [--yes] [--json]
sshw run [<name>] "<command>" [--json] [--yes] [--as-root]
sshw put [<name>] <local> <remote> [--json] [--yes]
sshw get [<name>] <remote> <local> [--json] [--yes]
sshw remove <name> [--yes] [--json]
sshw doctor [--json]
sshw privilege <set|show|clear> ... [--json]
sshw profile <add|list|show|default|remove> ...
```

`add` (and `profile add`) take `--force` to overwrite an existing entry without the interactive confirmation prompt — required when registering or updating an entry non-interactively (e.g. from an agent). Updating an existing server with `add` clears that server's privilege metadata and deletes the stale privilege password from the active credential backend, so run `sshw privilege set ...` again before the next `run --as-root`.

Global flags (available on every command): `--home <path>`, `--profile <name>`, `--policy`, `--timeout <seconds>`.

`--timeout` sets an inactivity timeout (seconds) for the remote operation phase of `run`/`put`/`get` after the connection is established; `0` or omitting it means no operation timeout, so long-running or quiet commands are not killed (matching `ssh`). Connection setup always uses a fixed timeout regardless. `run` drains stdout and stderr concurrently; `--timeout` is still useful in automated or untrusted contexts to bound commands that stop producing output or never close.

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

See the Security Boundary note: `allow_commands` delegates whole-program execution. It does not restrict arguments, file paths, or subprocess behavior inside the allowed program. `allow_put_paths`/`allow_get_paths` match remote paths by lexical prefix and reject `..`, but they do not resolve remote symlinks or canonicalize paths, so a symlink under an allowed prefix can still point elsewhere on the host — the path allowlist is a guardrail, not a remote sandbox.

### Audit Log

Mutating/active operations (`add`, `remove`, `trust`, `default`, `run`, `put`, `get`, `privilege set`, `privilege clear`) are appended to the home's `audit.jsonl`, one JSON object per line:

```json
{"time_ms":1700000000000,"action":"run","server":"web","status":"ok","exit_code":0,"detail":"uptime"}
```

`detail` for `run` is only the program name (not its arguments). Server names, paths, and details are redacted on a best-effort basis. Read-only commands (`list`, `show`, `doctor`, `profile`) are not audited. Audit writes are best-effort and never fail the operation; the file is owner-only on Unix (best-effort on Windows). The log is append-only but not tamper-evident — it has no integrity chain or signing, and anyone who can write the home can edit or delete entries. Treat `audit.jsonl` as sensitive.

### Output Redaction

`run` stdout, stderr, and the echoed command are passed through best-effort redaction that masks PEM private-key blocks, `keyword=value`/`keyword: value` assignments for common secret keywords, and bearer tokens. For `run --as-root`, the configured privilege password is also redacted if it appears verbatim in stdout/stderr. This does not understand shell semantics: a secret passed as a flag value (`mysql -phunter2`) or split across lines may not be masked. Do not pass secrets inline; remote command output is otherwise returned verbatim.

### Doctor

```bash
sshw doctor
sshw doctor --json
```

`doctor` reports the resolved home and how it was selected, the registry / config / known_hosts / policy / audit paths, whether the config file exists, the operating system, the linked libssh2 and OpenSSL version/status, the credential namespace, whether policy is present/valid/enabled, whether the audit log is writable, the credential backend health, and any configured servers whose credentials are missing (`missing_credentials`). On Windows default builds, `openssl_version` may report `not linked (Windows WinCNG backend)` because libssh2 uses WinCNG instead of OpenSSL.

### JSON Error Contract

Commands that support `--json` (`add`, `list`, `show`, `trust`, `run`, `put`, `get`, `remove`, `doctor`, `profile list`, `profile show`, `privilege set`, `privilege show`, `privilege clear`) return a structured error envelope on runtime failures:

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
| `usage` | 9 | CLI arguments were invalid (unknown flag/subcommand, missing or extra argument), detected before any command runs. |
| `unknown` | 1 | The failure did not match a stable category. |

`put --json` and `get --json` return transfer summaries on success:

```json
{"ok":true,"server":"server-alpha","local":"./app","remote":"/tmp/app","bytes":1234}
```

Every single-object `--json` success response (`add`, `show`, `trust`, `run`, `put`, `get`, `remove`, `doctor`, `profile show`, `privilege set`, `privilege show`, `privilege clear`) includes `"ok":true`, mirroring the `"ok":false` error envelope so a consumer can branch on `ok`. `list` and `profile list` return a JSON array on success (no wrapping object); on failure they emit the same `{"ok":false,...}` envelope.

`default` and profile state changes (`profile add`, `profile default`, `profile remove`) do not have a `--json` flag; they report human-readable errors on stderr with the same stable exit codes. Human output everywhere uses the same exit-code mapping.

Invalid CLI arguments exit with code `9` (`usage`), kept distinct from `safety` (2) so an agent can tell "called sshw wrong" apart from "a safety rail blocked the operation". With `--json`, a usage error is emitted as the same envelope on stdout (`{"ok":false,"error":{"kind":"usage",...}}`); otherwise the parser's message goes to stderr. `--help`/`--version` print to stdout and exit `0`.

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
Chain dependent calls with &&, not ; (for example: sshw put ... && sleep 1 && sshw run ...).
If exit 5 mentions KEX/handshake during rapid repeated connections, wait briefly and retry from the failed step.
Example: Unable to exchange encryption keys.
Retry earlier successful steps only when they are idempotent and safe to repeat.
If it fails again, inspect network, server, and host trust state.
```

### Development

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo run --locked -- --help
cargo run --locked -- doctor
```

On constrained local machines, limit Cargo parallelism per invocation instead of committing a repo-wide config, for example `CARGO_BUILD_JOBS=1 cargo test --locked`.

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
- policy의 `allow_commands`는 인자가 아니라 **프로그램 이름**으로 매칭합니다. 어떤 프로그램을 allowlist에 넣는 것은 그 프로그램의 원격 실행권 전체를 위임하는 것과 같습니다. 그 프로그램의 플래그, 읽고 쓸 수 있는 파일, 자체 기능으로 실행할 수 있는 하위 프로세스까지 포함됩니다. 쉘/인터프리터(`sh`, `bash`, `python`, `perl`), 파일 도구(`cat`, `tar`, `find`, `rsync`, `scp`), 권한/프로세스 도구(`sudo`, service manager)는 특히 주의하세요. 따라서 `allow_commands`는 `allow_get_paths`/`allow_put_paths`보다 강한 권한이며, `uptime`이나 `systemctl status app` 같은 좁은 exact command를 선호하세요.
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

릴리스 산출물에는 GitHub Artifact Attestation도 생성됩니다. checksum은 파일 무결성을 확인하고, attestation은 빌드 출처(repository, workflow, commit, event)를 확인합니다. 릴리스 산출물을 내려받은 디렉터리에서:

```bash
gh release download vX.Y.Z --repo Lv2dev/sshw
sha256sum -c SHA256SUMS

for artifact in sshw-*.tar.gz sshw-*.zip SHA256SUMS; do
  gh attestation verify "$artifact" -R Lv2dev/sshw
done
```

### 저장 구조와 profile

모든 상태는 프로젝트별 **home** 아래에 있습니다. home 디렉터리 구성:

```text
<home>/servers.json    서버 메타데이터(host, port, user, auth type, credential key, privilege metadata)
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
sshw:<profile-id>:privilege:<server>     privileged sudo/su credential metadata
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

비대화형 등록에서는 secret manager 출력에서 비밀번호를 pipe로 전달할 수 있습니다.

```bash
secret-manager-read deploy/server-alpha | sshw add server-alpha --host 192.0.2.10 --port 2222 --user deploy --password-stdin
```

`--password-stdin`은 password auth에서만 유효합니다. stdin을 한 번 읽고 마지막 LF 또는 CRLF 하나만 제거하며, 빈 입력은 거부합니다. 이 경로는 비밀번호를 argv나 shell history에 남기지 않기 위한 것이며, `sshw`는 의도적으로 `--password <value>` 인자를 제공하지 않습니다.

Linux의 native backend는 동작하는 Secret Service provider(GNOME Keyring, KWallet)가 필요합니다. `sshw doctor`가 가용성을 보고하며, 평문 저장으로 fallback하지 않습니다.

### SSH Agent 인증

```bash
sshw add server-beta --host 192.0.2.11 --port 2222 --user deploy --auth agent
```

agent auth는 비밀을 저장하지 않고 활성 SSH agent를 사용합니다.

### Credential 백엔드

home의 `servers.json`이 `credential_backend`(기본 `native`)로 백엔드를 선택합니다.

- `native` — OS keyring(Windows Credential Manager, macOS Keychain, Linux Secret Service).
- `session_only` — keyring을 쓰지 않습니다. `set_password`는 프로세스 메모리에만 유지되고, 실행 시 비밀번호는 `SSHW_PASSWORD` 환경변수에서 가져온 뒤 이 프로세스 환경에서 제거합니다. ephemeral/CI에 적합합니다. 환경변수는 `sshw` 시작 전이나 부모 셸에는 노출될 수 있으므로 `SSHW_PASSWORD`를 민감하게 취급하세요. `add --auth password`는 비밀번호가 영속되지 않는다고 경고합니다.

external-helper 백엔드는 동일한 `CredentialStore` trait 뒤의 후속 확장점입니다.

### 권한 상승 명령

```bash
secret-manager-read root/server-alpha | sshw privilege set server-alpha --method sudo --password-stdin
sshw privilege show server-alpha
sshw privilege clear server-alpha --yes
sshw run server-alpha "systemctl restart app" --as-root --yes
```

`privilege set`은 method, 대상 user(기본 `root`), credential key metadata만 `servers.json`에 저장합니다. sudo/root 비밀번호는 활성 credential backend에만 저장되며 CLI 인자나 평문 config에는 들어가지 않습니다. `--password-stdin`을 쓰지 않으면 숨김 입력 프롬프트로 받습니다.

`run --as-root`는 명시적으로만 동작하며 항상 `--yes`가 필요합니다. 원래 명령에 기존 safety/policy 검사를 먼저 적용한 뒤, SSH channel stdin으로만 privilege 비밀번호를 전달하는 `sudo -S` 경로를 사용합니다. 비밀번호는 원격 command string이나 audit detail에 들어가지 않습니다. 대상 user에 `NOPASSWD` sudoers 규칙이 있으면 `sudo`가 비밀번호를 소비하지 않으므로, 저장된 비밀번호의 정확성과 무관하게 명령이 실행됩니다 — 이 경우 저장 비밀번호는 추가 게이트가 아닙니다. sudo 비밀번호 거부는 원격에서 실행된 `sudo` 명령의 non-zero 상태로 보고되므로 sshw exit `8`이며, 실제 상태는 `run --json`의 `exit_status`에 들어갑니다. `method=su`는 `su - <user> -c ...`를 PTY로 실행하고 `Password:` 프롬프트가 나오면 저장된 비밀번호를 주입합니다(echo 비활성화, `LC_ALL=C`로 프롬프트를 영어로 고정). 명령 출력과 exit code는 marker로 정확히 추출되어 출력 라인이 누락되지 않습니다. `sudo`보다 환경에 민감하며, 프롬프트를 인식하지 못하면 무한 대기 대신 타임아웃으로 fail-closed됩니다. completion marker 전에 발생한 `su` 프롬프트/인증 실패는 sshw의 auth/setup 실패로 간주되어 exit code `4`에 매핑됩니다.

### Host Trust Flow

Host key 검증은 fail-closed이며, 알 수 없거나 변경된 key는 조용히 허용하지 않습니다. 신뢰한 key는 활성 home의 `known_hosts`에 저장됩니다.

```bash
sshw trust server-alpha
sshw trust server-alpha --yes
```

`trust`는 algorithm과 SHA256 fingerprint를 출력하고 `--yes`가 없으면 확인하며, 쓰기 직전에 fingerprint를 다시 검증합니다. 흐름 중 key가 바뀌면 새 key를 저장하지 않고 실패합니다.

### 명령

```bash
sshw add <name> --host <host> --port <port> --user <user> [--auth password|agent] [--password-stdin] [--force] [--json]
sshw list [--json]
sshw show <name> [--json]
sshw default [<name>]
sshw trust <name> [--yes] [--json]
sshw run [<name>] "<command>" [--json] [--yes] [--as-root]
sshw put [<name>] <local> <remote> [--json] [--yes]
sshw get [<name>] <remote> <local> [--json] [--yes]
sshw remove <name> [--yes] [--json]
sshw doctor [--json]
sshw privilege <set|show|clear> ... [--json]
sshw profile <add|list|show|default|remove> ...
```

`add`(및 `profile add`)는 `--force`로 기존 항목을 대화형 확인 프롬프트 없이 덮어씁니다 — 비대화형(예: 에이전트)에서 항목을 등록/갱신할 때 필요합니다. 기존 서버를 `add`로 갱신하면 해당 서버의 privilege metadata와 활성 credential backend의 오래된 privilege 비밀번호가 삭제되므로, 다음 `run --as-root` 전에 `sshw privilege set ...`을 다시 실행해야 합니다.

전역 플래그(모든 명령에서 사용): `--home <path>`, `--profile <name>`, `--policy`, `--timeout <seconds>`.

`--timeout`은 연결 수립 이후 `run`/`put`/`get`의 원격 작업 단계에 적용되는 무진행(inactivity) 타임아웃(초)입니다. `0`이거나 생략하면 작업 타임아웃이 없어, 오래 걸리거나 조용한 명령이 강제 종료되지 않습니다(`ssh`와 동일). 연결 수립 단계는 항상 고정 타임아웃을 사용합니다. `run`은 stdout과 stderr를 동시에 배출합니다. 그래도 자동화/비신뢰 환경에서는 출력이 멈추거나 닫히지 않는 명령을 제한하기 위해 `--timeout`으로 상한을 둘 수 있습니다.

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

보안 경계 참고: `allow_commands`는 프로그램 실행권 전체를 위임합니다. 허용된 프로그램 내부의 인자, 파일 경로, 하위 프로세스 동작은 제한하지 않습니다. `allow_put_paths`/`allow_get_paths`는 원격 경로를 lexical prefix로 매칭하고 `..`를 거부하지만, 원격 symlink를 따라가거나 canonical 경로로 검증하지는 않습니다. 허용된 prefix 아래의 symlink가 호스트의 다른 위치를 가리킬 수 있으므로 path allowlist는 원격 sandbox가 아니라 guardrail입니다.

### Audit Log

변경/실행 작업(`add`, `remove`, `trust`, `default`, `run`, `put`, `get`, `privilege set`, `privilege clear`)은 home의 `audit.jsonl`에 줄당 JSON 객체로 append됩니다.

```json
{"time_ms":1700000000000,"action":"run","server":"web","status":"ok","exit_code":0,"detail":"uptime"}
```

`run`의 `detail`은 인자가 아닌 프로그램 이름만 기록합니다. 서버명·경로·detail은 best-effort로 redaction됩니다. read-only 명령(`list`, `show`, `doctor`, `profile`)은 기록하지 않습니다. audit 쓰기는 best-effort이며 작업을 실패시키지 않습니다. 파일은 Unix에서 owner-only(Windows는 best-effort)입니다. append-only이지만 tamper-evident가 아닙니다 — 무결성 체인이나 서명이 없고, home을 쓸 수 있는 누구나 항목을 수정·삭제할 수 있습니다. `audit.jsonl`은 민감 파일로 취급하세요.

### 출력 redaction

`run`의 stdout/stderr/echo된 command는 best-effort redaction을 거칩니다. PEM 개인키 블록, 흔한 비밀 keyword의 `keyword=value`/`keyword: value`, bearer 토큰을 마스킹합니다. `run --as-root`에서는 설정된 privilege 비밀번호가 stdout/stderr에 그대로 나타나면 추가로 마스킹합니다. 쉘 의미는 이해하지 못하므로, 플래그 값으로 전달된 비밀(`mysql -phunter2`)이나 여러 줄에 걸친 비밀은 마스킹되지 않을 수 있습니다. 비밀을 인라인으로 넘기지 마세요. 그 외 원격 출력은 그대로 반환됩니다.

### Doctor

```bash
sshw doctor
sshw doctor --json
```

`doctor`는 해석된 home과 선택 경위, registry/config/known_hosts/policy/audit 경로, config 파일 존재 여부, 운영체제, 연결된 libssh2 및 OpenSSL 버전/상태, credential namespace, policy present/valid/enabled, audit 쓰기 가능 여부, credential backend 상태, 그리고 credential이 없는 등록 서버 목록(`missing_credentials`)을 보고합니다. Windows 기본 빌드에서는 libssh2가 OpenSSL 대신 WinCNG를 사용하므로 `openssl_version`이 `not linked (Windows WinCNG backend)`로 표시될 수 있습니다.

### JSON 오류 계약

`--json`을 지원하는 명령(`add`, `list`, `show`, `trust`, `run`, `put`, `get`, `remove`, `doctor`, `profile list`, `profile show`, `privilege set`, `privilege show`, `privilege clear`)은 런타임 실패 시 구조화된 envelope를 반환합니다.

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
| `usage` | 9 | CLI 인자가 잘못됨(알 수 없는 플래그/서브커맨드, 인자 누락/초과). 명령 실행 전에 감지. |
| `unknown` | 1 | 안정 카테고리에 매핑되지 않은 실패. |

`put --json`과 `get --json`은 성공 시 전송 요약을 반환합니다.

```json
{"ok":true,"server":"server-alpha","local":"./app","remote":"/tmp/app","bytes":1234}
```

단일 object를 반환하는 `--json` 성공 응답(`add`, `show`, `trust`, `run`, `put`, `get`, `remove`, `doctor`, `profile show`, `privilege set`, `privilege show`, `privilege clear`)은 모두 `"ok":true`를 포함해 오류 envelope의 `"ok":false`와 대칭을 이루므로, 소비자가 `ok`로 분기할 수 있습니다. `list`와 `profile list`는 성공 시 JSON 배열을 반환하며(래핑 object 없음), 실패 시에는 동일한 `{"ok":false,...}` envelope를 출력합니다.

`default`와 profile 상태 변경(`profile add`, `profile default`, `profile remove`)에는 `--json` 플래그가 없으며, 동일한 안정 exit code로 stderr에 사람용 메시지를 출력합니다. human 출력도 같은 exit code 매핑을 사용합니다.

잘못된 CLI 인자는 exit code `9`(`usage`)로 끝나며, `safety`(2)와 분리해 에이전트가 "sshw를 잘못 호출함"과 "safety rail이 차단함"을 구분할 수 있습니다. `--json`이면 usage 오류도 동일한 envelope로 stdout에 출력하고(`{"ok":false,"error":{"kind":"usage",...}}`), 아니면 파서 메시지를 stderr로 보냅니다. `--help`/`--version`은 stdout으로 출력하고 exit `0`입니다.

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
Chain dependent calls with &&, not ; (for example: sshw put ... && sleep 1 && sshw run ...).
If exit 5 mentions KEX/handshake during rapid repeated connections, wait briefly and retry from the failed step.
Example: Unable to exchange encryption keys.
Retry earlier successful steps only when they are idempotent and safe to repeat.
If it fails again, inspect network, server, and host trust state.
```

### 개발

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo run --locked -- --help
cargo run --locked -- doctor
```

로컬 머신 부담이 크면 저장소 전체 설정을 커밋하지 말고 호출별로 Cargo 병렬도를 제한하세요. 예: `CARGO_BUILD_JOBS=1 cargo test --locked`.

### 보안 제보

의심되는 취약점은 GitHub Security Advisories로 제보해 주세요. 공개 이슈에는 실제 hostname, IP, 비밀번호, 토큰, 개인키, 패스프레이즈를 남기지 마세요.

### 라이선스

MIT
