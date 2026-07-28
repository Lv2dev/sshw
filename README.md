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

Tagged releases build GitHub release artifacts for `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`. Each release includes a `SHA256SUMS` file. Release workflows pin GitHub Actions by commit SHA and the release compiler to Rust 1.97.0. ZIP and tar.gz packaging uses deterministic archive metadata derived from the release commit timestamp, so the same binary and timestamp produce the same archive bytes. This is not a claim that separately compiled binaries are bit-for-bit reproducible; see `SECURITY.md`.

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

New credential keyring entries use a purpose-aware, generation-qualified v2 key so the same server name in different homes never collides and login credentials cannot be reused as privilege credentials:

```text
sshw:v2:<encoded-namespace>:login:<encoded-server>:<generation>
sshw:v2:<encoded-namespace>:privilege:<encoded-server>:<generation>
```

The namespace and server components are base64url-encoded. Each credential update receives a new generation. Legacy v1 keys (`sshw:<namespace>:<server>` and `sshw:<namespace>:privilege:<server>`) remain readable only when they exactly match the active namespace, purpose, and server; new writes never use v1.

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

Each profile stores a stable id and its home path. The first profile added becomes the default. `profile add --force` preserves the existing id when the normalized home is unchanged; moving the name to a different home creates a fresh namespace. The selection mechanism is part of the credential boundary: opening a profile-owned directory with `--home` does not reuse that profile's credentials. Removing a profile leaves its directory and native keyring entries physically intact, but removes the trusted namespace binding; re-adding a removed profile creates a fresh credential namespace and requires credentials to be registered again. Use `--force` instead of remove/re-add when updating the same profile and home.

Registries are validated strictly. If an older release stored a relative profile home, normal selection/list/show/default operations fail closed. `sshw doctor` reports `registry_valid: false` and an actionable `registry_message`; `sshw profile remove <affected-name>` is the only recovery exception and succeeds only when removing that exact entry leaves a fully valid registry. It never resolves or migrates the relative path against the current working directory.

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
- `session_only` — never touches the keyring. `set_password` stays in memory for the process only. At run time, login passwords come from `SSHW_PASSWORD` and privilege passwords come from `SSHW_PRIVILEGE_PASSWORD`; both variables are removed from this process environment after reading. Suited to ephemeral/CI use. Environment variables can still be visible before `sshw` starts or in the parent shell, so treat both as sensitive. `add --auth password` and `privilege set` warn that their passwords are not persisted.

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

`--timeout` sets an absolute timeout (seconds) for the remote operation phase of `run`/`put`/`get` after the connection is established; output or transfer progress does not extend it. Omitting the flag uses the 900-second default, while `0` explicitly disables the deadline. DNS resolution, all resolved-address attempts, TCP setup, and the SSH handshake share one 15-second connection deadline. `run` closes channel stdin even when no input was supplied and drains stdout and stderr concurrently. Exceeding the 16 MiB limit fails the operation with exit 5 instead of returning truncated output; the remote command may already have run, so do not blindly retry non-idempotent work.

When the name is omitted for `run`/`put`/`get`, the configured default server is used.

### Windows Shell Paths

Git Bash/MSYS automatically converts path-like arguments passed to native Windows executables. That conversion can rewrite a remote POSIX path such as `/tmp/artifact.tgz` into a local Windows path before `sshw` sees it, producing an SSH failure (exit 5). Disable argument conversion for the invocation and write the local path in Windows form:

```bash
MSYS2_ARG_CONV_EXCL='*' sshw put server-alpha \
  'C:/path/artifact.tgz' \
  '/tmp/artifact.tgz'
```

The same rule applies to `get`. In PowerShell, use a normal Windows local path and quote the remote path:

```powershell
sshw put server-alpha 'C:\path\artifact.tgz' '/tmp/artifact.tgz'
```

Windows accepts both `C:\path\file` and `C:/path/file` as local paths; backslashes are shown for the native PowerShell form. A missing or unreadable local file is an I/O failure (exit 6), while a converted remote path can surface later as an SSH failure (exit 5).

To transfer the tracked source tree, create the archive from Git instead of archiving the working directory or `target`:

```powershell
$archive = Join-Path $env:TEMP 'sshw-src.tgz'
git archive --format=tar.gz --output="$archive" HEAD
sshw put server-alpha "$archive" '/tmp/sshw-src.tgz'
```

`git archive` includes only files tracked in the selected commit, so it excludes `.git`, `target`, untracked files, and uncommitted changes. This also avoids depending on whether the shell resolves `tar` to Windows bsdtar, Git's GNU tar, or a WSL executable.

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

Policy fails closed: with `--policy`, a missing policy file is an error, and a present-but-invalid file is always an error. An inactive policy file (`"enabled": false`) is still rejected when it has an unknown field or unsupported version; rename or remove an intentionally unused invalid file before running remote operations.

See the Security Boundary note: `allow_commands` delegates whole-program execution. It does not restrict arguments, file paths, or subprocess behavior inside the allowed program. `allow_put_paths`/`allow_get_paths` match remote paths by lexical prefix and reject `..`, but they do not resolve remote symlinks or canonicalize paths, so a symlink under an allowed prefix can still point elsewhere on the host — the path allowlist is a guardrail, not a remote sandbox.

### Audit Log

Mutating/active operations (`add`, `remove`, `trust`, `default`, `profile add`, `profile default`, `profile remove`, `run`, `put`, `get`, `privilege set`, `privilege clear`) are appended to `audit.jsonl`, one JSON object per line. Home-scoped operations use the active home's log; global profile-registry mutations consistently use the built-in default home's log regardless of the profile being added, selected, or removed:

```json
{"time_ms":1700000000000,"action":"run","server":"web","status":"ok","exit_code":0,"detail":"uptime"}
```

`detail` for `run` is only the program name (not its arguments). Server names, paths, and details are redacted on a best-effort basis. Attempted `run`/`put`/`get` operations, including policy setup failures, are recorded with an error status. Read-only commands (`list`, `show`, `doctor`, `profile list`, `profile show`) are not audited. Audit writes are best-effort: a busy record lock is retried for 100 milliseconds and then that record is skipped without failing the operation. The file is owner-only on Unix (best-effort on Windows). The log is append-only but not tamper-evident — it has no integrity chain or signing, and anyone who can write the home can edit or delete entries. Treat `audit.jsonl` as sensitive.

### Output Redaction

`run` stdout, stderr, and the echoed JSON command are passed through best-effort redaction that masks PEM private-key blocks, `keyword=value`/`keyword: value` assignments for common secret keywords, and bearer tokens. When loaded for an operation, the exact login password and configured privilege password are also redacted wherever they appear in those fields. Very short or common exact passwords can therefore over-redact unrelated output; secrecy takes priority over output fidelity. This does not understand every shell representation, and secrets split across lines may not be masked. Do not pass secrets inline.

### Doctor

```bash
sshw doctor
sshw doctor --json
```

`doctor` reports the resolved home and how it was selected, the registry / config / known_hosts / policy / audit paths, registry validity and diagnostics (`registry_valid`, `registry_message`), whether the config file exists, the operating system, the linked libssh2 and OpenSSL version/status, the credential namespace, whether policy is present/valid/enabled, whether the audit log is writable, the credential backend health, and any configured servers whose credentials are missing (`missing_credentials`). A corrupt registry does not prevent `doctor` from running; it diagnoses the registry from the built-in default home unless an explicit home already resolves. On Windows default builds, `openssl_version` may report `not linked (Windows WinCNG backend)` because libssh2 uses WinCNG instead of OpenSSL.

### JSON Error Contract

Commands that support `--json` (`add`, `list`, `show`, `trust`, `run`, `put`, `get`, `remove`, `doctor`, `profile list`, `profile show`, `privilege set`, `privilege show`, `privilege clear`) return a structured error envelope on runtime failures:

```json
{"ok":false,"error":{"kind":"config","message":"unknown server 'missing'","exit_code":3}}
```

When wrapped source errors exist, `error` includes an optional `causes` array containing the full redacted cause chain, ordered from the immediate cause outward. The field is omitted when there are no additional causes. Consumers should treat it as diagnostic text rather than a stable machine-readable taxonomy.

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

New `servers.json`, `policy.json`, `audit.jsonl`, profile registry, and mutation lock files are created owner-only on platforms that support it. Config and registry writes finalize permissions and sync the temporary file before atomic rename, then sync the parent directory where supported. If the rename succeeds but parent sync fails, sshw reports that the state was published but durability was not confirmed; credential updates retain both generations instead of deleting a key that either the old or new config may need after a crash. On Windows, permissions and directory sync are best-effort (NTFS ACLs on the per-user directory provide the protection).

Cooperating `sshw` processes serialize home mutations with `.sshw.lock`, profile registry mutations with `.profiles.lock`, and complete audit records by locking `audit.jsonl`. A state-mutation lock waits at most 5 seconds before returning an actionable config error; audit uses the shorter best-effort bound above. Config and registry writes also reject a stale loaded revision. These locks are advisory: another program or same-user process that ignores them can still race or edit the files, so this is coordination rather than tamper protection.

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

See `CONTRIBUTING.md` for dependency-audit commands, integration-test expectations, and safe issue/PR data handling.

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

태그 릴리스는 `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`, `x86_64-apple-darwin`, `aarch64-apple-darwin`용 GitHub Release 산출물과 `SHA256SUMS`를 생성합니다. 릴리스 워크플로우는 GitHub Actions를 commit SHA로, 릴리스 컴파일러를 Rust 1.97.0으로 pin합니다. ZIP과 tar.gz는 릴리스 commit timestamp에서 가져온 결정적 metadata로 패키징하므로 같은 바이너리와 timestamp는 같은 archive bytes를 만듭니다. 별도로 컴파일한 바이너리까지 bit-for-bit 재현된다는 보장은 아니며 자세한 내용은 `SECURITY.md`를 참고하세요.

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

신규 credential keyring 키는 purpose와 generation을 포함한 v2 형식을 사용합니다. 따라서 서로 다른 home의 같은 서버 이름이 충돌하지 않고 login credential을 privilege credential로 재사용할 수도 없습니다.

```text
sshw:v2:<encoded-namespace>:login:<encoded-server>:<generation>
sshw:v2:<encoded-namespace>:privilege:<encoded-server>:<generation>
```

namespace와 server는 base64url로 인코딩하며 credential을 갱신할 때마다 새 generation을 발급합니다. legacy v1 키(`sshw:<namespace>:<server>`, `sshw:<namespace>:privilege:<server>`)는 active namespace, purpose, server가 정확히 일치할 때만 읽기 호환을 유지하며 신규 저장에는 사용하지 않습니다.

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

각 profile은 stable id와 home 경로를 저장합니다. 처음 추가한 profile이 default가 됩니다. 정규화된 home이 같으면 `profile add --force`는 기존 id를 보존하고, 다른 home으로 바꾸면 새 namespace를 만듭니다. profile 선택 방식 자체가 credential 경계이므로 profile 소유 디렉터리를 `--home`으로 열어도 그 profile credential을 재사용하지 않습니다. profile을 제거하면 디렉터리와 native keyring 항목은 물리적으로 남지만 신뢰된 namespace 연결은 사라집니다. 제거한 profile을 다시 추가하면 새 credential namespace가 만들어지므로 credential을 다시 등록해야 합니다. 같은 profile/home 갱신에는 remove/re-add 대신 `--force`를 사용하세요.

registry는 엄격하게 검증합니다. 이전 릴리스가 상대경로 profile home을 저장한 경우 일반 선택/list/show/default 작업은 fail-closed합니다. `sshw doctor`는 `registry_valid: false`와 조치 가능한 `registry_message`를 보고합니다. 유일한 복구 예외인 `sshw profile remove <문제-profile>`은 그 항목을 제거한 뒤 나머지 registry가 완전히 유효할 때만 성공하며, 상대경로를 현재 작업 디렉터리 기준으로 해석하거나 자동 이동하지 않습니다.

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
- `session_only` — keyring을 쓰지 않습니다. `set_password`는 프로세스 메모리에만 유지됩니다. 실행 시 login 비밀번호는 `SSHW_PASSWORD`, privilege 비밀번호는 `SSHW_PRIVILEGE_PASSWORD`에서 가져오며, 읽은 두 환경변수는 이 프로세스 환경에서 제거합니다. ephemeral/CI에 적합합니다. 환경변수는 `sshw` 시작 전이나 부모 셸에는 노출될 수 있으므로 둘 다 민감하게 취급하세요. `add --auth password`와 `privilege set`은 비밀번호가 영속되지 않는다고 경고합니다.

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

`--timeout`은 연결 수립 이후 `run`/`put`/`get`의 원격 작업 단계에 적용되는 절대 타임아웃(초)이며, 출력이나 전송 진행이 있어도 기한이 연장되지 않습니다. 플래그를 생략하면 기본 900초, `0`은 기한을 명시적으로 해제합니다. DNS 해석, 해석된 모든 주소에 대한 연결 시도, TCP 수립, SSH handshake는 하나의 15초 연결 deadline을 공유합니다. `run`은 입력이 없어도 채널 stdin을 닫고 stdout/stderr를 동시에 배출합니다. 두 출력 합계가 16 MiB를 넘으면 잘린 성공 출력을 반환하지 않고 exit 5로 실패합니다. 원격 명령의 부작용은 이미 발생했을 수 있으므로 비멱등 작업을 무작정 재시도하지 마세요.

`run`/`put`/`get`에서 이름을 생략하면 설정된 기본 서버를 사용합니다.

### Windows 셸 경로

Git Bash/MSYS는 Windows 네이티브 실행 파일에 전달하는 경로 형태의 인자를 자동 변환합니다. 이 과정에서 `/tmp/artifact.tgz` 같은 원격 POSIX 경로가 `sshw`에 도달하기 전에 로컬 Windows 경로로 바뀌어 SSH 실패(exit 5)가 발생할 수 있습니다. 호출 단위로 인자 변환을 끄고 로컬 경로를 Windows 형식으로 작성하세요.

```bash
MSYS2_ARG_CONV_EXCL='*' sshw put server-alpha \
  'C:/path/artifact.tgz' \
  '/tmp/artifact.tgz'
```

`get`에도 같은 규칙이 적용됩니다. PowerShell에서는 일반 Windows 로컬 경로를 사용하고 원격 경로를 따옴표로 감쌉니다.

```powershell
sshw put server-alpha 'C:\path\artifact.tgz' '/tmp/artifact.tgz'
```

Windows는 로컬 경로로 `C:\path\file`과 `C:/path/file`을 모두 허용합니다. 위 예시는 PowerShell의 네이티브 표기인 역슬래시를 사용했습니다. 로컬 파일이 없거나 읽을 수 없으면 I/O 실패(exit 6)이고, 변환된 원격 경로는 이후 SSH 실패(exit 5)로 나타날 수 있습니다.

추적 중인 소스 트리를 전송할 때는 작업 디렉터리나 `target`을 직접 압축하지 말고 Git에서 아카이브를 생성하세요.

```powershell
$archive = Join-Path $env:TEMP 'sshw-src.tgz'
git archive --format=tar.gz --output="$archive" HEAD
sshw put server-alpha "$archive" '/tmp/sshw-src.tgz'
```

`git archive`는 선택한 커밋에서 Git이 추적하는 파일만 포함하므로 `.git`, `target`, 미추적 파일, 커밋하지 않은 변경 사항은 제외됩니다. 셸이 `tar`를 Windows bsdtar, Git의 GNU tar, WSL 실행 파일 중 무엇으로 해석하는지에도 의존하지 않습니다.

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

policy는 fail-closed입니다. `--policy`인데 파일이 없으면 에러이고, 파일이 있으나 유효하지 않으면 항상 에러입니다. `"enabled": false`인 비활성 policy도 unknown field나 지원하지 않는 version이 있으면 거부됩니다. 의도적으로 사용하지 않는 잘못된 파일은 원격 작업 전에 이름을 바꾸거나 제거하세요.

보안 경계 참고: `allow_commands`는 프로그램 실행권 전체를 위임합니다. 허용된 프로그램 내부의 인자, 파일 경로, 하위 프로세스 동작은 제한하지 않습니다. `allow_put_paths`/`allow_get_paths`는 원격 경로를 lexical prefix로 매칭하고 `..`를 거부하지만, 원격 symlink를 따라가거나 canonical 경로로 검증하지는 않습니다. 허용된 prefix 아래의 symlink가 호스트의 다른 위치를 가리킬 수 있으므로 path allowlist는 원격 sandbox가 아니라 guardrail입니다.

### Audit Log

변경/실행 작업(`add`, `remove`, `trust`, `default`, `profile add`, `profile default`, `profile remove`, `run`, `put`, `get`, `privilege set`, `privilege clear`)은 `audit.jsonl`에 줄당 JSON 객체로 append됩니다. home 범위 작업은 active home의 로그를 사용하고, 전역 profile registry 변경은 추가·선택·제거 대상과 무관하게 내장 default home의 로그에 일관되게 기록됩니다.

```json
{"time_ms":1700000000000,"action":"run","server":"web","status":"ok","exit_code":0,"detail":"uptime"}
```

`run`의 `detail`은 인자가 아닌 프로그램 이름만 기록합니다. 서버명·경로·detail은 best-effort로 redaction됩니다. 시도한 `run`/`put`/`get`의 policy 준비가 실패한 경우도 error 상태로 기록합니다. read-only 명령(`list`, `show`, `doctor`, `profile list`, `profile show`)은 기록하지 않습니다. audit 쓰기는 best-effort입니다. record lock이 바쁘면 100밀리초 동안 재시도한 뒤 해당 레코드를 생략하며 작업 자체는 실패시키지 않습니다. 파일은 Unix에서 owner-only(Windows는 best-effort)입니다. append-only이지만 tamper-evident가 아닙니다 — 무결성 체인이나 서명이 없고, home을 쓸 수 있는 누구나 항목을 수정·삭제할 수 있습니다. `audit.jsonl`은 민감 파일로 취급하세요.

### 출력 redaction

`run`의 stdout/stderr/JSON에 echo된 command는 best-effort redaction을 거칩니다. PEM 개인키 블록, 흔한 비밀 keyword의 `keyword=value`/`keyword: value`, bearer 토큰을 마스킹합니다. 작업을 위해 읽은 정확한 login 비밀번호와 설정된 privilege 비밀번호가 이 필드에 그대로 나타나면 추가로 마스킹합니다. 매우 짧거나 흔한 비밀번호는 관련 없는 출력까지 과도하게 마스킹할 수 있으며, 이 경우 출력 충실도보다 비밀 보호를 우선합니다. 모든 쉘 표현을 이해하지는 못하고 여러 줄에 걸친 비밀은 마스킹되지 않을 수 있으므로 비밀을 인라인으로 넘기지 마세요.

### Doctor

```bash
sshw doctor
sshw doctor --json
```

`doctor`는 해석된 home과 선택 경위, registry/config/known_hosts/policy/audit 경로, registry 유효성과 진단(`registry_valid`, `registry_message`), config 파일 존재 여부, 운영체제, 연결된 libssh2 및 OpenSSL 버전/상태, credential namespace, policy present/valid/enabled, audit 쓰기 가능 여부, credential backend 상태, 그리고 credential이 없는 등록 서버 목록(`missing_credentials`)을 보고합니다. 손상된 registry도 `doctor` 실행을 막지 않으며, 명시적 home이 이미 해석되지 않았다면 내장 default home에서 registry 오류를 진단합니다. Windows 기본 빌드에서는 libssh2가 OpenSSL 대신 WinCNG를 사용하므로 `openssl_version`이 `not linked (Windows WinCNG backend)`로 표시될 수 있습니다.

### JSON 오류 계약

`--json`을 지원하는 명령(`add`, `list`, `show`, `trust`, `run`, `put`, `get`, `remove`, `doctor`, `profile list`, `profile show`, `privilege set`, `privilege show`, `privilege clear`)은 런타임 실패 시 구조화된 envelope를 반환합니다.

```json
{"ok":false,"error":{"kind":"config","message":"unknown server 'missing'","exit_code":3}}
```

래핑된 source error가 있으면 `error`에 immediate cause부터 바깥쪽 순서로 전체 redacted cause chain을 담은 선택적 `causes` 배열이 추가됩니다. 추가 cause가 없으면 이 필드는 생략됩니다. 이 값은 안정된 기계 판독 taxonomy가 아니라 진단용 문자열로 취급하세요.

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

새로 만드는 `servers.json`, `policy.json`, `audit.jsonl`, profile registry, mutation lock 파일은 지원 플랫폼에서 owner-only로 생성됩니다. config·registry 저장은 temp 파일의 권한과 sync를 먼저 완료하고 atomic rename한 뒤, 지원 플랫폼에서 parent directory를 sync합니다. rename 성공 뒤 parent sync가 실패하면 state는 공개됐지만 내구성을 확인하지 못했다고 오류를 반환하며, credential 갱신은 crash 뒤 old/new config 어느 쪽에도 대응하도록 두 세대를 보존합니다. Windows에서는 권한과 directory sync가 best-effort입니다.

서로 협력하는 `sshw` 프로세스는 home 변경을 `.sshw.lock`, profile registry 변경을 `.profiles.lock`으로 직렬화하고, 완전한 audit 레코드는 `audit.jsonl` 자체를 잠가 기록합니다. state mutation lock은 최대 5초만 기다린 뒤 config 오류를 반환하며, audit은 위의 더 짧은 best-effort 상한을 사용합니다. config와 registry 저장은 처음 읽은 revision이 바뀌었으면 거부합니다. 잠금은 advisory이므로 이를 무시하는 다른 프로그램이나 동일 사용자 프로세스의 경쟁·사후 편집까지 막는 변조 방지는 아닙니다.

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

dependency audit 명령, integration test 기대사항, 이슈/PR에서의 안전한 데이터 취급은 `CONTRIBUTING.md`를 참고하세요.

### 보안 제보

의심되는 취약점은 GitHub Security Advisories로 제보해 주세요. 공개 이슈에는 실제 hostname, IP, 비밀번호, 토큰, 개인키, 패스프레이즈를 남기지 마세요.

### 라이선스

MIT
