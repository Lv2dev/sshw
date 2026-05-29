# sshw

[![CI](https://github.com/Lv2dev/sshw/actions/workflows/ci.yml/badge.svg)](https://github.com/Lv2dev/sshw/actions/workflows/ci.yml)

Languages: [English](#english) | [한국어](#한국어)

---

## English

`sshw` is a cross-platform Rust CLI for operating known SSH servers without placing SSH passwords, private keys, passphrases, or tokens in prompts, shell history, or plaintext config files.

It is designed for local coding agents that need delegated server access for simple deployment and maintenance tasks.

### Security Boundary

`sshw` prevents accidental secret exposure in chat, command lines, shell history, JSON config, and normal command output.

It is delegated access, not a sandbox. If a local coding agent is allowed to run `sshw run`, that agent has the server authority exposed by the configured account. A fully privileged local process running as the same OS user may still try to access the operating system credential store directly.

`sshw` never stores passwords, private keys, passphrases, or tokens in its config file. Password auth stores the password only through the native OS credential store. Agent auth stores no secret and uses the user's active SSH agent.

### Install From Source

```bash
cargo build --locked --release
```

The binary will be at:

```text
target/release/sshw
target/release/sshw.exe
```

### Release Builds

Tagged releases build GitHub release artifacts for:

- `x86_64-unknown-linux-gnu`
- `x86_64-pc-windows-msvc`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

Each release also includes a `SHA256SUMS` file for artifact integrity checks. Release workflows pin GitHub Actions by commit SHA; review those SHAs when updating action major versions.

Create a release by pushing a version tag:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

### Config

`sshw` stores non-secret server metadata in the per-user config directory:

```text
Windows: C:\Users\<user>\AppData\Roaming\sshw\servers.json
macOS:   /Users/<user>/Library/Application Support/sshw/servers.json
Linux:   /home/<user>/.config/sshw/servers.json
```

The config contains server host, port, user, auth type, and credential key names only.

### Password Auth

```bash
sshw add server-alpha --host 192.0.2.10 --port 2222 --user deploy
```

Password auth is the default. `sshw` prompts for the password using hidden input and stores it in the native OS credential store under a key like `sshw:server-alpha`.

On Linux, password auth requires a working Secret Service provider such as GNOME Keyring or KWallet. Headless Linux systems often do not have one. `sshw doctor` reports this clearly; `sshw` does not fall back to plaintext password storage.

### SSH Agent Auth

```bash
sshw add server-beta --host 192.0.2.11 --port 2222 --user deploy --auth agent
```

Agent auth stores no secret in `sshw`. It relies on your active SSH agent and loaded identities.

### Host Trust Flow

Host key verification fails closed. Unknown or changed host keys are not silently accepted.

Trust a server deliberately:

```bash
sshw trust server-alpha
sshw trust server-alpha --yes
```

The trust command prints the host key algorithm and SHA256 fingerprint, asks for confirmation unless `--yes` is present, and writes the host key to the user's OpenSSH `known_hosts` file.

`sshw trust` verifies that the fingerprint shown for confirmation still matches immediately before writing to `known_hosts`. If the key changes during the trust flow, the command fails instead of storing the new key.

### Commands

```bash
sshw list
sshw list --json

sshw show server-alpha
sshw show server-alpha --json

sshw default
sshw default server-alpha

sshw run server-alpha "hostname && whoami && pwd"
sshw run server-alpha "pm2 status" --json
sshw run server-alpha "pm2 restart my-app" --yes
sshw run "hostname && whoami && pwd"

sshw put server-alpha ./app.exe /home/deploy/app/app.exe
sshw put ./app.exe /home/deploy/app/app.exe
sshw get server-alpha /home/deploy/app/log.txt ./log.txt
sshw get /home/deploy/app/log.txt ./log.txt
sshw get server-alpha /home/deploy/app/log.txt ./log.txt --yes

sshw remove server-alpha
sshw remove server-alpha --yes

sshw doctor
sshw doctor --json
```

Dangerous commands such as `rm -rf`, `sudo`, `chmod -R`, `chown -R`, `pm2 delete`, and obvious writes to `/etc` require `--yes`. These are safety rails, not a security sandbox.

`sshw get` will not overwrite an existing local file unless `--yes` is provided. `sshw put` creates remote files with owner-only permissions where the SSH server honors SCP modes.

Remote command stdout and stderr are remote data. `sshw` never prints stored secrets by itself, but it cannot prevent a remote command from printing sensitive file contents if the caller asks it to do so.

### JSON Error Contract

Commands with `--json` return a structured error envelope on runtime failures:

```json
{"ok":false,"error":{"kind":"config","message":"unknown server 'missing'","exit_code":3}}
```

Successful JSON output keeps the existing command-specific schema. The error envelope applies after CLI arguments have been parsed; clap usage errors are still handled by clap.

Stable error kinds and exit codes:

| Kind | Exit code | Meaning |
| --- | ---: | --- |
| `safety` | 2 | A safety rail blocked the operation, usually requiring `--yes`. |
| `config` | 3 | Configuration is missing, invalid, or references an unknown server. |
| `auth` | 4 | Credential lookup or authentication setup failed. |
| `ssh` | 5 | SSH connection, host key, known_hosts, or session setup failed. |
| `io` | 6 | Local file or filesystem handling failed. |
| `unknown` | 1 | The failure did not match a stable category. |

Human output keeps the existing plain stderr message, but uses the same stable exit code mapping.

### Coding Agent Usage

Use prompts like:

```text
Use only the local sshw CLI for server operations.
Do not ask for or print SSH passwords.
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

로컬 코딩 에이전트가 간단한 배포와 유지보수 작업을 위임받아 수행해야 할 때 쓰도록 설계했습니다.

### 보안 경계

`sshw`는 채팅, 명령줄, 셸 히스토리, JSON 설정 파일, 일반 명령 출력에서 비밀이 실수로 노출되는 일을 줄입니다.

이 도구는 위임된 접근 수단이지 샌드박스가 아닙니다. 로컬 코딩 에이전트에게 `sshw run` 실행 권한을 주면, 그 에이전트는 설정된 계정이 가진 서버 권한을 사용할 수 있습니다. 같은 OS 사용자 권한으로 실행되는 완전한 로컬 프로세스는 운영체제 credential store에 직접 접근을 시도할 수도 있습니다.

`sshw`는 비밀번호, 개인키, 패스프레이즈, 토큰을 설정 파일에 저장하지 않습니다. password auth는 비밀번호를 native OS credential store에만 저장합니다. agent auth는 비밀을 저장하지 않고 사용자의 활성 SSH agent를 사용합니다.

### 소스에서 설치

```bash
cargo build --locked --release
```

빌드된 바이너리는 아래 경로에 생성됩니다.

```text
target/release/sshw
target/release/sshw.exe
```

### 릴리스 빌드

태그 릴리스는 GitHub Release 산출물을 아래 플랫폼용으로 생성합니다.

- `x86_64-unknown-linux-gnu`
- `x86_64-pc-windows-msvc`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

각 릴리스에는 산출물 무결성 확인을 위한 `SHA256SUMS` 파일도 포함됩니다. 릴리스 워크플로우는 GitHub Actions를 commit SHA로 pin합니다. action major version을 올릴 때는 해당 SHA를 검토해야 합니다.

릴리스는 버전 태그를 push해서 생성합니다.

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

### 설정

`sshw`는 비밀이 아닌 서버 메타데이터를 사용자별 설정 디렉터리에 저장합니다.

```text
Windows: C:\Users\<user>\AppData\Roaming\sshw\servers.json
macOS:   /Users/<user>/Library/Application Support/sshw/servers.json
Linux:   /home/<user>/.config/sshw/servers.json
```

설정 파일에는 서버 host, port, user, auth type, credential key name만 들어갑니다.

### 비밀번호 인증

```bash
sshw add server-alpha --host 192.0.2.10 --port 2222 --user deploy
```

비밀번호 인증이 기본값입니다. `sshw`는 숨김 입력으로 비밀번호를 받고, `sshw:server-alpha` 같은 키로 native OS credential store에 저장합니다.

Linux에서 비밀번호 인증을 쓰려면 GNOME Keyring 또는 KWallet 같은 Secret Service provider가 동작해야 합니다. Headless Linux 환경에는 없는 경우가 많습니다. `sshw doctor`가 이 상태를 명확히 보고하며, `sshw`는 평문 비밀번호 저장으로 fallback하지 않습니다.

### SSH Agent 인증

```bash
sshw add server-beta --host 192.0.2.11 --port 2222 --user deploy --auth agent
```

Agent auth는 `sshw`에 비밀을 저장하지 않습니다. 사용자의 활성 SSH agent와 로드된 identity에 의존합니다.

### Host Trust Flow

Host key 검증은 fail-closed입니다. 알 수 없거나 변경된 host key는 조용히 허용하지 않습니다.

서버를 명시적으로 신뢰하려면 아래 명령을 사용합니다.

```bash
sshw trust server-alpha
sshw trust server-alpha --yes
```

trust 명령은 host key algorithm과 SHA256 fingerprint를 출력하고, `--yes`가 없으면 확인을 요청한 뒤 사용자의 OpenSSH `known_hosts` 파일에 host key를 기록합니다.

`sshw trust`는 확인 화면에 보여준 fingerprint가 `known_hosts`에 쓰기 직전에도 같은지 다시 검증합니다. trust 흐름 중 key가 바뀌면 새 key를 저장하지 않고 실패합니다.

### 명령

```bash
sshw list
sshw list --json

sshw show server-alpha
sshw show server-alpha --json

sshw default
sshw default server-alpha

sshw run server-alpha "hostname && whoami && pwd"
sshw run server-alpha "pm2 status" --json
sshw run server-alpha "pm2 restart my-app" --yes
sshw run "hostname && whoami && pwd"

sshw put server-alpha ./app.exe /home/deploy/app/app.exe
sshw put ./app.exe /home/deploy/app/app.exe
sshw get server-alpha /home/deploy/app/log.txt ./log.txt
sshw get /home/deploy/app/log.txt ./log.txt
sshw get server-alpha /home/deploy/app/log.txt ./log.txt --yes

sshw remove server-alpha
sshw remove server-alpha --yes

sshw doctor
sshw doctor --json
```

`rm -rf`, `sudo`, `chmod -R`, `chown -R`, `pm2 delete`, `/etc`에 대한 명백한 쓰기 같은 위험 명령은 `--yes`가 필요합니다. 이것은 safety rail이지 보안 샌드박스가 아닙니다.

`sshw get`은 `--yes`가 없으면 기존 로컬 파일을 덮어쓰지 않습니다. `sshw put`은 SSH 서버가 SCP mode를 존중하는 경우 owner-only 권한으로 원격 파일을 만듭니다.

원격 명령의 stdout과 stderr는 원격 데이터입니다. `sshw` 자체는 저장된 비밀을 출력하지 않지만, 호출자가 민감한 파일 내용을 출력하는 원격 명령을 실행하면 그 출력을 막을 수 없습니다.

### JSON 오류 계약

`--json`을 가진 명령은 런타임 실패 시 구조화된 error envelope를 반환합니다.

```json
{"ok":false,"error":{"kind":"config","message":"unknown server 'missing'","exit_code":3}}
```

성공 JSON 출력은 기존 명령별 스키마를 유지합니다. error envelope는 CLI 인자 파싱이 끝난 뒤의 실패 경로에 적용됩니다. clap usage error는 여전히 clap이 처리합니다.

안정 오류 종류와 exit code는 아래와 같습니다.

| Kind | Exit code | 의미 |
| --- | ---: | --- |
| `safety` | 2 | safety rail이 작업을 차단했습니다. 보통 `--yes`가 필요합니다. |
| `config` | 3 | 설정이 없거나 잘못됐거나 알 수 없는 서버를 참조합니다. |
| `auth` | 4 | credential 조회 또는 인증 준비에 실패했습니다. |
| `ssh` | 5 | SSH 연결, host key, known_hosts, session 준비에 실패했습니다. |
| `io` | 6 | 로컬 파일 또는 파일 시스템 처리에 실패했습니다. |
| `unknown` | 1 | 안정 카테고리에 매핑되지 않은 실패입니다. |

Human 출력은 기존처럼 stderr에 평문 메시지를 유지하지만, exit code는 같은 안정 매핑을 사용합니다.

### 코딩 에이전트 사용 예

아래와 같은 프롬프트를 사용할 수 있습니다.

```text
Use only the local sshw CLI for server operations.
Do not ask for or print SSH passwords.
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

의심되는 취약점은 GitHub Security Advisories를 통해 제보해 주세요. 공개 이슈에는 실제 hostname, IP 주소, 비밀번호, 토큰, 개인키, 패스프레이즈를 남기지 마세요.

### 라이선스

MIT
