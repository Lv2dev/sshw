# sshw

[![CI](https://github.com/Lv2dev/sshw/actions/workflows/ci.yml/badge.svg)](https://github.com/Lv2dev/sshw/actions/workflows/ci.yml)

[English](#sshw) | [한국어](#한국어)

`sshw` connects to SSH servers to run commands and transfer files.

Register a server with a name such as `web`, then use that name instead of typing its address each time. Passwords go in your operating system's password store. You can use sshw yourself or give a local coding agent access to the same commands.

- Run commands and read the results. Get JSON results or watch output while a command runs.
- Upload and download files. Replace a file in one step after its upload finishes.
- Register several login accounts for a server and use sudo or su when needed.
- Keep separate settings for projects, choose which commands and paths to allow, and record activity.

**Read before use.** The libraries used for SSH communication have [known security issues](SECURITY.md#native-ssh-의존성의-알려진-보안-제한-0130). sshw helps keep passwords out of places where they could be exposed by accident. An agent still works with the permissions of the account it logs into. Read the [security notes](#security-notes) before giving it server access.

[Install](#install) · [First connection](#first-connection) · [Everyday commands](#everyday-commands) · [Accounts and sudo](#accounts-and-sudo) · [Project settings](#project-settings) · [Coding agents](#coding-agents) · [Troubleshooting](#troubleshooting)

## Install

### Download an executable

No Rust toolchain is needed. Open [GitHub Releases](https://github.com/Lv2dev/sshw/releases/latest) and download the archive for your system:

| System | Archive |
| --- | --- |
| Windows x64 | `sshw-x86_64-pc-windows-msvc.zip` |
| Linux x64 (GNU/glibc) | `sshw-x86_64-unknown-linux-gnu.tar.gz` |
| macOS, Apple Silicon | `sshw-aarch64-apple-darwin.tar.gz` |
| macOS, Intel | `sshw-x86_64-apple-darwin.tar.gz` |

Extract the archive and add the executable to `PATH`, the list of folders your terminal searches for commands:

- **Windows:** put `sshw.exe` in a folder such as `C:\Tools\sshw`. Open **Edit environment variables for your account** and add that folder to the user `Path` variable. Then open a new terminal.
- **Linux/macOS:** run these commands from the extracted folder. They copy sshw into `~/.local/bin` and add that folder to this terminal's `PATH`.

  ```sh
  mkdir -p "$HOME/.local/bin"
  cp ./sshw "$HOME/.local/bin/sshw"
  export PATH="$HOME/.local/bin:$PATH"
  ```

  Add the last export line to your shell's startup file to keep it in new terminals. You can skip that step if `~/.local/bin` is already on your `PATH`.

Check that the following command prints the version:

```sh
sshw --version
```

You can try it before setting up `PATH`. From the extracted folder, run `./sshw --version` on Linux/macOS or `.\sshw.exe --version` in PowerShell.

See [download verification](docs/reference.md#release-verification) to check that a file matches the published copy and to verify where it was built.

### Install with Cargo

The crates.io package is named `sshw-agent`; the executable is `sshw`. Install Rust 1.89 or newer and the native build prerequisites below, then run:

```sh
cargo install sshw-agent --locked
sshw --version
```

| System | Cargo build prerequisites |
| --- | --- |
| Windows | Rust MSVC toolchain and Visual C++ Build Tools/Windows SDK |
| Linux | C toolchain, `pkg-config`, OpenSSL libraries and headers |
| macOS | Xcode Command Line Tools and a discoverable OpenSSL installation |

Run the same Cargo command to upgrade.

On Linux, storing passwords requires a running Secret Service provider such as GNOME Keyring or KWallet. You can use an SSH Agent when logging in with a key.

To build from source, run `cargo build --locked --release` in the repository. The executable is created in `target/release`.

## First connection

Have your server address and SSH login account ready. The server and account must already exist. Run these setup steps yourself in a terminal before giving a coding agent access.

### 1. Register your server

`web` is the name you will use for this server. You can choose another name. Replace `192.0.2.10` with your server address and `deploy` with your login user:

```sh
sshw add web --host 192.0.2.10 --user deploy
```

Enter the **SSH login password** when asked. The characters will not appear on screen. sshw stores the password in your operating system's password store, not in its settings file.

Registration does not test whether you can log in. You will check the connection in the next steps. If your server uses a port other than 22, add its port number, for example `--port 2222`.

The printed `next`/`then` commands keep the settings home, profile or project you selected. Use those commands when registering with `--home`, `--profile`, `--project-dir` or `SSHW_HOME`; registration with `--global` keeps that selection too. Host approval and command execution still require you to run the next steps yourself.

To change an existing server's address while keeping its accounts, use `sshw endpoint web --host 192.0.2.20`. If `add` detects an address change, it prints an `endpoint` command for the same settings selection. `add --replace` is for a full replacement that resets accounts and privilege settings.

To log in with an SSH key, use the command below instead. Your SSH Agent must already have the key loaded, and the server must accept it for `deploy`:

```sh
sshw add web --host 192.0.2.10 --user deploy --auth agent
```

This uses your running SSH Agent. sshw does not load a private-key file itself or store a password for this account.

If you get passwords from a secret manager, see [password input options](docs/reference.md#password-auth).

### 2. Verify the server's identity

```sh
sshw trust web
```

This step checks that you are connecting to the intended server. Compare the fingerprint on screen with one from your server administrator or another trusted source. Approve it only when they match.

The approval question shows the actual address/port, selected server settings and the config/known_hosts paths. Check these too when several projects use the same server nickname.

sshw saves the approved key. If the server's key changes later, it refuses the connection.

### 3. Run a harmless command

```sh
sshw run web "hostname"
sshw run web "whoami"
```

The first command prints the server's hostname. The second prints your login user. If both work, you are ready to use the server.

Keep the **whole command you want to run on the server inside quotes**. If you get an error, follow the message or check [troubleshooting](#troubleshooting).

## Everyday commands

Use `sshw endpoint web --host 192.0.2.20 --port 10022` to change only the saved address and port while preserving all accounts, passwords and privilege settings. Confirm the displayed change, or pass `--yes`. The destination still needs normal host-key verification; existing approvals are not copied to it.

Use `sshw doctor web --user ops` to diagnose one registered login and its privilege credentials. Download with `sshw get web /var/log/app.log --into .` to keep the remote filename inside a local directory; an existing file still requires `--yes` to overwrite.

Doctor and server/account lookup recovery commands retain the selected home/profile/project. If a repair would change inherited server settings, the message explicitly identifies the global action. Copying guidance does not approve a host or change credentials by itself.

`doctor` and `list` give the same registration guidance for an empty server list. `run`, `put`, `get`, and `test` identify the selected settings and server in the approval command when a host key is missing. For a changed key, verify the new fingerprint with the server administrator before updating the reported `known_hosts` file.

When removing a default server, use `sshw remove web --switch-default staging` to choose its replacement, or `--clear-default` to require explicit server names afterward. The same options work with `sshw profile remove prod`; clearing a profile default returns to the built-in home when no explicit selector is given. Hidden password prompts identify the server, login account and, for privilege passwords, the sudo/su method and target.

Rename a profile with `sshw profile rename old new` while keeping saved passwords. To replace a default login and remove its old sshw registration together, use `sshw account remove web old-user --switch-default deploy`; server OS accounts and files stay intact.

Use `sshw test web --user ops` to verify host approval and login without running a remote command. A policy denial now includes a suggested `policy allow` command and its scope; review it before applying the grant.

Add `--progress` to `put/get` to see transferred bytes, percentage and speed. To require a server name each time, clear the default with `sshw default --clear`. `sshw profile default --clear` returns to the built-in home when no explicit selector is given. Registered settings stay available.

These examples use the server name `web`. The commands that run on the server assume Linux/Unix. On another system, choose commands that work in the server's shell.

| Task | Command |
| --- | --- |
| List registered servers | `sshw list` |
| Inspect a server | `sshw show web` |
| Rename a server | `sshw rename web production` |
| Find servers by name or host | `sshw list --filter prod` |
| Update a saved login password | `sshw password web` |
| Update a saved sudo/su password | `sshw password web --privilege` |
| Run a command | `sshw run web "uptime"` |
| Follow output as it arrives | `sshw run web "journalctl -n 20" --stream` |
| Upload a file | `sshw put web ./report.txt /tmp/report.txt` |
| Download a file | `sshw get web /tmp/report.txt ./downloaded-report.txt` |
| Upload an executable | `sshw put web ./app /srv/app/app --mode 755` |
| Replace a file after the upload completes | `sshw put web ./app /srv/app/app --atomic --mode 755` |

`rename` keeps the server's accounts, passwords, privilege settings and host approval. Its default selection and account policy rules follow the new name. The destination must be unused; an identical name makes no changes. Use the same `--home` or `--profile` you used when registering the server.

`list --filter` matches a literal substring of the name or host, ignoring case. To save a new login password after changing it on the server, use `password web`; add `--user ops` to choose another registered password account. It asks only for the new password with hidden input and preserves your other settings. SSH-agent accounts keep using the agent; change their authentication method explicitly with `account add` if needed.

For PowerShell Tab completion, run this once in the current session, or add the line to your PowerShell profile:

```powershell
sshw completions powershell | Out-String | Invoke-Expression
```

Tab suggests commands, options and registered server/account/profile names from the selected home. The script does not edit your profile or connect to a server. See the [completion reference](docs/reference.md#powershell-completion) for quoting and shell limitations.

`show web` displays every registered account, marks the default login with `*`, and includes each account's authentication and sudo/su target. To update only a saved privilege password, use `password web --privilege`; `--user ops` selects the login account whose privilege settings you want to keep. The saved method and target stay unchanged. Passwordless sudo stays passwordless; change that setting explicitly with `privilege set` when needed.

For `put`, give **the file on your PC, then its destination on the server**. For `get`, give **the file on the server, then its destination on your PC**.

Add `--yes` to overwrite an existing file when downloading. Ordinary uploads can overwrite files on the server, so check the path first. To upload to `/srv/app`, your login account needs write permission there. `--yes` cannot grant that permission.

`--atomic` uploads the new file before replacing the old one. The server must support the OpenSSH POSIX rename extension, and your account needs write permission on the destination folder. The old file's ownership and access control list (ACL) are not kept. See [transfer details](docs/reference.md#safer-transfers-and-live-output) for what happens if an error interrupts the transfer.

`--stream` shows output as each line completes. It cannot be combined with `--json` or su execution.

**Windows Git Bash** can convert server paths such as `/tmp/report.txt` into Windows paths. Add `remote:` before the server's absolute path to prevent this:

```sh
sshw put web 'C:/work/report.txt' 'remote:/tmp/report.txt'
```

In PowerShell, a plain remote path works: `sshw put web 'C:\work\report.txt' '/tmp/report.txt'`. See [Windows paths](docs/reference.md#windows-shell-paths).

## Accounts and sudo

### Add another login account

To log in as `ops`, register that account first. Enter its SSH password for the first command, then check the login user with the second:

```sh
sshw account add web ops
sshw run web "whoami" --user ops
```

Add `--auth agent` when registering an account that uses an SSH key. `--user` accepts only accounts you have registered.

Run `sshw account default web ops` to use `ops` by default from now on.

### Run a command through sudo

If the server already permits passwordless sudo for the selected account:

```sh
sshw run web "id -u" --as-root --no-password
```

If sudo requires a password, register the **sudo password** first, then run:

```sh
sshw privilege set web --method sudo
sshw run web "id -u" --as-root
```

Register the login password and sudo password separately, even if they are the same. The server's sudoers settings decide whether sudo is allowed.

To configure sudo for another login account, add `--account ops` to `privilege set`. Use `--user ops` when running the command. Dangerous operations such as deletion may also require `--yes`.

See [privilege settings](docs/reference.md#privileged-commands) for saved passwordless sudo, other target users and su.

## Project settings

You can start with the default settings. Run `sshw doctor` to see where they are stored.

Run this in the project folder to use global servers with project permissions:

```sh
sshw project init
sshw project status
sshw policy allow command hostname
sshw policy enable
sshw run web "hostname"
```

The current folder's `.sshw` is selected automatically. Server lists and permissions are selected independently: a local file takes precedence; a missing file or an explicit global selection uses global settings. Parent folders are not searched. `project init` copies the current global policy as the starting point and preserves its enabled state; it does not copy passwords.

`project init` and `project status` show the saved policy setting and whether enforcement is on, off or blocked. A disabled local policy includes an enable command for that exact project; review the allowlist before running it. `--policy` forces enforcement only for that invocation and does not change the saved setting. Initialization and recovery commands retain the selected project directory when run from another folder.

When both selected resources are local and the local policy already exists, `project init` works without reading unused global profiles. Creating a missing local policy still requires its global starting point; an invalid required global setting fails without replacing it with a disabled policy.

To keep a separate server list too, run `sshw project init --servers-source local`. It starts empty, and only that local list is searched. Register accounts with `sshw add` and approve their host keys with `sshw trust`.

If the inherited global list is empty, `sshw list` offers two choices: register globally with `--global`, or initialize a local server list and register there. Replace the host/login-user placeholders in the displayed command; neither choice runs automatically.

Inherited settings are read-only in project mode. Use `sshw --global add ...` for an intentional global edit, or initialize the local resource first. `--home`, `--profile` and `SSHW_HOME` bypass automatic project selection. Use `sshw --global list` to inspect global servers or `sshw --project-dir <folder> list` to select a project from another folder. See [project settings](docs/reference.md#current-directory-project-settings) for file formats and source choices.

You can also register a folder under a name and select it with `--profile prod`. Named profiles and `--home` do not share passwords, even for the same folder. Keep using the method you chose during setup. See [profile setup](docs/reference.md#managing-profiles).

## Coding agents

After you register and trust the server, give the agent the server nickname and intended task. For example:

```text
Use sshw for the registered server web.
First run sshw run web "hostname && whoami && pwd" --json.
Use sshw put/get for file transfer. Do not request or print credentials.
Show the commands and get my approval before destructive changes or service restarts.
Chain dependent steps with && and stop if a step fails.
```

Use `--json` when the agent needs to read the result. A `run` succeeds when `command_succeeded` is `true` or `exit_status` is `0`. `ok:true` means the command finished; it does not tell you whether it succeeded. sshw returns exit code `8` when the command on the server finishes with a failure.

See [JSON and exit codes](docs/reference.md#json-error-contract) for other commands and errors during a task. The agent also needs access to the password store or SSH Agent you used during setup.

## Troubleshooting

If you get an error, try `sshw doctor`. It checks settings and passwords on your PC and suggests what to do next. It does not try connecting to the server.

Use `sshw doctor web` to focus the server checks on `web`. Home-wide problems, such as an invalid policy or unavailable credential backend, are still reported. Removing a server or login account also clears its matching account allowlist entries, so a later registration does not inherit those old entries.

If the failing command used `--home` or `--profile`, use the same option for doctor.

| Problem | First step |
| --- | --- |
| `sshw` is not found | Check `PATH`, or run the extracted executable by its full path. |
| Server or account is unknown | Run `sshw list` or `sshw account list web` in the same settings location. |
| Host key is unknown | Use `sshw trust web` and verify the fingerprint independently. |
| Host key changed | Confirm the change with the administrator before updating trust. |
| Password or SSH key login failed | Run `sshw doctor` and check the account, password or key. Check that the server allows that login method. |
| An operation needs confirmation | Review it first; use `--yes` for an approved operation or `--force` for an approved registration update. |
| A policy blocked the command | Use `sshw policy check web "uptime"` to inspect the rule. |
| A run timed out or completion is uncertain | Check the remote state before retrying; it may already have made changes. |

Run `sshw --help` to see all commands. For upload options, use `sshw put --help`. You can check other commands the same way. See [diagnostics and recovery](docs/reference.md#doctor) for other errors.

## Security notes

- Passwords go in Windows Credential Manager, macOS Keychain or Linux Secret Service. sshw stores no private key when using an SSH Agent. Keep passwords and tokens out of command arguments, agent conversations and plaintext settings.
- An agent works with the permissions of its SSH login account. Saving sudo settings does not change ordinary commands. Add `--as-root` to run through sudo or su.
- Command and path policies are off by default. These rules and `--yes` checks cannot fully isolate the server. Allowing a whole program can allow its other capabilities too. Path rules do not check where remote symlinks point.
- sshw masks secrets in output and records activity, but it cannot guarantee that it catches every secret or records every operation. It cannot detect edits to the log. Another process with sufficient permissions under the same local OS user may access the password store.
- An error or timeout can happen after some work has run on the server. Check the server state before repeating anything that is unsafe to run twice.

Read [SECURITY.md](SECURITY.md) for the limits of these protections and the known issues in the SSH libraries.

## More documentation

- [Detailed reference](docs/reference.md): all commands, authentication, profiles, policies, JSON, timeouts and storage behavior.
- [Changes and Rust API migration](CHANGELOG.md).
- [Contributing and release procedure](https://github.com/Lv2dev/sshw/blob/master/CONTRIBUTING.md).

Report suspected vulnerabilities privately through GitHub Security Advisories as described in [SECURITY.md](SECURITY.md). Use synthetic values in public issues; do not include credentials or private infrastructure details.

## License

MIT. See [LICENSE](LICENSE).

---

# 한국어

[English](#sshw) | 한국어

`sshw`는 SSH로 서버에 접속해 명령을 실행하고 파일을 주고받는 도구입니다.

서버를 `web` 같은 이름으로 등록해 두면, 다음부터는 주소 대신 그 이름을 쓰면 됩니다. 비밀번호는 PC의 비밀번호 저장소에 보관합니다. 로컬 코딩 에이전트도 같은 명령으로 서버를 사용할 수 있습니다.

- 서버에서 명령을 실행하고 결과를 확인합니다. JSON으로 받거나 실행 중 출력을 볼 수도 있습니다.
- 파일을 올리고 내려받습니다. 업로드가 끝난 파일로 기존 파일을 한 번에 교체할 수도 있습니다.
- 한 서버에 여러 로그인 계정을 등록하고, 필요하면 sudo나 su를 사용합니다.
- 프로젝트마다 설정을 따로 두고, 허용할 명령과 파일 경로를 정할 수 있습니다. 작업 기록도 남깁니다.

**사용 전에 읽어주세요.** SSH 통신에 사용하는 라이브러리에 [알려진 보안 문제](SECURITY.md#native-ssh-의존성의-알려진-보안-제한-0130)가 남아 있습니다. sshw는 비밀번호가 실수로 노출되는 일을 줄여 줍니다. 다만 에이전트도 로그인한 계정의 권한으로 작업하므로, 서버를 맡기기 전에 [보안 안내](#보안-안내)를 확인하세요.

[설치](#설치) · [첫 연결](#첫-연결) · [자주 쓰는 명령](#자주-쓰는-명령) · [계정과 sudo](#계정과-sudo) · [프로젝트별 설정](#프로젝트별-설정) · [코딩 에이전트](#코딩-에이전트) · [문제 해결](#문제-해결)

## 설치

### 실행 파일 다운로드

Rust 설치 없이 사용할 수 있습니다. [GitHub Releases](https://github.com/Lv2dev/sshw/releases/latest)에서 운영체제에 맞는 압축 파일을 받으세요.

| 환경 | 압축 파일 |
| --- | --- |
| Windows x64 | `sshw-x86_64-pc-windows-msvc.zip` |
| Linux x64 (GNU/glibc) | `sshw-x86_64-unknown-linux-gnu.tar.gz` |
| macOS, Apple Silicon | `sshw-aarch64-apple-darwin.tar.gz` |
| macOS, Intel | `sshw-x86_64-apple-darwin.tar.gz` |

압축을 풀고 실행 파일을 `PATH`에 추가하세요. `PATH`는 터미널이 실행 파일을 찾는 폴더 목록입니다.

- **Windows:** `sshw.exe`를 `C:\Tools\sshw` 같은 폴더에 넣으세요. **계정의 환경 변수 편집**을 열고, 사용자 변수 `Path`에 그 폴더를 추가합니다. 그런 다음 터미널을 새로 여세요.
- **Linux/macOS:** 압축을 푼 폴더에서 아래 명령을 실행하세요. 실행 파일을 `~/.local/bin`에 복사하고, 현재 터미널의 `PATH`에 추가합니다.

  ```sh
  mkdir -p "$HOME/.local/bin"
  cp ./sshw "$HOME/.local/bin/sshw"
  export PATH="$HOME/.local/bin:$PATH"
  ```

  새 터미널에서도 쓰려면 마지막 `export` 줄을 사용하는 셸의 시작 설정 파일에 추가하세요. `~/.local/bin`이 이미 `PATH`에 있다면 추가할 필요가 없습니다.

다음 명령으로 버전이 나오면 설치가 끝난 것입니다.

```sh
sshw --version
```

`PATH`를 설정하기 전에 실행해 볼 수도 있습니다. 압축을 푼 폴더에서 Linux/macOS는 `./sshw --version`, PowerShell은 `.\sshw.exe --version`을 실행하세요.

다운로드한 파일이 배포 원본과 같은지, 어느 빌드에서 만들어졌는지 확인하려면 [파일 검증 방법](docs/reference.ko.md#실행-파일-검증)을 참고하세요.

### Cargo로 설치

crates.io 패키지명은 `sshw-agent`이고 실행 파일명은 `sshw`입니다. Rust 1.89 이상과 아래 빌드 도구가 필요합니다.

```sh
cargo install sshw-agent --locked
sshw --version
```

| 환경 | Cargo 설치에 필요한 도구 |
| --- | --- |
| Windows | Rust MSVC 도구 모음과 Visual C++ Build Tools/Windows SDK |
| Linux | C 컴파일 도구, `pkg-config`, OpenSSL 라이브러리·헤더 |
| macOS | Xcode Command Line Tools, 빌드 도구가 찾을 수 있는 OpenSSL 설치 |

업데이트할 때도 같은 Cargo 명령을 사용합니다.

Linux에서 비밀번호를 저장하려면 GNOME Keyring이나 KWallet 같은 Secret Service가 실행 중이어야 합니다. SSH 키로 로그인한다면 SSH Agent를 사용할 수 있습니다.

소스 코드를 직접 빌드하려면 저장소에서 `cargo build --locked --release`를 실행하세요. 실행 파일은 `target/release`에 만들어집니다.

## 첫 연결

접속할 서버 주소와 SSH 로그인 계정을 준비하세요. 서버와 계정은 미리 만들어져 있어야 합니다. 아래 설정은 에이전트에 맡기기 전에 직접 터미널에서 진행하세요.

### 1. 서버 등록

`web`은 이 서버를 부를 이름입니다. 원하는 이름으로 바꿔도 됩니다. 아래의 `192.0.2.10`에는 실제 서버 주소를, `deploy`에는 로그인 계정을 넣으세요.

```sh
sshw add web --host 192.0.2.10 --user deploy
```

질문이 나오면 **SSH 로그인 비밀번호**를 입력하세요. 입력한 글자는 화면에 보이지 않습니다. 비밀번호는 설정 파일에 쓰지 않고 PC의 비밀번호 저장소에 보관합니다.

등록을 마쳐도 아직 로그인이 되는지 확인한 것은 아닙니다. 실제 접속은 다음 단계에서 확인합니다. 서버가 기본 포트 22를 쓰지 않는다면 `--port 2222`처럼 포트 번호도 붙이세요.

등록 뒤 표시되는 `next`/`then` 명령은 선택한 설정 home·프로필·프로젝트를 유지합니다. `--home`·`--profile`·`--project-dir`·`SSHW_HOME`으로 등록했다면 해당 안내 명령을 사용하세요. `--global` 등록도 그대로 유지하며, 호스트 승인과 명령 실행은 다음 단계를 직접 실행해야 진행됩니다.

기존 서버의 계정을 유지하면서 주소만 바꾸려면 `sshw endpoint web --host 192.0.2.20`을 사용하세요. `add`에서 주소 변경을 발견하면 같은 설정을 쓰는 `endpoint` 명령을 안내합니다. `add --replace`는 계정·승격 설정을 초기화하는 전체 교체용입니다.

SSH 키로 로그인하려면 위 명령 대신 아래 명령을 사용하세요. SSH Agent에 키가 등록되어 있고, 서버에서도 그 키로 `deploy`에 로그인할 수 있어야 합니다.

```sh
sshw add web --host 192.0.2.10 --user deploy --auth agent
```

이 방식은 이미 실행 중인 SSH Agent를 사용합니다. sshw가 개인키 파일을 직접 읽거나 비밀번호를 저장하지는 않습니다.

비밀 관리 도구에서 비밀번호를 받아 등록하려면 [비밀번호 입력 방법](docs/reference.ko.md#비밀번호-인증)을 참고하세요.

### 2. 서버 지문 확인

```sh
sshw trust web
```

접속하려는 서버가 맞는지 확인하는 단계입니다. 화면에 나온 지문을 서버 관리자 등 신뢰할 수 있는 경로에서 받은 지문과 비교하세요. 일치할 때만 승인하세요.

승인 질문에는 실제 주소·포트, 선택한 서버 설정 출처와 config/known_hosts 경로가 표시됩니다. 여러 프로젝트에서 같은 별명을 쓴다면 이 정보도 함께 확인하세요.

승인한 키는 저장됩니다. 이후 서버의 키가 바뀌면 sshw가 접속을 거부합니다.

### 3. 간단한 명령 실행

```sh
sshw run web "hostname"
sshw run web "whoami"
```

첫 번째 명령은 서버 이름을, 두 번째는 로그인 계정을 보여 줍니다. 둘 다 정상적으로 나오면 사용할 준비가 된 것입니다.

**서버에서 실행할 명령은 전체를 따옴표로 묶으세요.** 오류가 나면 화면의 안내나 [문제 해결](#문제-해결)을 확인하세요.

## 자주 쓰는 명령

`sshw endpoint web --host 192.0.2.20 --port 10022`는 계정·비밀번호·승격 설정을 보존하고 주소·포트만 바꿉니다. 표시된 변경을 확인하거나 `--yes`를 사용하세요. 기존 호스트 승인을 새 주소로 복사하지 않으며, 변경한 주소에도 기존 호스트키 검증을 적용합니다.

`sshw doctor web --user ops`로 등록된 로그인 계정 하나와 그 계정의 승격 비밀번호를 진단합니다. `sshw get web /var/log/app.log --into .`은 로컬 폴더 안에 원래 파일명으로 저장합니다. 기존 파일을 덮어쓰려면 이전처럼 `--yes`가 필요합니다.

doctor와 서버·계정 조회 오류의 복구 명령도 선택한 home/profile/project를 유지합니다. 상속한 서버 설정을 고쳐야 한다면 글로벌 변경임을 명시합니다. 안내만으로 호스트를 승인하거나 비밀번호를 바꾸지는 않습니다.

빈 서버 목록은 `doctor`와 `list`에서 같은 등록 방법을 안내합니다. `run`, `put`, `get`, `test`에서 호스트 키가 미승인 상태면 선택한 설정과 서버 별명이 들어간 승인 명령을 표시합니다. 키가 바뀌었다면 서버 관리자에게 새 지문을 확인한 뒤 표시된 `known_hosts` 파일을 갱신하세요.

기본 서버를 삭제할 때 `sshw remove web --switch-default staging`으로 다음 기본 서버를 지정하거나 `--clear-default`로 기본 선택을 해제하세요. `sshw profile remove prod`에도 같은 옵션을 사용할 수 있고, 프로필 기본값을 해제하면 명시한 selector가 없을 때 내장 home을 사용합니다. 숨김 비밀번호 입력창에는 서버·로그인 계정과 sudo/su 방식·대상을 표시합니다.

`sshw profile rename old new`로 저장된 비밀번호를 유지하며 프로필 이름을 바꿀 수 있습니다. 기본 로그인을 교체하고 기존 sshw 등록을 정리하려면 `sshw account remove web old-user --switch-default deploy`를 사용하세요. 서버의 실제 계정과 파일은 유지됩니다.

`sshw test web --user ops`로 호스트 승인과 실제 로그인을 확인할 수 있습니다. 원격 명령은 실행하지 않습니다. 정책에 막히면 필요한 `policy allow` 명령과 허용 범위를 안내하므로, 범위를 확인한 뒤 직접 적용하세요.

`put/get`에 `--progress`를 붙이면 전송량·퍼센트·속도가 보입니다. 매번 서버명을 지정하려면 `sshw default --clear`로 기본 서버를 해제하세요. `sshw profile default --clear`는 명시한 selector가 없을 때 내장 기본 home을 사용하도록 돌립니다. 등록한 설정은 유지됩니다.

아래 예시는 등록한 서버 이름을 `web`이라고 가정합니다. 서버에서 실행하는 명령은 Linux/Unix 기준입니다. 다른 서버에서는 해당 서버의 셸에서 사용할 수 있는 명령으로 바꾸세요.

| 할 일 | 명령 |
| --- | --- |
| 등록 서버 목록 보기 | `sshw list` |
| 서버 설정 보기 | `sshw show web` |
| 서버 이름 바꾸기 | `sshw rename web production` |
| 이름이나 호스트로 서버 찾기 | `sshw list --filter prod` |
| 저장한 로그인 비밀번호 갱신 | `sshw password web` |
| 저장한 sudo/su 비밀번호 갱신 | `sshw password web --privilege` |
| 원격 명령 실행 | `sshw run web "uptime"` |
| 실행 중 출력 보기 | `sshw run web "journalctl -n 20" --stream` |
| 파일 올리기 | `sshw put web ./report.txt /tmp/report.txt` |
| 파일 내려받기 | `sshw get web /tmp/report.txt ./downloaded-report.txt` |
| 실행 파일 올리기 | `sshw put web ./app /srv/app/app --mode 755` |
| 업로드가 끝난 뒤 한 번에 파일 교체 | `sshw put web ./app /srv/app/app --atomic --mode 755` |

`rename`은 계정·비밀번호·권한 상승 설정과 승인한 서버 키를 유지합니다. 기본 서버 지정과 계정별 허용 규칙도 새 이름을 따릅니다. 새 이름은 사용 중이지 않아야 하며, 같은 이름으로 바꾸면 변경 없이 끝납니다. 등록할 때 사용한 `--home`이나 `--profile`이 있다면 동일하게 지정하세요.

`list --filter`는 이름이나 호스트의 일부가 일치하는 서버를 대소문자 구분 없이 찾습니다. 서버에서 바꾼 비밀번호를 sshw에 다시 저장하려면 `password web`을 사용하세요. 다른 등록 계정은 `--user ops`로 선택합니다. 새 비밀번호만 숨김 입력으로 받고 다른 설정은 유지합니다. SSH-agent 계정의 인증 방식을 바꾸려면 `account add`에서 명시적으로 선택하세요.

PowerShell에서 Tab 자동완성을 켜려면 현재 세션에서 아래 명령을 한 번 실행하세요. 매번 사용하려면 PowerShell 프로필에 이 줄을 추가하면 됩니다.

```powershell
sshw completions powershell | Out-String | Invoke-Expression
```

선택한 home의 등록 서버·계정과 프로필 이름, 명령·옵션을 제안합니다. 스크립트가 프로필을 편집하거나 서버에 접속하지는 않습니다. 인용과 셸 제약은 [자동완성 참조](docs/reference.ko.md#powershell-자동완성)를 확인하세요.

`show web`은 전체 등록 계정과 계정별 인증 방식·sudo/su 대상을 보여 주며, 기본 로그인 계정을 `*`로 표시합니다. 저장한 권한 상승 비밀번호만 바꾸려면 `password web --privilege`를 쓰세요. `--user ops`로 로그인 계정을 선택하며 기존 승격 방식과 대상은 유지합니다. 무비밀번호 sudo 설정을 비밀번호 방식으로 바꾸려면 `privilege set`에서 명시적으로 변경하세요.

`put`에는 **내 PC의 파일, 서버의 저장 경로** 순서로 적습니다. `get`은 **서버의 파일, 내 PC의 저장 경로** 순서입니다.

내려받을 위치에 파일이 이미 있으면 `--yes`를 붙여야 덮어씁니다. 일반 업로드는 서버의 기존 파일을 덮어쓸 수 있으니 경로를 확인하세요. `/srv/app`에 올리려면 로그인 계정에 그 폴더의 쓰기 권한이 있어야 합니다. `--yes`로 권한을 얻을 수는 없습니다.

`--atomic`을 붙이면 업로드를 마친 뒤 기존 파일을 새 파일로 교체합니다. 서버가 OpenSSH의 POSIX rename 확장을 지원해야 하고, 저장할 폴더의 쓰기 권한도 필요합니다. 기존 파일의 소유자와 추가 접근 권한(ACL)은 유지되지 않습니다. 오류가 났을 때 파일이 어떻게 처리되는지는 [전송 상세](docs/reference.ko.md#업로드-보호실시간-출력전송-사전-검사)를 확인하세요.

`--stream`은 출력이 한 줄씩 완성될 때 보여 줍니다. `--json`이나 su 방식의 실행과 함께 사용할 수 없습니다.

**Windows Git Bash**는 `/tmp/report.txt` 같은 서버 경로를 Windows 경로로 바꿀 수 있습니다. 서버의 절대 경로 앞에 `remote:`를 붙이면 이를 막을 수 있습니다.

```sh
sshw put web 'C:/work/report.txt' 'remote:/tmp/report.txt'
```

PowerShell에서는 `sshw put web 'C:\work\report.txt' '/tmp/report.txt'`처럼 원격 경로를 그대로 사용할 수 있습니다. [Windows 경로 안내](docs/reference.ko.md#windows-셸-경로)를 참고하세요.

## 계정과 sudo

### 다른 로그인 계정 추가

`ops`로 로그인하려면 그 계정을 먼저 등록하세요. 첫 번째 명령에서 `ops`의 SSH 비밀번호를 입력한 뒤, 두 번째 명령으로 로그인 계정을 확인합니다.

```sh
sshw account add web ops
sshw run web "whoami" --user ops
```

SSH 키를 쓰는 계정은 등록할 때 `--auth agent`를 붙이세요. `--user`에는 미리 등록한 계정만 쓸 수 있습니다.

앞으로 `ops`를 기본 계정으로 쓰려면 `sshw account default web ops`를 실행하세요.

### sudo로 실행

서버가 선택한 계정의 무비밀번호 sudo를 이미 허용한다면:

```sh
sshw run web "id -u" --as-root --no-password
```

sudo에 비밀번호가 필요하다면 **sudo 비밀번호**를 먼저 등록하고 실행합니다.

```sh
sshw privilege set web --method sudo
sshw run web "id -u" --as-root
```

로그인 비밀번호와 sudo 비밀번호는 따로 등록합니다. 두 비밀번호가 같아도 등록은 각각 해야 합니다. sudo 실행을 허용할지는 서버의 sudoers 설정이 결정합니다.

다른 로그인 계정의 sudo를 설정하려면 `privilege set`에 `--account ops`를 붙이세요. 실행할 때는 `--user ops`를 사용합니다. 삭제 같은 위험 작업은 추가로 `--yes`가 필요할 수 있습니다.

sudo 설정을 저장하는 다른 방법과 su 사용법은 [권한 설정 안내](docs/reference.ko.md#권한-상승-명령)를 참고하세요.

## 프로젝트별 설정

처음에는 기본 설정을 그대로 사용해도 됩니다. 설정이 어디에 저장되는지 궁금하면 `sshw doctor`를 실행하세요.

프로젝트 폴더에서 다음 명령을 실행하면 글로벌 서버 목록을 쓰면서 권한을 프로젝트별로 관리할 수 있습니다.

```sh
sshw project init
sshw project status
sshw policy allow command hostname
sshw policy enable
sshw run web "hostname"
```

현재 폴더의 `.sshw`를 자동으로 사용합니다. 서버 목록과 권한은 각각 선택하며, 로컬 파일이 있으면 로컬을, 없거나 글로벌 사용으로 지정하면 글로벌 설정을 따릅니다. 상위 폴더는 찾지 않습니다. `project init`은 글로벌 권한을 시작본으로 복사하며 활성화 상태를 유지하고, 비밀번호는 복사하지 않습니다.

`project init`과 `project status`는 저장된 정책 활성화 값과 실제 적용 상태(on/off/blocked)를 표시합니다. 비활성 로컬 정책에는 그 프로젝트를 대상으로 한 활성화 명령을 안내하므로 허용 규칙을 검토한 뒤 직접 실행하세요. `--policy`는 이번 명령에서만 강제하며 저장된 값을 바꾸지 않습니다. 다른 폴더에서 실행해도 초기화·복구 안내는 지정한 프로젝트 경로를 유지합니다.

서버·권한을 모두 로컬로 선택하고 로컬 정책이 이미 있으면 `project init`은 사용하지 않는 글로벌 프로필을 읽지 않고 동작합니다. 새 로컬 정책을 만들어야 한다면 여전히 글로벌 시작본이 필요하며, 필요한 글로벌 설정이 잘못돼도 임의로 비활성 정책을 만들지 않습니다.

서버 목록도 따로 쓰려면 `sshw project init --servers-source local`을 실행하세요. 빈 로컬 목록으로 시작하며 그 목록 안에서만 서버를 찾습니다. `sshw add`로 계정을 등록하고 `sshw trust`로 호스트 키를 승인하세요.

상속한 글로벌 목록이 비어 있으면 `sshw list`가 `--global`로 등록하는 방법과 로컬 목록을 초기화해 등록하는 방법을 각각 안내합니다. 표시된 명령의 host/login-user 자리표시자를 실제 값으로 바꾸세요. 안내만으로 등록이나 초기화를 실행하지 않습니다.

프로젝트에서 상속 중인 설정은 읽기 전용입니다. 글로벌을 바꾸려면 `sshw --global add ...`처럼 명시하고, 로컬을 바꾸려면 해당 항목을 먼저 초기화하세요. `--home`·`--profile`·`SSHW_HOME`은 프로젝트 자동 선택을 건너뜁니다. `sshw --global list`로 글로벌 목록을 확인하거나 다른 폴더에서 `sshw --project-dir <폴더> list`로 프로젝트를 선택할 수 있습니다. 파일 형식과 출처 지정은 [프로젝트 설정 참조](docs/reference.ko.md#현재-폴더의-프로젝트-설정)를 참고하세요.

설정 폴더에 이름을 붙여 `--profile prod`로 선택할 수도 있습니다. 다만 `--home`과 이름으로 등록한 프로필은 비밀번호를 서로 공유하지 않습니다. 등록할 때 선택한 방식을 계속 사용하세요. [프로필 등록 방법](docs/reference.ko.md#profile-관리)에 자세히 설명되어 있습니다.

## 코딩 에이전트

서버 등록과 지문 확인을 마친 뒤 에이전트에게 서버 별명과 원하는 작업을 알려주세요. 예를 들면:

```text
등록한 서버 web에는 sshw로 접속해.
먼저 sshw run web "hostname && whoami && pwd" --json으로 대상을 확인해.
파일 전송은 sshw put/get을 사용하고, 비밀번호나 개인키를 요구하거나 출력하지 마.
삭제나 서비스 재시작 전에는 실행할 명령을 보여주고 내 승인을 받아.
앞 단계에 의존하는 명령은 &&로 연결하고 실패하면 중단해.
```

에이전트가 결과를 읽을 때는 `--json`을 사용하세요. `run` 결과의 `command_succeeded`가 `true`이거나 `exit_status`가 `0`이면 명령이 성공한 것입니다. `ok:true`는 명령이 끝났다는 뜻이므로 이것만으로 성공을 판단하면 안 됩니다. 서버에서 실행한 명령이 실패하면 sshw는 종료 코드 `8`을 반환합니다.

다른 명령의 결과와 작업 도중 생긴 오류는 [JSON·종료 코드](docs/reference.ko.md#json-오류-계약)를 참고하세요. 에이전트도 서버를 설정할 때 사용한 PC의 비밀번호 저장소나 SSH Agent에 접근할 수 있어야 합니다.

## 문제 해결

오류가 나면 `sshw doctor`를 실행해 보세요. PC에 저장한 설정과 비밀번호를 확인하고 다음에 할 일을 알려 줍니다. 서버 접속까지 시험하는 명령은 아닙니다.

`sshw doctor web`으로 서버 관련 검사를 `web`에 한정할 수 있습니다. 잘못된 정책이나 비밀번호 저장소 접근 문제처럼 home 전체에 영향을 주는 진단은 함께 표시합니다. 서버나 로그인 계정을 삭제하면 연결된 계정 허용 규칙도 정리하므로 나중에 같은 이름을 등록해도 그 규칙이 따라오지 않습니다.

오류가 난 명령에 `--home`이나 `--profile`을 썼다면 doctor에도 같은 옵션을 붙이세요.

| 상황 | 먼저 할 일 |
| --- | --- |
| `sshw` 명령을 찾지 못함 | `PATH`를 확인하거나 압축을 푼 실행 파일의 전체 경로로 실행하세요. |
| 서버·계정이 등록되지 않았다고 나옴 | 같은 설정 위치에서 `sshw list`·`sshw account list web`을 확인하세요. |
| 모르는 호스트 키라고 나옴 | 오류에 표시된 `trust` 명령을 실행하고 지문을 신뢰할 수 있는 경로에서 확인한 뒤 승인하세요. |
| 호스트 키가 바뀌었다고 나옴 | 서버 관리자에게 변경과 새 지문을 확인한 뒤 오류에 표시된 `known_hosts` 파일을 갱신하세요. |
| 비밀번호나 SSH 키로 로그인하지 못함 | `sshw doctor`를 실행하고 계정·비밀번호·키를 확인하세요. 서버가 그 로그인 방식을 허용하는지도 확인해야 합니다. |
| 확인이 필요하다고 나옴 | 작업을 검토한 뒤 승인된 실행에는 `--yes`, 등록 갱신에는 `--force`를 사용하세요. |
| 정책에 의해 거부됨 | `sshw policy check web "uptime"`으로 해당 명령의 규칙을 확인하세요. |
| 시간이 초과됐거나 작업이 끝났는지 알 수 없음 | 다시 실행하기 전에 서버 상태를 확인하세요. 이미 변경이 일어났을 수 있습니다. |

전체 명령은 `sshw --help`로 볼 수 있습니다. 파일 업로드 옵션이 궁금하면 `sshw put --help`를 실행하세요. 다른 명령도 같은 방식으로 확인합니다. 그 밖의 오류는 [진단과 복구 안내](docs/reference.ko.md#doctor)를 참고하세요.

## 보안 안내

- 비밀번호는 Windows Credential Manager, macOS Keychain, Linux Secret Service에 저장합니다. SSH Agent를 쓰면 sshw에 개인키를 저장하지 않습니다. 비밀번호나 토큰을 명령줄, 에이전트 대화, 평문 설정 파일에 적지 마세요.
- 에이전트는 로그인한 SSH 계정의 권한으로 작업합니다. sudo 설정을 저장해도 일반 명령은 그대로 실행됩니다. sudo나 su로 실행하려면 `--as-root`를 붙여야 합니다.
- 허용할 명령과 경로를 정하는 정책 기능은 기본적으로 꺼져 있습니다. 이 기능과 `--yes` 확인만으로 서버를 완전히 격리할 수는 없습니다. 프로그램을 통째로 허용하면 그 프로그램의 다른 기능도 쓸 수 있습니다. 경로 규칙도 서버의 심볼릭 링크가 어디를 가리키는지 확인하지 않습니다.
- 출력에서 비밀을 가리고 작업 기록을 남기지만, 모든 비밀을 잡거나 모든 작업을 기록한다고 보장하지 않습니다. 기록이 수정돼도 감지하지 못합니다. 같은 PC 사용자 권한으로 실행하는 다른 프로그램이 비밀번호 저장소에 접근할 수도 있습니다.
- 오류가 나거나 시간이 초과돼도 서버에서 작업 일부가 실행됐을 수 있습니다. 두 번 실행하면 위험한 작업은 서버 상태부터 확인하세요.

보안 기능의 범위와 SSH 라이브러리에 남은 문제는 [SECURITY.md](SECURITY.md)에 설명되어 있습니다.

## 추가 문서

- [상세 참조](docs/reference.ko.md): 명령과 옵션, 로그인 방식, 설정 폴더, 허용 규칙, JSON, 시간 제한과 파일 저장 방식
- [변경 이력과 Rust API 변경 안내](CHANGELOG.md)
- [개발 참여와 배포 절차](https://github.com/Lv2dev/sshw/blob/master/CONTRIBUTING.md)

보안 문제가 의심되면 [SECURITY.md](SECURITY.md)의 안내에 따라 GitHub Security Advisories로 비공개 제보하세요. 공개 이슈에는 예시 값만 쓰고, 실제 비밀번호나 비공개 서버 정보를 올리지 마세요.

## 라이선스

MIT. [LICENSE](LICENSE)를 참고하세요.
