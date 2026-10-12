# sshw

[![CI](https://github.com/Lv2dev/sshw/actions/workflows/ci.yml/badge.svg)](https://github.com/Lv2dev/sshw/actions/workflows/ci.yml)

[English](README.md) | [한국어](README.ko.md)

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

sshw saves the approved key. If the server's key changes later, it refuses the connection.

### 3. Run a harmless command

```sh
sshw run web "hostname"
sshw run web "whoami"
```

The first command prints the server's hostname. The second prints your login user. If both work, you are ready to use the server.

Keep the **whole command you want to run on the server inside quotes**. If you get an error, follow the message or check [troubleshooting](#troubleshooting).

## Everyday commands

These examples use the server name `web`. The commands that run on the server assume Linux/Unix. On another system, choose commands that work in the server's shell.

| Task | Command |
| --- | --- |
| List registered servers | `sshw list` |
| Inspect a server | `sshw show web` |
| Run a command | `sshw run web "uptime"` |
| Follow output as it arrives | `sshw run web "journalctl -n 20" --stream` |
| Upload a file | `sshw put web ./report.txt /tmp/report.txt` |
| Download a file | `sshw get web /tmp/report.txt ./downloaded-report.txt` |
| Upload an executable | `sshw put web ./app /srv/app/app --mode 755` |
| Replace a file after the upload completes | `sshw put web ./app /srv/app/app --atomic --mode 755` |

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

To keep a separate server list for a project, choose a settings folder. These examples use `.sshw` in the current folder. **Use the same `--home` on every command.**

```sh
sshw --home ./.sshw add web --host 192.0.2.10 --user deploy
sshw --home ./.sshw trust web
sshw --home ./.sshw run web "hostname"
```

Commands using this folder have their own server list, approved server keys, passwords, policy and activity log. A folder named `.sshw` is not selected automatically.

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
