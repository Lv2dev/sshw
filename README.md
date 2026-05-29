# sshw

[![CI](https://github.com/Lv2dev/sshw/actions/workflows/ci.yml/badge.svg)](https://github.com/Lv2dev/sshw/actions/workflows/ci.yml)

`sshw` is a cross-platform Rust CLI for operating known SSH servers without placing SSH passwords, private keys, passphrases, or tokens in prompts, shell history, or plaintext config files.

It is designed for local coding agents that need delegated server access for simple deployment and maintenance tasks.

## Security Boundary

`sshw` prevents accidental secret exposure in chat, command lines, shell history, JSON config, and normal command output.

It is delegated access, not a sandbox. If a local coding agent is allowed to run `sshw run`, that agent has the server authority exposed by the configured account. A fully privileged local process running as the same OS user may still try to access the operating system credential store directly.

`sshw` never stores passwords, private keys, passphrases, or tokens in its config file. Password auth stores the password only through the native OS credential store. Agent auth stores no secret and uses the user's active SSH agent.

## Install From Source

```bash
cargo build --release
```

The binary will be at:

```text
target/release/sshw
target/release/sshw.exe
```

## Release Builds

Tagged releases build GitHub release artifacts for:

- `x86_64-unknown-linux-gnu`
- `x86_64-pc-windows-msvc`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

Create a release by pushing a version tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Config

`sshw` stores non-secret server metadata in the per-user config directory:

```text
Windows: C:\Users\<user>\AppData\Roaming\sshw\servers.json
macOS:   /Users/<user>/Library/Application Support/sshw/servers.json
Linux:   /home/<user>/.config/sshw/servers.json
```

The config contains server host, port, user, auth type, and credential key names only.

## Password Auth

```bash
sshw add server-alpha --host 192.0.2.10 --port 2222 --user deploy
```

Password auth is the default. `sshw` prompts for the password using hidden input and stores it in the native OS credential store under a key like `sshw:server-alpha`.

On Linux, password auth requires a working Secret Service provider such as GNOME Keyring or KWallet. Headless Linux systems often do not have one. `sshw doctor` reports this clearly; `sshw` does not fall back to plaintext password storage.

## SSH Agent Auth

```bash
sshw add server-beta --host 192.0.2.11 --port 2222 --user deploy --auth agent
```

Agent auth stores no secret in `sshw`. It relies on your active SSH agent and loaded identities.

## Host Trust Flow

Host key verification fails closed. Unknown or changed host keys are not silently accepted.

Trust a server deliberately:

```bash
sshw trust server-alpha
sshw trust server-alpha --yes
```

The trust command prints the host key algorithm and SHA256 fingerprint, asks for confirmation unless `--yes` is present, and writes the host key to the user's OpenSSH `known_hosts` file.

## Commands

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

sshw put server-alpha ./app.exe /home/deploy/app/app.exe
sshw get server-alpha /home/deploy/app/log.txt ./log.txt

sshw remove server-alpha
sshw remove server-alpha --yes

sshw doctor
sshw doctor --json
```

Dangerous commands such as `rm -rf`, `sudo`, `chmod -R`, `chown -R`, `pm2 delete`, and obvious writes to `/etc` require `--yes`. These are safety rails, not a security sandbox.

## Coding Agent Usage

Use prompts like:

```text
Use only the local sshw CLI for server operations.
Do not ask for or print SSH passwords.
Before making changes, run: sshw run <server> "hostname && whoami && pwd"
Before destructive or service-impacting commands, show the exact command list and wait for confirmation.
Prefer sshw run --json when parsing output.
Use sshw put and sshw get for file transfer.
```

## Development

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo run -- --help
cargo run -- doctor
```
