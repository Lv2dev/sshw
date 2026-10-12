# sshw reference

[Getting started](../README.md) | [한국어](reference.ko.md)

Look up exact options, configuration rules and failure behavior here. Start with the README for your first connection.

- [Homes and profiles](#storage-layout-and-profiles)
- [Password authentication](#password-auth) and [SSH Agent](#ssh-agent-auth)
- [Accounts](#managing-server-accounts) and [privilege settings](#privileged-commands)
- [Commands](#commands) and [file transfers](#safer-transfers-and-live-output)
- [Windows paths](#windows-shell-paths)
- [Policy](#policy-enforcement), [audit](#audit-log) and [redaction](#output-redaction)
- [Diagnostics](#doctor) and [JSON/exit codes](#json-error-contract)
- [Persistence](#file-permissions-and-atomicity) and [release verification](#release-verification)


## Storage Layout And Profiles

Version 0.15.0 preserves existing CLI calls, exit codes and config read compatibility while adding diagnostic and change-status fields. Rust callers constructing `PrivilegeConfig` use `credential: Some(...)` with `no_password: false` for password-based settings, or `None` with `true` for passwordless sudo. Callers constructing `ErrorResponse` must include its new `mutation` field. The new `Prompter` confirmation-readiness hook has a default implementation, so existing implementations remain compatible. See [CHANGELOG.md](../CHANGELOG.md) for the release and Rust API migration notes.

All state lives under per-project **homes**. A home directory contains:

```text
<home>/servers.json    server endpoints plus registered accounts, auth/credential keys, and per-account privilege metadata
<home>/known_hosts      trusted SSH host keys (OpenSSH format)
<home>/policy.json      optional policy (see Policy Enforcement)
<home>/audit.jsonl      append-only audit log
```

The global profile registry maps profile names to homes:

```text
<config_dir>/sshw/profiles.json            registry
<config_dir>/sshw/profiles/default/         built-in default profile home
```

`<config_dir>` is `%AppData%` on Windows, `~/Library/Application Support` on macOS, and `~/.config` on Linux.

New credential keyring entries use a purpose-aware, account-qualified, generation-qualified v3 key so the same server/user pair in different homes never collides, accounts on one server cannot reuse each other's credentials, and login credentials cannot be reused as privilege credentials:

```text
sshw:v3:<encoded-namespace>:login:<encoded-server>:<encoded-user>:<generation>
sshw:v3:<encoded-namespace>:privilege:<encoded-server>:<encoded-user>:<generation>
```

The namespace, server, and user components are base64url-encoded. Each credential update receives a new generation. Legacy v1 keys (`sshw:<namespace>:<server>` and `sshw:<namespace>:privilege:<server>`) and server-scoped v2 keys remain readable only when they match the active namespace, purpose, and server without colliding with another account; new writes use v3.

`servers.json` schema v2 stores `default_user` plus a username-keyed `accounts` map under each server. Schema v1 remains readable: its single `user`/`auth` pair becomes the default account in memory, together with any matching server entry from the top-level `privileges` map. A v1 server object does not accept a nested `privilege` field. Read-only commands do not rewrite the file; the next successful config mutation persists schema v2 while retaining the legacy credential reference.

## Selecting A Home

Home selection priority, highest first:

1. `--home <path>` — a one-off / project-local home for this invocation.
2. `SSHW_HOME` — same, from the environment.
3. `--profile <name>` — a registered profile (errors if unknown).
4. the registry's default profile.
5. the built-in default profile home (`<config_dir>/sshw/profiles/default`).

`--home` and `--profile` cannot be combined (exit code 3). An explicit `--profile` also conflicts with a non-empty `SSHW_HOME`: unset the environment variable to use the profile, or omit the flag to use the environment home. SSHW never silently substitutes one for the other.

The selected home must be a directory. A file, a child beneath a file, or a failure to inspect the path fails with config/3 before loading servers or policy. Missing directories remain valid and this check creates nothing; relative paths retain their selection and credential namespace. Global `profile` management remains available to repair a bad selected home, and `profile add/default` validate their target before saving. Doctor's invalid-registry recovery still checks its built-in home and never hides an invalid explicit `--home`/`SSHW_HOME`.

```bash
sshw --home ./.sshw list
SSHW_HOME=./.sshw sshw list
sshw --profile prod run web "uptime"
```

## Managing Profiles

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

`profile add --force` validates the target and compares the resulting registry with its previous contents. Unchanged registration skips saving, preserves original bytes/mtime, and reports human (unchanged) plus JSON `changed:false`/`change:"unchanged"`. Actual changes report `changed:true` and `change:"added"` or `"updated"`. Existing action/id/home/namespace fields, the force requirement, locking and auditing remain. Default or saved-path changes still use the existing concurrency and atomic-write checks.

`profile default <name>` rechecks the target's settings and home path using its registered credential namespace before saving the default. Invalid settings or incompatible credential references fail with config/3 and leave the previous default intact. Empty homes remain valid. You can switch away from a damaged current profile to a valid target; the check does not read secrets, connect over SSH, or rewrite the target's files or namespace.

Removing the default profile also checks the automatically selected next profile's local settings. Removal still succeeds and keeps the existing name order. If the new default cannot be validated, human output and JSON `default_target_warning` report its name, home, masked cause, and recovery steps alongside `default_change`. Repair that home or use `sshw profile list` and `sshw profile default <valid-name>` to switch. Other removals, an empty target home, and removal of the last profile do not produce this warning. The check does not read secrets or test SSH connectivity.

Profile registration and updates validate the target servers.json schema, defaults, accounts and credential references against the selected namespace. The registry is saved only when it changes. Incompatible settings report the path and cause and preserve the previous mapping and default; --force does not bypass validation. Missing homes and compatible agent/passwordless settings are accepted unless an existing path component is a file. Validation does not modify the target, read passwords or the keyring, or connect over SSH; later file changes are rechecked at execution.

profile add distinguishes added from updated entries. JSON includes id and namespace_changed; a move adds previous_home and a warning to re-register credentials. Updates to the same home preserve the namespace. Moving a profile does not move server files or secrets, and the old home/keyring remains. If copied password settings are incompatible, choose an empty or compatible home and register the necessary passwords in the new namespace.

Removing a default server or profile selects the first remaining name in sorted order. Human output shows the previous and new defaults; JSON includes default_change only for an actual transition, with resource (server or profile), previous and current. Removing the last entry sets current to null. Without a registered default profile or explicit home/profile, normal selection uses the built-in home. Check the result because later commands that omit a server use the new default.

Registries are validated strictly. If an older release stored a relative profile home, normal selection/list/show/default operations fail closed. `sshw doctor` reports `registry_valid: false` and an actionable `registry_message`; `sshw profile remove <affected-name>` is the only recovery exception and succeeds only when removing that exact entry leaves a fully valid registry. It never resolves or migrates the relative path against the current working directory.

## Password Auth

```bash
sshw add server-alpha --host 192.0.2.10 --port 2222 --user deploy
```

Password auth is the default. `sshw` prompts for the password with hidden input and stores it in the active credential backend under the home's namespace.

Registration rejects empty/whitespace-only hosts, control characters in hosts, and port `0` before confirmation or password input, with `config`/exit `3`. Ports are `1..65535`. The same checks apply when loading v1/v2 settings; `doctor` reports invalid settings with the server name and cause. Host values are preserved, including IPv6 addresses. These are metadata checks and do not resolve DNS or test connectivity. Correct an invalid saved endpoint in the reported `servers.json` path.

For non-interactive registration, pipe the password from a secret manager:

```bash
secret-manager-read deploy/server-alpha | sshw add server-alpha --host 192.0.2.10 --port 2222 --user deploy --password-stdin
```

`--password-stdin` is valid only with password auth. It reads stdin once, strips one final LF or CRLF, rejects empty input, and avoids placing the password in argv or shell history. `sshw` intentionally does not provide `--password <value>`.

If `add`, `account add`, or `privilege set` cannot read a password from the controlling terminal, the auth/4 error includes the original OS cause and suggests an interactive terminal or `--password-stdin` with a secret-manager pipe. Redirecting stdin alone does not enable password input; pass the option explicitly. A working controlling terminal still supports hidden password input when stdin is redirected.

On Linux the native backend requires a working Secret Service provider (GNOME Keyring, KWallet). `sshw doctor` reports availability; `sshw` never falls back to plaintext storage.

## SSH Agent Auth

```bash
sshw add server-beta --host 192.0.2.11 --port 2222 --user deploy --auth agent
```

Agent auth stores no secret; it uses the active SSH agent.

Re-registering an agent server with `add` or an agent account with `account add` still requires confirmation or `--force`. If the resulting configuration is identical, it skips saving, preserves the original format/bytes/mtime, and reports human `(unchanged)` and JSON `changed:false`/`change:"unchanged"`. Actual changes use `changed:true` with `change:"added"` or `"updated"`; existing action and target fields remain. Endpoint/default/account changes and replacement are compared as part of the whole configuration. Password registration always renews the credential and remains a real change. Validation, locking, auditing and actual-change concurrency/atomic-write/credential-cleanup checks remain.

Agent authentication failures in `run`, `put` and `get` show the selected login user, endpoint, redacted native cause and recovery steps. Run `sshw doctor` with the same home/profile and execution environment, check the agent connection and loaded identities, then verify that the server allows that account/key. An unavailable agent and an agent with no identities can have different causes. These errors retain auth/4 and JSON `causes`; they do not automatically start an agent, load keys, or fall back to password auth. Host-key verification still happens before authentication.

## Managing Server Accounts

Unknown server errors (config/3) explain that selection requires a registered server and show `sshw list` plus a registration command with host/login-user placeholders. Keep the same home/profile and replace the placeholders before running it. The command quotes the requested name for PowerShell on Windows or POSIX shells elsewhere, masks sensitive values and puts the name after `--`. Registration defaults to hidden password input; put `--auth agent` or `--password-stdin` before `--` as needed. `run` and its policy check also keep the whole-command quoting hint. No server is registered, selected from another home or contacted by this diagnostic.

Password SSH authentication failures in `run`, `put` and `get` show the selected login user, host/port and redacted native cause. Use the same home/profile with `sshw doctor` to inspect local credential readiness, check the login password (`SSHW_PASSWORD` for session-only homes), the account's login access and whether the server accepts password authentication. A generic authentication failure alone does not identify which condition failed. Errors retain the original native source/code, auth/4 and JSON causes. Host-key verification still comes first; these diagnostics do not change credentials, retry authentication or switch to agent auth.

Each server endpoint can hold multiple explicitly registered SSH usernames. Omitting `--user` uses that server's `default_user`; `--user <name>` selects only an existing account and never acts as an ad-hoc username override.

The canonical selector is the explicit `--user` flag. `user@alias` is not parsed because existing server aliases may contain `@`; an exact flag avoids ambiguous target resolution.

An unknown account error (config/3) explains that login selection requires a registered account and shows copyable `account list` and `account add` commands. Use the same home/profile. Registration defaults to hidden password input; insert `--auth agent` before the suggested command's `--` for agent auth, or `--password-stdin` for redirected password input. The error does not register an account or change credentials. Suggested names are masked and quoted for the local shell.

```bash
sshw account add server-alpha ops                         # password prompt
sshw account add server-alpha auditor --auth agent
sshw account list server-alpha
sshw account show server-alpha ops --json
sshw account default server-alpha ops
sshw account remove server-alpha auditor --yes

sshw run server-alpha "whoami"                           # default account
sshw run server-alpha "whoami" --user deploy             # registered deploy account
sshw put server-alpha ./app /srv/app/app --user deploy
sshw get server-alpha /var/log/app.log ./app.log --user deploy
```

Password accounts store a distinct credential per server and username. Updating an account rotates only its login credential and preserves its account-specific privilege configuration. Removing a non-default account publishes the config removal before deleting that account's login and privilege credentials. A default account cannot be removed until another registered account becomes the default. `trust` remains server-only because every account on an endpoint shares the same host/port host-key boundary.

Human `account list/show` output includes the privilege method, target user, and authentication mode, such as `sudo -> service (no password)` or `su -> root (password)`. An omitted saved target defaults to `root`; accounts without privilege settings show `none`. The login account is listed separately. Human target labels mask secret patterns; the JSON structure is unchanged.

Server, account and privilege mutations save configuration before cleaning up old credentials. A cleanup failure still returns exit 4 and ok:false, but explains that the configuration has already been applied. JSON mutation includes config_applied:true, failed_stage:"credential_cleanup", action, server and account where relevant. A default change from server removal is retained as mutation.default_change. Inspect show/list/account show/privilege show before retrying; repeating an applied command does not guarantee cleanup of credentials whose references have already been removed. Failed configuration saves do not report successful application.

## Credential Backends

The home's `servers.json` selects the credential backend via `credential_backend` (default `native`):

- `native` — the OS keyring (Windows Credential Manager, macOS Keychain, Linux Secret Service).
- `session_only` — never touches the keyring. `set_password` stays in memory for the process only. At run time, login passwords come from `SSHW_PASSWORD` and privilege passwords come from `SSHW_PRIVILEGE_PASSWORD`; both variables are removed from this process environment after reading. Suited to ephemeral/CI use. Environment variables can still be visible before `sshw` starts or in the parent shell, so treat both as sensitive. `add --auth password` and `privilege set` warn that their passwords are not persisted.

An external-helper backend is a planned extension behind the same `CredentialStore` trait.

## Privileged Commands

```bash
secret-manager-read root/server-alpha | sshw privilege set server-alpha --method sudo --password-stdin
secret-manager-read root/server-alpha-ops | sshw privilege set server-alpha --account ops --method sudo --password-stdin
sshw privilege show server-alpha
sshw privilege show server-alpha --account ops
sshw privilege clear server-alpha --yes
sshw run server-alpha "systemctl restart app" --user ops --as-root --yes
```

Privilege metadata is scoped to the selected login account. `privilege set/show/clear --account <login-user>` selects an explicit account; omitting it uses the server default. `privilege set` stores only method, target user (default `root`), and credential key metadata in `servers.json`. The sudo/root password is stored in the active credential backend, never in CLI arguments or plaintext config. For password-based settings, omitting `--password-stdin` uses a hidden prompt. Passwordless settings store `no_password:true` without a credential reference. Existing settings remain password-based. Human set/show/clear output and confirmation prompts identify the login account and target user separately; JSON includes `no_password` and uses `credential:null` for passwordless settings.

`run --as-root` (alias `--elevate`) explicitly requests elevation; a second `--yes` is not needed unless the original command triggers a safety check. With password-based sudo settings, it first applies the normal safety and policy checks to the original command, then uses `sudo -S` with the privilege password passed through SSH channel stdin. The password is never embedded in the remote command string or audit detail. If the target user has a `NOPASSWD` sudoers rule, the command runs regardless of whether the stored password is correct, since `sudo` never consumes it — keep the stored secret accurate, but do not rely on it as an extra gate in that configuration. A sudo password rejection is reported as the remote command's non-zero status (sshw exit `8`, with the real status in `run --json` as `exit_status`) because `sudo` ran remotely. `method=su` runs `su - <user> -c ...` over a PTY and injects the stored password at the `Password:` prompt (echo disabled, prompt forced to English via `LC_ALL=C`). The command's output and exit code are framed by markers and extracted exactly. It is more environment-sensitive than `sudo`; where the prompt is not recognized it fails closed via a timeout rather than hanging. A `su` prompt/auth failure before the completion marker is an sshw auth/setup failure and maps to exit code `4`.

For a server that already permits passwordless sudo, use `sshw run web "id -u" --as-root --no-password`. This runs `sudo -n` without reading a stored privilege password or prompting. It uses the configured sudo target user, or `root` when no privilege configuration exists; a configured `su` path is rejected. The server still enforces sudoers. `privilege set --account` also accepts `--login-user`, and its target `--user` accepts `--target-user`.

`run --as-root` checks the required privilege settings and any su/`--no-password` conflict before looking up the login password. A missing login password therefore no longer hides a local privilege configuration error (config/3). Safety, policy, account selection and stream/su checks still run first. Ordinary login failures remain auth/4, and `--as-root --no-password` still allows an account without saved privilege settings.

Repeating `privilege set --no-password` still requires confirmation or `--force`. An identical resulting configuration skips saving and reports human `(unchanged)` and JSON `changed:false`/`change:"unchanged"`, preserving the original bytes/mtime. New settings and changes report `true` with `added/updated`; existing target and credential fields remain. Password registration still rotates the credential. Validation, locking, auditing and actual-change concurrency/atomic-write/credential cleanup remain. This compares local metadata and does not check server sudoers.

To save a passwordless sudo target for a specific login account:

```bash
sshw privilege set web --account ops --user service --no-password
sshw run web "id -un" --user ops --as-root
```

The saved setting makes `--as-root` use `sudo -n` without prompting, storing or loading a privilege password. Ordinary runs still use the login account. `privilege set --no-password` rejects `--method su` and `--password-stdin`; omit `--no-password` on a later set to restore password-based authentication. Updating an existing setting requires confirmation or `--force`. Switching modes removes the old stored password only after the configuration is saved successfully. Doctor and removal commands skip nonexistent password entries. The server must independently allow the requested sudo target; denial returns the normal remote failure status without a password fallback.

## Host Trust Flow

Host key verification fails closed; unknown or changed keys are not silently accepted. Trusted keys are stored in the active home's `known_hosts`.

```bash
sshw trust server-alpha
sshw trust server-alpha --yes
```

`trust` prints the algorithm and SHA256 fingerprint, confirms unless `--yes`, and re-verifies the fingerprint immediately before writing. If the key changes during the flow, it fails instead of storing the new key.

Without `--yes`, trust checks that confirmation is available after server lookup and before connecting. Noninteractive stdin fails with config/3 and an interactive-terminal/`--yes` hint, even if the endpoint is unreachable. `--yes` keeps the normal connection and fingerprint re-verification flow. Library `Prompter` implementations can override the default `ensure_confirmation_available` hook without prompting; existing implementations remain compatible.

## Commands

```bash
sshw add <name> --host <host> [--port <port>] --user <user> [--auth password|agent] [--password-stdin] [--force] [--replace] [--json]
sshw list [--json]
sshw show <name> [--json]
sshw default [<name>] [--json]
sshw trust <name> [--yes] [--json]
sshw run [<name>] "<command>" [--user <registered-user>] [--json|--stream] [--yes] [--as-root [--no-password]]
sshw put [<name>] <local> <remote> [--user <registered-user>] [--atomic] [--mode <octal>] [--json] [--yes]
sshw get [<name>] <remote> <local> [--user <registered-user>] [--json] [--yes]
sshw remove <name> [--yes] [--json]
sshw doctor [--json]
sshw account add <name> <user> [--auth password|agent] [--password-stdin] [--force] [--json]
sshw account list <name> [--json]
sshw account show <name> <user> [--json]
sshw account default <name> <user> [--json]
sshw account remove <name> <user> [--yes] [--json]
sshw privilege <set|show|clear> ... [--json]
sshw profile <add|list|show|default|remove> ... [--json]
sshw policy <init|show|enable|disable|allow|remove|check> ... [--json]
```

`add`, `account add`, and `profile add` take `--force` to confirm an update non-interactively. Updating a server at the same host/port preserves its other accounts and the updated account's privilege settings; only the selected login credential is rotated. Changing host or port requires `--replace`, which explicitly resets the account set and privilege settings and cleans up stale credentials. Use a new server name to keep the old endpoint available. `--force` alone never authorizes endpoint replacement.

`add` and `account add` reject `--auth agent --password-stdin` with config/3 before asking to confirm an update. Existing config, target and endpoint-replacement checks retain their precedence. Valid updates still require confirmation or `--force`; password input and credential cleanup are unchanged.

add --user registers that account and selects it as the default login. If an update changes the default, confirmation and human output show the previous and new accounts; JSON adds user and default_change (resource:"account", previous, current). An unchanged default has no transition object. If only credential cleanup fails after saving, mutation.default_change still records the transition. Use account add to register an account while keeping the existing default.

Global flags (available on every command): `--home <path>`, `--profile <name>`, `--policy`, `--timeout <seconds>`.

`--timeout` sets an absolute timeout (seconds) for the remote operation phase of `run`/`put`/`get` after the connection is established; output or transfer progress does not extend it. Omitting the flag uses the 900-second default, while `0` explicitly disables the deadline. DNS resolution, all resolved-address attempts, TCP setup, and the SSH handshake share one 15-second connection deadline. `run` closes channel stdin even when no input was supplied and drains stdout and stderr concurrently. Exceeding the 16 MiB limit fails the operation with exit 5 instead of returning truncated success output; the remote command may already have run, so do not blindly retry non-idempotent work.

When the name is omitted for `run`/`put`/`get`, the configured default server is used. When `--user` is omitted, that server's default account is used.

`default <name>`, `account default <server> <user>`, and `profile default <name>` keep an already selected default without rewriting the config or registry. Human output marks it unchanged; JSON retains the existing action/target fields and adds `changed:false`/`change:"unchanged"` (`true`/`"updated"` for a real change). No-ops preserve the original bytes, modification time, and v1 format. Target validation, locks, and audit recording still apply; a damaged profile target is rejected even when already the default. The query-only `default` response is unchanged.

## Safer transfers and live output

Atomic upload errors identify the failed step, its cause, the destination and temporary path, and the cleanup/replacement state. If the server's file-creation response is lost, the temporary file may exist but its creation is unconfirmed; sshw does not automatically delete that path. Inspect the path and ownership before retrying. Confirmed temporary files are cleaned up on failure when the connection and permissions allow it.

```bash
sshw policy check-put web ./app /srv/app/app --atomic --json
sshw put web ./app /srv/app/app --atomic --mode 755
sshw policy check-get web /var/log/app.log ./app.log --json
sshw run web "./long-build" --stream
```

`put --atomic` writes a temporary file in the destination directory, verifies its size and closes it before replacing the destination using `posix-rename@openssh.com`. An SFTP server supporting that extension and write permission on the parent directory are required. When policy is enabled, allow the parent directory as well as the destination. Unsupported atomic rename fails without a non-atomic fallback. Before replacement, failures preserve the existing destination and attempt to remove the temporary file. A lost connection can leave a temporary file or an unconfirmed replacement; inspect the reported paths before retrying. Replacement creates a new inode with mode 600 unless `--mode` is specified: old ownership/ACLs are not preserved, and a destination symlink is replaced rather than followed. This provides atomic visibility, not crash-durability or privilege escalation. Ordinary `put` retains its existing SCP behavior.

`run --stream` emits complete, redacted stdout/stderr lines while the command runs. Incomplete lines wait for completion; PEM private-key blocks and secrets split across network reads remain masked. Known multiline secrets require conservative buffering. The existing 16 MiB combined output limit and exit codes remain in force. JSON and `su` PTY are not supported with streaming; ordinary run and sudo are supported. Failures show the redacted cause together with the completion-unconfirmed notice. Output already emitted is not repeated on failure, and the remote command may have had side effects. Ordinary run and sudo use a short SSH cleanup timeout after channel errors in buffered, JSON and streaming modes; this does not confirm that the remote process stopped.

`policy check-put/check-get` use the same positional arguments, `--user` and `--yes` as transfers; `check-put --atomic` also checks staging-directory policy. Shared checks use the execution order and report the first failing prerequisite. After access checks pass, both `put` (including `--atomic`) and `check-put` verify that the local source is a readable regular file without reading its contents. `put` performs this check before looking up the account password, so an invalid source is reported as IO/6 even when credentials are missing. JSON distinguishes `access_allowed`, `local_file_checked` and `local_file_ready`; `allowed` covers all evaluated local checks. These are point-in-time results, and the transfer still opens and validates its own file handle. SSH authentication, remote filesystem permissions and server extension support are not tested by preflight. `--yes` confirms a guardrail; it grants no remote OS permission.

For `get`, specify a local file path. Both execution and `policy check-get` reject an existing directory destination and identify invalid local parent paths before connecting. `--yes` approves replacing a file; it does not make a directory a valid file destination. Missing parent directories are created only during the actual download. Preflight does not create files or verify local write permission. With `--yes`, a destination symlink is replaced rather than writing through it to its target. The destination is checked again before staging and final publication; failures before publication preserve the existing destination and clean up the staged file.

## Windows Shell Paths

Git Bash/MSYS automatically converts path-like arguments passed to native Windows executables. That conversion can rewrite a remote POSIX path such as `/tmp/artifact.tgz` into a local Windows path before `sshw` sees it. Prefix an absolute remote path with `remote:` to pass it literally; sshw removes the prefix before applying safety, policy, audit, JSON, and SSH handling:

```bash
sshw put server-alpha 'C:/path/artifact.tgz' 'remote:/tmp/artifact.tgz'
sshw get server-alpha 'remote:/var/log/app.log' 'C:/path/app.log'
```

The suffix must be an absolute POSIX path (`remote:/tmp/file`), Windows drive path (`remote:C:/Data/file` or `remote:C:\Data\file`), or UNC path. An empty or relative literal such as `remote:` or `remote:tmp/file` fails as config error 3 before SSH. Prefix-free absolute and relative remote paths keep their existing behavior. The leading `remote:` form is reserved; use `./remote:name` when a literal relative filename itself starts with `remote:`.

Alternatively, disable conversion for the whole Git Bash invocation with `MSYS2_ARG_CONV_EXCL='*'`. In PowerShell no conversion occurs, so both a raw remote absolute path and the explicit literal work:

```powershell
sshw put server-alpha 'C:\path\artifact.tgz' '/tmp/artifact.tgz'
sshw put server-alpha 'C:\path\artifact.tgz' 'remote:/tmp/artifact.tgz'
```

Windows accepts both `C:\path\file` and `C:/path/file` as local paths; backslashes are shown for the native PowerShell form. A missing or unreadable local file is an I/O failure (exit 6). A raw remote path already converted by MSYS can still surface later as an SSH failure (exit 5), with a hint to use `remote:` or disable conversion.

To transfer the tracked source tree, create the archive from Git instead of archiving the working directory or `target`:

```powershell
$archive = Join-Path $env:TEMP 'sshw-src.tgz'
git archive --format=tar.gz --output="$archive" HEAD
sshw put server-alpha "$archive" 'remote:/tmp/sshw-src.tgz'
```

`git archive` includes only files tracked in the selected commit, so it excludes `.git`, `target`, untracked files, and uncommitted changes. This also avoids depending on whether the shell resolves `tar` to Windows bsdtar, Git's GNU tar, or a WSL executable.

`run` returns captured output after completion. Human TTY invocations show the selected home and a start notice. Ordinary run/sudo read failures and timeouts can include redacted `partial_output` with `completion_confirmed:false`; they remain errors and must not trigger blind retries. A capture ending inside a known password is conservatively masked. `su` prompt/marker failures do not offer this partial-output contract. Local stdin is not forwarded to the remote command.

For executable uploads, request permissions explicitly: `sshw put web ./app /srv/app/app --mode 755`. The creation default stays 600, and special permission bits are rejected. Explicit mode also updates an existing file's permissions and sets its timestamps to the transfer time; ordinary uploads retain the server's existing-mode behavior. This does not elevate file transfers. Uploading to an existing remote file can replace it; downloading over a local file still requires `--yes`.

## Safety Rails

Dangerous commands such as `rm -rf`, `sudo`, `chmod -R`, `chown -R`, `pm2 delete`, and obvious writes to `/etc` require `--yes`. `sshw get` will not overwrite an existing local file without `--yes`. `sshw put` creates remote files with owner-only permissions where the server honors SCP modes. These are safety rails, not a security sandbox.

## Policy Enforcement

Manage the existing policy format without editing JSON:

```bash
sshw policy init
sshw policy allow command "systemctl status app"
sshw policy allow put /srv/app
sshw policy allow account web ops
sshw policy enable
sshw policy check web "systemctl status app" --user ops --json
sshw policy show --json
```

`init` creates a disabled empty policy and refuses to replace an existing file. `allow` adds a rule without enabling enforcement; `remove` removes an exact entry, while other rules may still match. `enable`/`disable` change the saved `enabled` setting. Mutations distinguish added, already present, removed, not found and unchanged results. JSON adds `changed` and `change` (`created`, `added`, `already_present`, `removed`, `not_found`, `updated`, `unchanged`). A no-op still succeeds and skips saving. Policy mutations retain the home's lock and audit log; actual changes use revision checking and atomic save. Full command rules are never copied into audit detail. Existing policy v1 files remain readable and are saved as v2 when their contents change.

Policy management output distinguishes file presence, the saved `enabled` setting, and enforcement for the current invocation. JSON includes `present`, `enforced`, and `forced` (`--policy`). A missing file is shown as not configured with an `sshw policy init` next step; forced operations still fail closed until the file exists. `disable` changes the saved setting, while `--policy` continues forcing enforcement for invocations that pass it. Remove that option to use the saved disabled setting, keeping the same home/profile selection.

`check`, `check-put` and `check-get` show policy enforcement state and matching rules in human output and a JSON `policy` object (`path`, `enforced`, `forced`, `checks`). Each check explains `allowed`, `reason`, and, when a rule matched, `matched_rule` and `match_type` (`program`, `exact`, `prefix`, `path`, `account`). The first matching rule in file order is reported. The explanation also distinguishes a disabled policy, an implicitly allowed default account, shell syntax requiring an exact full-command rule, unmatched rules and parent traversal. Atomic uploads explain the parent-directory rule separately as `atomic_parent`. Explanations use the same loaded policy and matching logic as enforcement and redact secrets. These policy decisions are independent of safety, account existence and local file readiness; the existing overall `allowed`, `reasons` and exit code remain authoritative. Local checks do not test credentials, SSH or sudoers.

`policy check [server] "<command>"` uses the same target syntax and default server as `run`; for example, `sshw policy check "uptime" --json`. Shared local checks follow execution order, so the first reason and exit code match `run` for the checks performed. Preflight still lists additional independent blockers. Config and policy loading errors retain their normal error envelope, as does an account-selection failure when it is the first failure. Privilege metadata is checked without loading passwords; authentication or connection failures are outside this check.


Policy is **off by default**. Turn it on for an invocation with `--policy`, or persistently with `"enabled": true` in the home's `policy.json`:

```json
{
  "version": 2,
  "enabled": true,
  "allow_commands": ["uptime", "systemctl status *"],
  "allow_put_paths": ["/srv/app"],
  "allow_get_paths": ["/var/log"],
  "allow_accounts": [
    { "server": "server-alpha", "user": "ops" }
  ]
}
```

When enforcing, default accounts remain available, but a non-default `--user` must exactly match a structured `allow_accounts` entry. Existing policy v1 files remain valid and allow only default accounts. `run` commands must match `allow_commands` and `put`/`get` paths must be under `allow_put_paths`/`allow_get_paths`. A command containing shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `(`, `)`, `<`, `>`) only matches an **exact** allowlist entry. Transfer paths containing `..` are rejected. Denied operations return exit code 7 (`policy`).

`policy allow put/get` rejects root-only `/` and repeated-slash rules because they grant no access; choose a specific directory such as `/srv/app` or `/var/log`. Existing root-only entries remain inactive and can be removed with `policy remove`. Windows drive-absolute paths (`C:\Data` or `C:/Data`) and UNC paths beginning with `\\` recognize both separators for children and trailing separators, while preserving case and directory boundaries. POSIX and relative paths keep literal backslashes. This matching does not rewrite the path sent to SSH or canonicalize it. `put --atomic` still requires forward slashes in the actual SFTP destination.

Policy fails closed: with `--policy`, a missing policy file is an error, and a present-but-invalid file is always an error. An inactive policy file (`"enabled": false`) is still rejected when it has an unknown field or unsupported version; rename or remove an intentionally unused invalid file before running remote operations.

Command rules have three forms: a full command such as `systemctl status app` matches exactly; a trailing `*` such as `systemctl status *` matches a text prefix; and a bare program name such as `cat` allows that program with arbitrary arguments when the command contains no shell metacharacters. Bare-program rules delegate that program's capabilities, including accessible files and subprocesses. Even an exact rule does not isolate what the permitted program can do. `allow_put_paths`/`allow_get_paths` match remote paths by lexical prefix and reject `..`, but they do not resolve remote symlinks or canonicalize paths, so a symlink under an allowed prefix can still point elsewhere on the host — the path allowlist is a guardrail, not a remote sandbox.

## Audit Log

Mutating/active operations (`add`, `remove`, `trust`, `default`, `account add`, `account default`, `account remove`, `profile add`, `profile default`, `profile remove`, `run`, `put`, `get`, `privilege set`, `privilege clear`) are appended to `audit.jsonl`, one JSON object per line. Home-scoped operations use the active home's log; global profile-registry mutations consistently use the built-in default home's log regardless of the profile being added, selected, or removed:

```json
{"time_ms":1700000000000,"action":"run","server":"web","user":"ops","status":"ok","exit_code":0,"detail":"uptime"}
```

`user` records the selected login account. `detail` for `run` is only the program name (not its arguments). Server names, users, paths, and details are redacted on a best-effort basis. Attempted `run`/`put`/`get` operations, including policy setup failures, are recorded with an error status. Read-only commands (`list`, `show`, `account list`, `account show`, `doctor`, `profile list`, `profile show`) are not audited. Audit writes are best-effort: a busy record lock is retried for 100 milliseconds and then that record is skipped without failing the operation. The file is owner-only on Unix (best-effort on Windows). The log is append-only but not tamper-evident — it has no integrity chain or signing, and anyone who can write the home can edit or delete entries. Treat `audit.jsonl` as sensitive.

## Output Redaction

`run` stdout, stderr, and the echoed JSON command are passed through best-effort redaction that masks PEM private-key blocks, `keyword=value`/`keyword: value` assignments for common secret keywords, and bearer tokens. When loaded for an operation, the exact login password and configured privilege password are also redacted wherever they appear in those fields. Very short or common exact passwords can therefore over-redact unrelated output; secrecy takes priority over output fidelity. This does not understand every shell representation, and secrets split across lines may not be masked. Do not pass secrets inline.

Copyable trust/run hints after registration, doctor host-trust hints, and privilege setup hints quote each argument and place positional values after `--`. They use PowerShell syntax on Windows and POSIX shell syntax on other operating systems. Keep the same `--home`/`--profile` selection and insert extra options before `--`. In Git Bash on Windows, adapt PowerShell quoting to POSIX quoting. Sensitive values in hints are replaced with `<redacted>`; replace those placeholders with the intended identifiers before executing a command, and never put passwords in arguments.

## Doctor

```bash
sshw doctor
sshw doctor --json
```

Missing privilege-password recovery keeps the saved login account, privilege method and target. Persistent backends suggest re-registration using the same --home/--profile; confirm the update or put --force before the suggested command's --. For redirected input also put --password-stdin before --. Windows hints use PowerShell quoting; other platforms use POSIX quoting. A session-only backend instead requires SSHW_PRIVILEGE_PASSWORD at execution because registration cannot persist it. Never put a password in command arguments.

Trust/run hints after registration, doctor host-trust hints and privilege-setup hints quote each argument and place server/command values after --. Keep the same home/profile and insert extra options before --. In Windows Git Bash adapt the PowerShell quoting to POSIX quoting. Secret-looking identifiers are replaced with <redacted>; substitute the intended identifiers before running the command. Never put passwords in arguments.

Empty, whitespace-only or control-character privilege targets are rejected as config/3 during registration and v1/v2 configuration loading. Registration stops before confirmation or password input. For an invalid saved target, use doctor and the reported configuration path to repair it; preflight and execution also reject it. This validation does not test whether the remote account exists or sudoers permits it.

`doctor` reports the active home/source, storage paths, config/registry/policy validity, linked libraries, audit writability, credential-backend health, missing login and privilege credentials, and local SSH agent availability. `issues` includes a suggested next step for each local problem. `local_checks_passed` summarizes those checks while `connection_tested:false` makes clear that reachability, matching host keys, authentication and sudoers were not tested. `ok:true` means the diagnostic ran, even when local issues exist. A corrupt registry is diagnosed from a recoverable home; conflicting home/profile selectors are still rejected.

If the audit log is absent, doctor creates and immediately removes a private empty sibling probe in its existing parent to check creation permission. Unix probes are owner-only; neither `audit.jsonl` nor missing parents are created. Existing logs are only opened for append readiness without writing records or changing contents/permissions. Failures report a masked path/cause and recovery step; JSON `audit_message` is null on success. A creation probe can update the parent directory modification time. This point-in-time check does not guarantee a later record or lock succeeds, and the existing best-effort recording and doctor exit0/`ok:true` remain unchanged.

The local host-key check reads and parses the active home's `known_hosts` using the connection parser and checks each server's endpoint, including hashed hosts and non-default ports. JSON `host_trust` reports `entry_present:true/false`, or `null` when reading, parsing or inspection fails, and always `key_match_checked:false`. Empty files and entries for other servers are not ready. Repair unreadable or invalid files before retrying the suggested trust command. An existing entry does not prove that it matches the remote server's current key; normal connections still verify that key.

Login credential lookup failures from `run`, `put`, and `get` show the selected server/account and the redacted backend cause. Session-only homes require `SSHW_PASSWORD` at run time. Persistent backends suggest `sshw doctor` and password re-registration through `account add` if the entry is missing. Keep the same home/profile selection; confirm an update or insert `--force` and `--password-stdin` before the command's `--` for non-interactive secret-manager input. These commands preserve the selected account's privilege settings and do not put secrets in arguments.

Privilege password lookup failures from `run --as-root` also show the server/login account, sudo/su method, target user, and redacted backend cause. Session-only homes require `SSHW_PRIVILEGE_PASSWORD` independently of the login password. Persistent backends suggest checking `sshw doctor` before re-registering a missing entry with `privilege set`; the suggested command retains the account, method, and target. Use the same home/profile, confirm the update or insert `--force` and `--password-stdin` before `--`, and keep passwords out of arguments. These local lookup failures retain auth/4 and JSON causes; passwordless elevation and remote sudo/su behavior are unchanged.

`privilege clear` succeeds without prompting or rewriting settings when a registered account already has no saved privilege configuration. JSON retains `action:"cleared"`, server/account fields, and adds `changed:false`/`change:"unchanged"`; a real clear reports `true`/`"removed"`. Unknown targets and invalid settings still fail, and lock/audit behavior is retained. Actual clears retain confirmation, secret cleanup, and partial-application diagnostics. This only clears saved local privilege settings; remote sudoers and existing elevation flags are unchanged.

Lock and config/profile-registry persistence failures show the reported path, operation stage, masked underlying cause, and a recovery step in human and JSON errors. Check the reported path/parent permissions, file type, filesystem, or active lock holder as indicated. Existing exit codes, JSON causes, timeouts, concurrency checks and atomic writes remain unchanged. A parent-directory sync failure after publication explicitly says the state was published: inspect it before retrying; the original publication marker and credential cleanup decisions are retained.

## JSON Error Contract

Connection setup failures from `run`, `put`, `get` and `trust` show the failing stage (address resolution, TCP connection or SSH handshake), host/port, redacted underlying cause and a next step. For a refused connection, check the endpoint, whether SSH is listening, and network/firewall access. The displayed `connect timeout budget` is the maximum budget, not elapsed time; the cause identifies an actual timeout or refusal. Errors retain ssh/5 and JSON `causes`. Connection deadlines, retries, host-key verification and authentication behavior remain unchanged.

Commands that support `--json` (`add`, `list`, `show`, `trust`, `run`, `put`, `get`, `remove`, `doctor`, `account add`, `account list`, `account show`, `account remove`, `profile list`, `profile show`, `privilege set`, `privilege show`, `privilege clear`) return a structured error envelope on runtime failures:

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
{"ok":true,"server":"server-alpha","user":"ops","local":"./app","remote":"/tmp/app","bytes":1234}
```

Every single-object `--json` success response (`add`, `show`, `trust`, `run`, `put`, `get`, `remove`, `doctor`, `account add`, `account show`, `account remove`, `profile show`, `privilege set`, `privilege show`, `privilege clear`) includes `"ok":true`, mirroring the `"ok":false` error envelope so a consumer can branch on `ok`. `list`, `account list`, and `profile list` return a JSON array on success (no wrapping object); on failure they emit the same `{"ok":false,...}` envelope.

`default`, `account default`, profile state changes, and all policy subcommands support `--json`. Existing list commands retain their array-on-success format. A completed `run` retains `ok:true` for compatibility; use `command_succeeded` (or `exit_status == 0`) to judge remote success. A policy check uses `allowed`, and doctor uses `local_checks_passed`; each says explicitly that remote connectivity was not tested.

An empty or whitespace-only remote command is an input error (usage/9) in both `run` and `policy check`. Empty local source/destination and remote paths are rejected the same way by `put/get` and `policy check-put/get`, before credentials or SSH are used. Check variables and quote the whole command or path; for example `sshw run web "uptime"` or `sshw put web ./app /srv/app/app`. Values are not trimmed or rewritten, and paths containing spaces, including a filename made only of spaces, remain literal. Existing config/policy loading and server-selection errors retain their precedence.

`--password-stdin` requires redirected stdin, such as a secret-manager pipe or file redirection. When stdin is a terminal, sshw rejects the request before reading a password (auth/4). Omit the option to use hidden terminal input instead. It does not silently switch input methods, and passwords must never appear in arguments. Existing EOF behavior, removal of one final LF/CRLF, embedded login-password newlines, and privilege-password single-line validation remain unchanged.

Doctor's JSON `credential_checks` reports each password-backed login/privilege entry with `server`, login `user`, `purpose`, `status`, `message`, and a `next_step` when needed. Status is `ready` (locally available), `missing` (confirmed entry absence), `unavailable` (lookup failed without confirming absence), or `invalid` (the privilege password is empty or contains CR/LF, as rejected by `run --as-root`). `missing_credentials` retains its array format and includes only confirmed missing login entries. Backend failures call for restoring access and rerunning doctor before re-registration. Agent logins and passwordless privilege settings require no password check. No password value is printed, and local readiness does not confirm remote authentication. Doctor still exits 0 with `ok:true`; inspect `local_checks_passed` and `issues` to decide whether action is required.

Missing operation targets are usage errors (exit 9), rejected before loading the home or writing an audit record. The server name remains optional for `run`/`put`/`get` and their policy checks, but the command or source/destination operands are required. JSON usage messages retain missing argument names, accepted values and correction tips while omitting the full usage banner and generic help footer. Input diagnostics are redacted before rendering; explicit help and version requests still exit 0.

Invalid CLI arguments exit with code `9` (`usage`), kept distinct from `safety` (2) so an agent can tell "called sshw wrong" apart from "a safety rail blocked the operation". With `--json`, a usage error is emitted as the same envelope on stdout (`{"ok":false,"error":{"kind":"usage",...}}`); otherwise the parser's message goes to stderr. `--help`/`--version` print to stdout and exit `0`.

These codes are sshw's own operational failures. When `run` connects and the remote command itself exits non-zero, sshw exits with code `8` — kept separate so a remote status can never be read as an sshw failure (e.g. a remote `grep` finding nothing). Exit `0` means the remote command succeeded. The real remote status is reported in `run --json` as `exit_status`, and in human mode as a `note: remote command exited with status N` line on stderr.

## File Permissions And Atomicity

New `servers.json`, `policy.json`, `audit.jsonl`, profile registry, and mutation lock files are created owner-only on platforms that support it. Config and registry writes finalize permissions and sync the temporary file before atomic rename, then sync the parent directory where supported. If the rename succeeds but parent sync fails, sshw reports that the state was published but durability was not confirmed; credential updates retain both generations instead of deleting a key that either the old or new config may need after a crash. On Windows, permissions and directory sync are best-effort (NTFS ACLs on the per-user directory provide the protection).

Cooperating `sshw` processes serialize home mutations with `.sshw.lock`, profile registry mutations with `.profiles.lock`, and complete audit records by locking `audit.jsonl`. A state-mutation lock waits at most 5 seconds before returning an actionable config error; audit uses the shorter best-effort bound above. Config and registry writes also reject a stale loaded revision. These locks are advisory: another program or same-user process that ignores them can still race or edit the files, so this is coordination rather than tamper protection.

## Release Verification

Tagged releases build GitHub release artifacts for `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`. Each release includes a `SHA256SUMS` file. Release workflows pin GitHub Actions by commit SHA and the release compiler to Rust 1.97.0. ZIP and tar.gz packaging uses deterministic archive metadata derived from the release commit timestamp, so the same binary and timestamp produce the same archive bytes. This is not a claim that separately compiled binaries are bit-for-bit reproducible; see `SECURITY.md`.

Release artifacts are also published with GitHub Artifact Attestations. Checksums verify file integrity; attestations verify build provenance (repository, workflow, commit, and event). From a directory containing the downloaded release assets:

```bash
gh release download vX.Y.Z --repo Lv2dev/sshw
sha256sum -c SHA256SUMS

for artifact in sshw-*.tar.gz sshw-*.zip SHA256SUMS; do
  gh attestation verify "$artifact" -R Lv2dev/sshw
done
```
