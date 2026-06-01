# Security Policy

## Supported Versions

Security fixes target the latest released version of `sshw`.

## Reporting A Vulnerability

Please report suspected vulnerabilities privately through GitHub Security Advisories for this repository.

Do not include real server passwords, private keys, passphrases, tokens, production hostnames, or production IP addresses in public issues.

## Security Model

`sshw` is a **sandbox-aware SSH wrapper**, not a strong OS sandbox. It is designed to keep SSH secrets out of prompts, shell history, plaintext config, normal output, and JSON output, and it adds:

- **Profile/home isolation.** Config, `known_hosts`, policy, audit log, and the credential keyring namespace are scoped to the active home (`--home`, `SSHW_HOME`, `--profile`, or the built-in default). Distinct profiles never share a credential namespace.
- **Optional policy enforcement.** Off by default. When enabled (via `--policy` or `policy.json` `enabled`), `run` commands and `put`/`get` paths must match allowlists; denials return exit code 7 and policy enforcement fails closed (a missing-when-required or unparseable policy file is an error).
- **Append-only audit log.** Mutating/active operations are recorded as JSONL in the home's `audit.jsonl`.
- **Output and audit redaction.** Best-effort masking of secret-looking strings.

Credentials: password authentication stores secrets only through the native OS credential store, or — opt-in — a session-only in-memory backend that never persists and reads `SSHW_PASSWORD` at run time, then removes it from this process environment. `add --password-stdin` may read the initial registration password from stdin and store it in the active credential backend; `sshw` intentionally does not provide a `--password <value>` argument. The session-only backend applies that single `SSHW_PASSWORD` to whichever server the invocation targets, so it does not provide the per-server credential-namespace isolation the native backend does. SSH agent authentication stores no secret in `sshw`.

## Release Integrity And Provenance

Tagged releases publish platform archives plus `SHA256SUMS`. The checksum file lets users verify that downloaded bytes match the release manifest.

Release assets are also covered by GitHub Artifact Attestations. The platform archives are attested in the release `build` jobs, and `SHA256SUMS` is attested in the `publish` job. Users can verify provenance with GitHub CLI:

```bash
gh release download vX.Y.Z --repo Lv2dev/sshw
sha256sum -c SHA256SUMS
gh attestation verify sshw-x86_64-unknown-linux-gnu.tar.gz -R Lv2dev/sshw
```

Attestations establish where and how an artifact was built (repository, workflow, commit, and event). They do not prove the artifact is vulnerability-free or safe to run in a particular environment; consumers still need to evaluate the release contents and their own policy.

`sshw doctor` reports the libssh2 and OpenSSL version/status that the current binary was built to use. This is diagnostic evidence for vulnerability triage, not a security guarantee and not a replacement for checksum or attestation verification. On Windows default builds, OpenSSL may be reported as not linked because libssh2 uses the Windows WinCNG backend.

## Limitations (Not Guarantees)

These are explicitly **not** strong guarantees:

- **Delegated access, not isolation.** Anything allowed to run `sshw run` has the configured account's server authority. A local process running as the same OS user may access the OS credential store directly.
- **Command allowlist delegates whole-program execution.** `allow_commands` matches the program name, not its arguments. Allowlisting a program is equivalent to delegating that program's full remote capability: it may read or write any file the SSH account can reach, interpret dangerous flags, or spawn subprocesses through its own features. Be especially careful with shells and interpreters (`sh`, `bash`, `python`, `perl`), file readers/copy tools (`cat`, `tar`, `find`, `rsync`, `scp`), and privilege/process tools (`sudo`, service managers). `allow_commands` is therefore a strictly stronger grant than `allow_get_paths`/`allow_put_paths`. Prefer narrow exact commands such as `uptime` or `systemctl status app`, and only allowlist programs you trust with arbitrary arguments.
- **Redaction is best-effort.** Output and audit redaction catch PEM private-key blocks, `keyword=value`/`keyword: value` for common secret keywords, and bearer tokens. They do not understand shell syntax, so secrets passed as flag values (`-p`, `-a`, `-u user:pass`, bare positional tokens) or split across lines may not be masked. Masking also applies only to the text *after* the matched keyword on a line, so a secret appearing before its keyword is not masked. Do not pass secrets inline on the command line. The `run` audit record stores only the program name to avoid persisting inline secrets, but treat `audit.jsonl` as sensitive regardless.
- **Environment variables are not a secret store.** The session-only backend removes `SSHW_PASSWORD` from `sshw`'s process environment immediately after reading it, but the value may already be visible to the parent shell, process launch metadata, shell history, or platform diagnostics. Prefer the native credential store for long-lived secrets.
- **stdin avoids argv, not every producer leak.** `add --password-stdin` keeps the registration password out of command-line arguments and shell history, strips one final LF/CRLF, and rejects empty input. The process that produces stdin can still expose the secret through its own logs, shell history, or diagnostics, so prefer a secret manager command over inline literals.
- **File protections are best-effort on Windows.** State files are created owner-only on Unix; on Windows protection relies on the per-user directory's NTFS ACLs. The audit log is plaintext.
- **Non-ASCII home paths break `known_hosts` on Windows.** `known_hosts` is read and written through libssh2's C file API, which on Windows resolves the path via the system ANSI code page rather than wide UTF-16. If the active home path contains non-ASCII characters (for example a non-ASCII Windows account name under `%APPDATA%`), `known_hosts` access can fail and `trust`/`run`/`put`/`get` fail closed — host-key verification cannot proceed — even though `servers.json` and other state (handled by Rust's wide file APIs) read fine. Use an ASCII home path via `--home`/`SSHW_HOME` on affected systems.
- **No OS-level sandboxing.** `sshw` does not constrain the remote host or the local process beyond the policy allowlist. Stronger per-OS sandbox backends are a possible future extension behind the existing `Sandbox` trait.
- **No concurrent-write coordination.** State files are written atomically, so a half-written file is never observed, but there is no cross-process locking. Two `sshw` processes mutating the same home's `servers.json`, profile registry, or policy file concurrently will silently lose one update (last writer wins). Run mutating commands one at a time per home.

## Stable Exit Codes

sshw's own failures map to stable exit codes for agent consumption: `2` safety, `3` config, `4` auth, `5` ssh, `6` io, `7` policy, `9` usage (invalid CLI arguments, detected before any command runs; kept distinct from safety/2), `1` unknown. A successful `run` whose remote command exits non-zero returns `8` — kept distinct from the operational codes so a remote command's status can never be mistaken for an sshw failure. The real remote status is available via `run --json` (`exit_status`).
