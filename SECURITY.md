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

Credentials: password authentication stores secrets only through the native OS credential store, or — opt-in — a session-only in-memory backend that never persists and reads `SSHW_PASSWORD` at run time. SSH agent authentication stores no secret in `sshw`.

## Limitations (Not Guarantees)

These are explicitly **not** strong guarantees:

- **Delegated access, not isolation.** Anything allowed to run `sshw run` has the configured account's server authority. A local process running as the same OS user may access the OS credential store directly.
- **Command allowlist is program-name based.** `allow_commands` matches the program name, not its arguments. Allowlisting a program (e.g. `cat`, `tar`, `find`, `perl`) grants its full capability, including reading or writing any file it can reach and any subprocess it can spawn via its own flags. `allow_commands` is therefore a strictly stronger grant than `allow_get_paths`/`allow_put_paths`. Only allowlist programs you trust with arbitrary arguments.
- **Redaction is best-effort.** Output and audit redaction catch PEM private-key blocks, `keyword=value`/`keyword: value` for common secret keywords, and bearer tokens. They do not understand shell syntax, so secrets passed as flag values (`-p`, `-a`, `-u user:pass`, bare positional tokens) or split across lines may not be masked. Do not pass secrets inline on the command line. The `run` audit record stores only the program name to avoid persisting inline secrets, but treat `audit.jsonl` as sensitive regardless.
- **File protections are best-effort on Windows.** State files are created owner-only on Unix; on Windows protection relies on the per-user directory's NTFS ACLs. The audit log is plaintext.
- **No OS-level sandboxing.** `sshw` does not constrain the remote host or the local process beyond the policy allowlist. Stronger per-OS sandbox backends are a possible future extension behind the existing `Sandbox` trait.

## Stable Exit Codes

Failures map to stable exit codes for agent consumption: `2` safety, `3` config, `4` auth, `5` ssh, `6` io, `7` policy, `1` unknown.
