# Security Policy

## Supported Versions

Security fixes target the latest released version of `sshw`.

## Reporting A Vulnerability

Please report suspected vulnerabilities privately through GitHub Security Advisories for this repository.

Do not include real server passwords, private keys, passphrases, tokens, production hostnames, or production IP addresses in public issues.

## Security Boundary

`sshw` is delegated access, not a sandbox. It is designed to keep SSH secrets out of prompts, shell history, plaintext config, normal output, and JSON output. A local process running as the same OS user may still attempt to access the native OS credential store directly.

Password authentication stores secrets only through the native OS credential store. SSH agent authentication stores no secret in `sshw`.
