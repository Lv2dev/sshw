# Contributing to sshw

Thank you for helping improve sshw. Keep changes focused, preserve the documented
CLI and exit-code contracts, and include regression coverage for behavior changes.

## Security Issues

Do not open a public issue for a suspected vulnerability. Report it privately with
a GitHub Security Advisory for this repository, following `SECURITY.md`.

Never include real credentials, hostnames, IP addresses, account names, private
keys, tokens, passphrases, `servers.json`, `known_hosts`, or `audit.jsonl` content
in an issue, pull request, test fixture, screenshot, or log. Use synthetic values.

## Development Setup

Install Rust 1.89 or newer and Python 3, then clone the repository and verify the
locked dependency graphs before making changes. Python 3 is required by the
deterministic ZIP/tar.gz packaging regression in the normal Rust test suite.

```bash
cargo metadata --locked --format-version 1
cargo metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1
```

## Making Changes

1. Keep the patch limited to one coherent problem.
2. Add a regression test that fails without the change.
3. Preserve stable JSON fields and exit codes unless the change is explicitly a
   documented compatibility break.
4. Update `README.md`, `SECURITY.md`, and `CHANGELOG.md` when their contracts or
   security claims change.

Use only synthetic SSH endpoints and credentials in tests. Integration tests that
need a real SSH server must remain opt-in and isolated from personal infrastructure.

## Local Verification

Run the same core checks used by CI:

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo deny --locked check
cargo deny --locked --manifest-path fuzz/Cargo.toml check
```

Also run relevant ignored integration tests when changing SSH transport, host-key,
authentication, privilege, or transfer behavior. State which checks were not run
and why in the pull request.

## Pull Requests

Describe the user-visible behavior, security implications, tests, and documentation
changes. Small, reviewable commits are preferred, but no particular commit format
is required. A maintainer may ask for changes when a patch expands the trust boundary
or leaves a regression path untested.
