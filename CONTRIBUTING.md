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
locked dependency graphs before making changes. The normal Rust test suite uses
Python 3 for deterministic ZIP/tar.gz packaging and, on Windows, the isolated
console-input regression.

```bash
cargo metadata --locked --format-version 1
cargo metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1
```

## Making Changes

1. Keep the patch limited to one coherent problem.
2. Add a regression test that fails without the change.
3. Preserve stable JSON fields and exit codes unless the change is explicitly a
   documented compatibility break.
4. Update both language sections in `README.md`, the corresponding `docs/reference*.md`,
   `SECURITY.md`, and `CHANGELOG.md` when their contracts or security claims change.
   Keep the README focused on first use and common tasks; put exact options,
   configuration compatibility and failure contracts in the reference documents.

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

## Releases

Release tags must match the version in `Cargo.toml`. After the release changes
have been reviewed, verified and approved, create and push the new tag:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

This triggers the release workflow, not a local installation. The workflow uses
the protected `release` environment, Rust 1.97.0, and pinned GitHub Actions to
verify, build platform archives, attest them and publish the release/package.
Do not move an existing release tag. See the [release verification reference](docs/reference.md#release-verification)
for archive metadata, checksums and attestation checks.
