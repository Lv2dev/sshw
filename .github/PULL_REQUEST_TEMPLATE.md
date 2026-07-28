## Summary

<!-- What changed, and why? -->

## Security Impact

<!-- Describe trust-boundary, credential, policy, audit, transport, or release impact. Use "None" when applicable. -->

## Verification

- [ ] Regression tests cover the changed behavior
- [ ] `cargo fmt --check`
- [ ] `cargo clippy --locked --all-targets -- -D warnings`
- [ ] `cargo test --locked`
- [ ] Root and fuzz dependency audits, when dependencies or policy changed
- [ ] Relevant ignored integration tests, when SSH behavior changed

## Documentation

- [ ] User-facing and security documentation is updated, or no update is needed
- [ ] `CHANGELOG.md` is updated for a user-visible change
- [ ] No real credentials or private infrastructure details are included
