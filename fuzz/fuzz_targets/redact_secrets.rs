#![no_main]

use libfuzzer_sys::fuzz_target;
use sshw::output::redact_secrets;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    // Stability invariant: redaction is idempotent.
    let once = redact_secrets(input);
    let twice = redact_secrets(&once);
    assert_eq!(once, twice);

    // Security invariant: any value placed as a sensitive keyword assignment is
    // removed by redaction. Build a single-line probe with no whitespace,
    // quotes, or separators from the fuzz input so the assignment is
    // unambiguous, then confirm the value never survives.
    let probe: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_control() && !matches!(c, '"' | '\'' | '=' | ':'))
        .take(48)
        .collect();
    if probe.len() >= 4 {
        let value = format!("ZZ{probe}ZZ");
        for keyword in ["password", "api_key", "authorization"] {
            let line = format!("{keyword}={value}");
            let redacted = redact_secrets(&line);
            assert!(
                !redacted.contains(&value),
                "sensitive value survived redaction: keyword={keyword} line={line:?} -> {redacted:?}"
            );
        }
    }
});
