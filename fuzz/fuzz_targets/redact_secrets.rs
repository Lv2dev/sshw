#![no_main]

use libfuzzer_sys::fuzz_target;
use sshw::output::redact_secrets;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let once = redact_secrets(input);
    let twice = redact_secrets(&once);

    assert_eq!(once, twice);
});
