#![cfg(windows)]

#[test]
fn confirmation_accepts_input_after_password_is_interrupted() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/windows_confirmation.py");
    let output = std::process::Command::new("python")
        .args(["-X", "utf8"])
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_sshw"))
        .output()
        .expect("Python 3 is required for the isolated Windows console regression");
    assert!(
        output.status.success(),
        "Windows console regression failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
