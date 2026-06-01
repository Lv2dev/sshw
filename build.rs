use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=DEP_SSH2_INCLUDE");
    println!("cargo:rerun-if-env-changed=DEP_OPENSSL_INCLUDE");
    println!("cargo:rerun-if-env-changed=DEP_OPENSSL_VERSION_NUMBER");

    let version = libssh2_header_version().unwrap_or_else(|| "unavailable".to_string());
    println!("cargo:rustc-env=SSHW_LIBSSH2_VERSION={version}");

    let version = openssl_header_version().unwrap_or_else(openssl_unavailable_message);
    println!("cargo:rustc-env=SSHW_OPENSSL_VERSION={version}");
}

fn libssh2_header_version() -> Option<String> {
    let include_paths = std::env::var_os("DEP_SSH2_INCLUDE")?;

    for include_path in std::env::split_paths(&include_paths) {
        let header = include_path.join("libssh2.h");
        if let Some(version) = version_from_header(&header) {
            println!("cargo:rerun-if-changed={}", header.display());
            return Some(version);
        }
    }

    None
}

fn version_from_header(header: &Path) -> Option<String> {
    let contents = fs::read_to_string(header).ok()?;
    contents
        .lines()
        .find_map(|line| parse_c_string_macro(line, "LIBSSH2_VERSION"))
}

fn openssl_header_version() -> Option<String> {
    let include_paths = std::env::var_os("DEP_OPENSSL_INCLUDE")?;

    for include_path in std::env::split_paths(&include_paths) {
        let header = include_path.join("openssl").join("opensslv.h");
        if let Ok(contents) = fs::read_to_string(&header)
            && let Some(version) = contents
                .lines()
                .find_map(|line| parse_c_string_macro(line, "OPENSSL_VERSION_TEXT"))
        {
            println!("cargo:rerun-if-changed={}", header.display());
            return Some(version);
        }
    }

    std::env::var("DEP_OPENSSL_VERSION_NUMBER")
        .ok()
        .map(|version| format!("OpenSSL version number 0x{version}"))
}

fn openssl_unavailable_message() -> String {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        "not linked (Windows WinCNG backend)".to_string()
    } else {
        "unavailable".to_string()
    }
}

fn parse_c_string_macro(line: &str, name: &str) -> Option<String> {
    let line = line.trim();
    let value = line
        .strip_prefix("#define")
        .or_else(|| line.strip_prefix("# define"))?
        .trim_start()
        .strip_prefix(name)?
        .trim();
    let value = value.strip_prefix('"')?;
    let end = value.find('"')?;
    Some(value[..end].to_string())
}
