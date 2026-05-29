use sshw::config::{AuthConfig, ServerConfig};
use sshw::credentials::AuthMaterial;
use sshw::ssh::{HostKeyInfo, RunResult, SshClient, TransferResult};
use std::path::Path;

struct FakeSshClient;

impl SshClient for FakeSshClient {
    fn host_key(&self, _server: &ServerConfig) -> anyhow::Result<HostKeyInfo> {
        Ok(HostKeyInfo {
            algorithm: "ssh-ed25519".to_string(),
            fingerprint_sha256: "SHA256:abc".to_string(),
        })
    }

    fn trust_host(
        &self,
        _server_name: &str,
        _server: &ServerConfig,
        expected_fingerprint_sha256: &str,
    ) -> anyhow::Result<HostKeyInfo> {
        let host_key = self.host_key(_server)?;
        assert_eq!(host_key.fingerprint_sha256, expected_fingerprint_sha256);
        Ok(host_key)
    }

    fn run(
        &self,
        _server: &ServerConfig,
        _auth: &AuthMaterial,
        command: &str,
    ) -> anyhow::Result<RunResult> {
        Ok(RunResult {
            exit_status: 0,
            stdout: command.to_string(),
            stderr: String::new(),
            duration_ms: 1,
        })
    }

    fn put(
        &self,
        _server: &ServerConfig,
        _auth: &AuthMaterial,
        local: &Path,
        remote: &str,
    ) -> anyhow::Result<TransferResult> {
        Ok(TransferResult {
            bytes: 10,
            source: local.display().to_string(),
            destination: remote.to_string(),
        })
    }

    fn get(
        &self,
        _server: &ServerConfig,
        _auth: &AuthMaterial,
        remote: &str,
        local: &Path,
        _overwrite: bool,
    ) -> anyhow::Result<TransferResult> {
        Ok(TransferResult {
            bytes: 10,
            source: remote.to_string(),
            destination: local.display().to_string(),
        })
    }
}

#[test]
fn ssh_client_trait_supports_run_and_transfer_results() {
    let client = FakeSshClient;
    let server = ServerConfig {
        host: "example.test".to_string(),
        port: 22,
        user: "deploy".to_string(),
        auth: AuthConfig::Agent,
    };

    let host_key = client.host_key(&server).unwrap();
    assert_eq!(host_key.algorithm, "ssh-ed25519");

    let run = client
        .run(&server, &AuthMaterial::Agent, "hostname")
        .unwrap();
    assert_eq!(run.exit_status, 0);
    assert_eq!(run.stdout, "hostname");

    let put = client
        .put(
            &server,
            &AuthMaterial::Agent,
            Path::new("local.bin"),
            "/tmp/local.bin",
        )
        .unwrap();
    assert_eq!(put.bytes, 10);

    let get = client
        .get(
            &server,
            &AuthMaterial::Agent,
            "/tmp/local.bin",
            Path::new("local.bin"),
            true,
        )
        .unwrap();
    assert_eq!(get.destination, "local.bin");
}
