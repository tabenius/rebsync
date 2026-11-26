//! Headless operation: `rbq peer serve` configured only by environment,
//! devices paired without prompts (stdin closed), and a clean exit on
//! SIGTERM, as a service manager would run it.
#![cfg(all(unix, feature = "peer"))]

use std::{
    io::Read,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const RBQ: &str = env!("CARGO_BIN_EXE_rbq");

/// rbq as a separate device: its own home and state, nothing interactive.
fn device(home: &Path) -> Command {
    let mut command = Command::new(RBQ);
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_STATE_HOME", home.join(".state"))
        .env("XDG_DATA_HOME", home.join(".data"))
        .stdin(Stdio::null());
    command
}

fn json(output: std::process::Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "rbq failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON on stdout")
}

/// Read the server's startup JSON (pretty-printed, so possibly several reads).
fn startup(child: &mut Child) -> serde_json::Value {
    let stdout = child.stdout.as_mut().unwrap();
    let mut text = Vec::new();
    let mut buffer = [0_u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        assert!(Instant::now() < deadline, "server printed no startup JSON");
        let n = stdout.read(&mut buffer).unwrap();
        assert!(n > 0, "server exited: {}", String::from_utf8_lossy(&text));
        text.extend_from_slice(&buffer[..n]);
        if let Ok(value) = serde_json::from_slice(&text) {
            return value;
        }
    }
}

#[test]
fn serve_from_environment_pair_without_prompts_and_stop_on_sigterm() {
    let root = tempfile::tempdir().unwrap();
    let (phone, laptop) = (root.path().join("phone"), root.path().join("laptop"));
    std::fs::create_dir_all(&phone).unwrap();
    std::fs::create_dir_all(&laptop).unwrap();

    // The server is configured entirely by environment: no token at all,
    // only paired devices will get in.
    let mut server = device(&phone)
        .args(["peer", "serve"])
        .env("RBQ_LISTEN", "quic://127.0.0.1:0")
        .env("RBQ_QUIC_IDENTITY", phone.join("identity"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = startup(&mut server);
    let serving = started["serving"][0].as_str().unwrap().to_owned();
    let port: u16 = serving.rsplit(':').next().unwrap().parse().unwrap();
    let pin = started["quic_peer_id"].as_str().unwrap().to_owned();

    // Invitations are created by the same device, from its identity.
    let invite = json(
        device(&phone)
            .args(["peer", "pair", "invite", "--name", "phone", "--port"])
            .arg(port.to_string())
            .env("RBQ_QUIC_IDENTITY", phone.join("identity"))
            .output()
            .unwrap(),
    );
    let connection = invite["connect"][0]["connection"]
        .as_str()
        .unwrap()
        .replace("HOST", "127.0.0.1");
    assert!(connection.contains(&pin));

    // The laptop pairs on first use, with stdin closed, and then uses the
    // pairing by name.
    let status = json(
        device(&laptop)
            .args(["--json", "peer", "status"])
            .arg(&connection)
            .output()
            .unwrap(),
    );
    assert_eq!(status["peer"]["protocol"], "rbq-peer/1");
    let named = json(
        device(&laptop)
            .args(["--json", "peer", "status", "paired:phone"])
            .output()
            .unwrap(),
    );
    assert_eq!(named["peer"]["protocol"], "rbq-peer/1");

    // SIGTERM, as systemd sends it: a clean, prompt exit with status 0.
    let stopped_at = Instant::now();
    assert!(
        Command::new("kill")
            .args(["-TERM", &server.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let status = server.wait().unwrap();
    assert!(status.success(), "{status:?}");
    assert!(stopped_at.elapsed() < Duration::from_secs(10));
    let mut stderr = String::new();
    server
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(stderr.contains("\"stopped\":true"), "{stderr}");
}
