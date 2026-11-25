//! The phone's Dash pairing (src-tauri/src/dash_link.rs) against a small
//! stand-in for Dash's pairing API on loopback. Dash's real Worker is
//! exercised with the rbq CLI in RAGBAZ/ragbaz-dash (test/rbq-pairing-cli).
use rebeqah_logic_tests::dash_link::DashLink;
use rebsync_core::dash_pairing::{State, matching_code};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Fake {
    nonce_sha256: Option<String>,
    approved: bool,
    claimed: bool,
    cancelled: bool,
    token: Option<String>,
}

const KEY: &str = "11111111-2222-4333-8444-555555555555";
const REPO: &str = "99999999-8888-4777-8666-555555555555";

fn sha(text: &str) -> String {
    rebsync_core::wire::sha256_hex(text.as_bytes())
}

/// A stand-in Dash: the pairing routes, plus the repository descriptor for
/// the issued credential.
fn fake_dash() -> (String, Arc<Mutex<Fake>>) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", server.server_addr().to_ip().unwrap());
    let state = Arc::new(Mutex::new(Fake::default()));
    let (shared, base) = (state.clone(), origin.clone());
    std::thread::spawn(move || {
        for mut request in server.incoming_requests() {
            let mut body = String::new();
            let _ = request.as_reader().read_to_string(&mut body);
            let url = request.url().to_owned();
            let json: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            let mut fake = shared.lock().unwrap();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let (status, reply) = match (request.method().as_str(), url.as_str()) {
                ("POST", "/api/rbq-pairing/requests") => {
                    let id = json["pairing_id"].as_str().unwrap().to_owned();
                    let hash = json["nonce_sha256"].as_str().unwrap().to_owned();
                    assert!(body.len() < 2048 && !body.contains("nonce\":"), "only the nonce's hash is sent");
                    fake.nonce_sha256 = Some(hash.clone());
                    (201, serde_json::json!({"pairing_id": id, "state": "pending", "expires_at": now + 600,
                        "matching_code": matching_code(&id, &hash), "approval_url": format!("{base}/pair/{id}")}))
                }
                ("GET", path) if path.starts_with("/api/rbq-pairing/requests/") => {
                    let state = if fake.cancelled { "cancelled" } else if fake.claimed { "claimed" } else if fake.approved { "approved" } else { "pending" };
                    (200, serde_json::json!({"state": state, "expires_at": now + 600}))
                }
                ("POST", path) if path.ends_with("/claim") => {
                    let ok = fake.approved && !fake.claimed
                        && json["nonce"].as_str().map(sha) == fake.nonce_sha256;
                    if ok {
                        fake.claimed = true;
                        let token = format!("rbs_{}", "ab".repeat(32));
                        fake.token = Some(token.clone());
                        (201, serde_json::json!({"key_id": KEY, "token": token, "token_type": "bearer",
                            "scopes": ["describe", "list", "read"], "expires_at": now + 86400,
                            "device_label": "phone", "repository_id": REPO}))
                    } else {
                        (409, serde_json::json!({"error": "not_claimable"}))
                    }
                }
                ("POST", path) if path.ends_with("/cancel") => {
                    fake.cancelled = true;
                    (200, serde_json::json!({"state": "cancelled"}))
                }
                ("GET", path) if path == format!("/api/rbq/{KEY}") => {
                    let auth = request.headers().iter().find(|h| h.field.equiv("authorization")).map(|h| h.value.to_string());
                    if auth == fake.token.as_ref().map(|t| format!("Bearer {t}")) {
                        (200, serde_json::json!({"schema": "ragbaz.rbq-repository.v1", "private": true, "repository_id": REPO,
                            "capabilities": {"list": true, "read": true, "append": false}}))
                    } else {
                        (401, serde_json::json!({"error": "authentication_required"}))
                    }
                }
                _ => (404, serde_json::json!({"error": "not_found"})),
            };
            drop(fake);
            let _ = request.respond(
                tiny_http::Response::from_string(reply.to_string())
                    .with_status_code(status)
                    .with_header("content-type: application/json".parse::<tiny_http::Header>().unwrap()),
            );
        }
    });
    (origin, state)
}

#[test]
fn the_phone_pairs_collects_its_credential_once_and_can_use_it() {
    let (dash, fake) = fake_dash();
    let dir = tempfile::tempdir().unwrap();
    let link = DashLink::open(dir.path(), None).unwrap();
    let begun = link.begin(&dash, "Rebeqah phone", true, 30).unwrap();
    assert_eq!(begun.approval_url, format!("{dash}/pair/{}", begun.pairing_id));
    assert_eq!(begun.matching_code.len(), 9);
    assert_eq!(link.pending().len(), 1);

    // Not approved yet: nothing to collect.
    let progress = link.poll(&begun.pairing_id).unwrap();
    assert_eq!(progress.state, State::Pending);
    assert!(progress.credential.is_none());

    fake.lock().unwrap().approved = true;
    let progress = link.poll(&begun.pairing_id).unwrap();
    assert_eq!(progress.state, State::Claimed);
    let credential = progress.credential.unwrap();
    assert_eq!(credential.id, KEY);
    assert_eq!(credential.audience.endpoint, format!("{dash}/api/rbq/{KEY}"));
    assert!(link.pending().is_empty(), "the pending pairing is gone once stored");

    // Metadata only, everywhere the web view can see.
    let token = fake.lock().unwrap().token.clone().unwrap();
    let listed = serde_json::to_string(&link.credentials().unwrap()).unwrap();
    assert!(!listed.contains(&token));
    assert!(!serde_json::to_string(&credential).unwrap().contains(&token));

    let checked = link.check(KEY).unwrap();
    assert_eq!(checked["matches"], true);
    assert!(!checked.to_string().contains(&token));

    // Forgotten on the phone: no further use.
    link.forget(KEY).unwrap();
    assert!(link.check(KEY).is_err());
}

#[test]
fn a_cancelled_pairing_ends_cleanly_and_a_bad_dash_is_refused() {
    let (dash, fake) = fake_dash();
    let dir = tempfile::tempdir().unwrap();
    let link = DashLink::open(dir.path(), None).unwrap();
    let begun = link.begin(&dash, "phone", false, 1).unwrap();
    assert_eq!(link.cancel(&begun.pairing_id).unwrap(), State::Cancelled);
    assert!(fake.lock().unwrap().cancelled);
    assert!(link.pending().is_empty());
    assert!(link.poll(&begun.pairing_id).is_err(), "nothing left to poll");

    for bad in ["http://dash.example", "https://dash.example/path", "not a url"] {
        assert!(link.begin(bad, "phone", false, 30).is_err(), "{bad}");
    }
    assert!(link.begin(&dash, " padded", false, 30).is_ok(), "labels are trimmed");
    assert!(link.begin(&dash, "phone", false, 91).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join("dash-credentials")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}
