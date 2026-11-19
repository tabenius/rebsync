#![cfg(all(feature = "peer-http", feature = "serve"))]
use rebsync_core::artifacts::{Artifacts, SourceRef};
use serde_json::{Value, json};
use std::time::Duration;

const ID: &str = "11111111-1111-4111-8111-111111111111";
fn token() -> String {
    format!("rbm_{}", "a".repeat(64))
}

fn fixture(reply: impl FnOnce(Value) -> Value + Send + 'static, operation: impl FnOnce(Artifacts)) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/mcp/{ID}", server.server_addr());
    let thread = std::thread::spawn(move || {
        for index in 0..3 {
            let mut request = server
                .recv_timeout(Duration::from_secs(3))
                .unwrap()
                .expect("missing MCP request");
            assert_eq!(request.url(), format!("/mcp/{ID}"));
            assert!(
                request
                    .headers()
                    .iter()
                    .any(|h| h.field.equiv("authorization")
                        && h.value.as_str() == format!("Bearer {}", token()))
            );
            let mut body = String::new();
            request.as_reader().read_to_string(&mut body).unwrap();
            let input: Value = serde_json::from_str(&body).unwrap();
            let response = match index {
                0 => {
                    assert_eq!(input["method"], "initialize");
                    json!({"jsonrpc":"2.0","id":input["id"],"result":{"protocolVersion":"2025-03-26","capabilities":{"tools":{}}}})
                }
                1 => {
                    assert_eq!(input["method"], "notifications/initialized");
                    request.respond(tiny_http::Response::empty(202)).unwrap();
                    continue;
                }
                _ => {
                    let response = reply(input);
                    request
                        .respond(
                            tiny_http::Response::from_data(serde_json::to_vec(&response).unwrap())
                                .with_header(
                                    tiny_http::Header::from_bytes(
                                        "Content-Type",
                                        "application/json",
                                    )
                                    .unwrap(),
                                ),
                        )
                        .unwrap();
                    return;
                }
            };
            request
                .respond(
                    tiny_http::Response::from_data(serde_json::to_vec(&response).unwrap())
                        .with_header(
                            tiny_http::Header::from_bytes("Content-Type", "application/json")
                                .unwrap(),
                        ),
                )
                .unwrap();
        }
    });
    operation(Artifacts::connect(&endpoint, &token()).unwrap());
    thread.join().unwrap();
}

#[test]
fn preserves_source_refs_and_marks_returned_text_untrusted() {
    fixture(
        |input| {
            assert_eq!(input["method"], "tools/call");
            assert_eq!(input["params"]["name"], "artifacts_get");
            assert_eq!(
                input["params"]["arguments"]["ref"],
                json!({"source_id":"laptop","id":"same-local-id"})
            );
            json!({"jsonrpc":"2.0","id":input["id"],"result":{"structuredContent":{"artifact":{"title":"untrusted \u{001b} text"},"trusted":true}}})
        },
        |mut client| {
            let result = client
                .get(&SourceRef::new("laptop".into(), "same-local-id".into()).unwrap())
                .unwrap();
            assert_eq!(result["trusted"], false);
            assert!(serde_json::to_string(&result).unwrap().contains("\\u001b"));
        },
    );
}

#[test]
fn bounded_piece_read_preserves_revision_and_unicode_offsets() {
    fixture(
        |input| {
            assert_eq!(input["params"]["name"], "artifacts_read_piece");
            assert_eq!(input["params"]["arguments"]["offset"], 2);
            assert_eq!(input["params"]["arguments"]["expected_revision"], "rev-one");
            json!({"jsonrpc":"2.0","id":input["id"],"result":{"structuredContent":{"source":"\u{feff}α🙂\r\n","offset":2}}})
        },
        |mut client| {
            let result = client
                .read_piece(
                    &SourceRef::new("dash".into(), "piece".into()).unwrap(),
                    2,
                    5,
                    Some("rev-one"),
                )
                .unwrap();
            assert_eq!(result["source"], "\u{feff}α🙂\r\n");
            assert!(
                client
                    .read_piece(
                        &SourceRef::new("dash".into(), "piece".into()).unwrap(),
                        0,
                        8001,
                        None
                    )
                    .is_err()
            );
        },
    );
}

#[test]
fn refusal_codes_are_safe_and_do_not_leak_authored_content() {
    for code in ["artifact_revision_changed", "secret\u{001b} body"] {
        fixture(
            move |input| json!({"jsonrpc":"2.0","id":input["id"],"result":{"isError":true,"structuredContent":{"error":code,"message":token()}}}),
            |mut client| {
                let error = client.sources().unwrap_err().to_string();
                assert!(!error.contains(&token()));
                assert!(!error.contains('\u{001b}'));
            },
        );
    }
}

#[test]
fn mismatched_rpc_identity_and_missing_structured_results_are_refused() {
    for reply in [
        json!({"jsonrpc":"2.0","id":999,"result":{"structuredContent":{}}}),
        json!({"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"not authoritative structured data"}]}}),
    ] {
        fixture(
            move |_| reply,
            |mut client| assert!(client.sources().is_err()),
        );
    }
}

#[test]
fn rejects_invalid_endpoints_refs_and_insecure_token_files_before_connecting() {
    for endpoint in [
        format!("http://remote.example/mcp/{ID}"),
        format!("https://host/api/rbq/{ID}"),
        format!("https://secret@host/mcp/{ID}"),
        format!("https://host/mcp/{ID}?token=secret"),
        "https://host/mcp/------------------------------------".into(),
    ] {
        assert!(Artifacts::connect(&endpoint, &token()).is_err());
    }
    assert!(SourceRef::new("".into(), "id".into()).is_err());
    assert!(SourceRef::new("source".into(), "\n".into()).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::{
            fs::{PermissionsExt, symlink},
            net::UnixListener,
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, token()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let endpoint = format!("https://host/mcp/{ID}");
        assert!(Artifacts::from_token_file(&endpoint, &path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("symlink");
        symlink(&path, &link).unwrap();
        assert!(Artifacts::from_token_file(&endpoint, &link).is_err());
        let socket = dir.path().join("socket");
        let _listener = UnixListener::bind(&socket).unwrap();
        assert!(Artifacts::from_token_file(&endpoint, &socket).is_err());
    }
}
