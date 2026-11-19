#![cfg(all(feature = "peer-http", feature = "serve"))]
use rebsync_core::repository::{Repository, read_input, write_output};
use sha2::{Digest, Sha256};
use std::time::Duration;

const ID: &str = "11111111-1111-4111-8111-111111111111";
fn token() -> String {
    format!("rbm_{}", "a".repeat(64))
}

fn response_test(
    status: u16,
    headers: Vec<(&str, String)>,
    body: Vec<u8>,
    op: impl FnOnce(Repository),
) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/api/rbq/{ID}", server.server_addr());
    let headers: Vec<_> = headers
        .into_iter()
        .map(|(k, v)| tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()).unwrap())
        .collect();
    let thread = std::thread::spawn(move || {
        if let Some(request) = server.recv_timeout(Duration::from_secs(3)).unwrap() {
            assert_eq!(
                request
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("authorization"))
                    .unwrap()
                    .value
                    .as_str(),
                format!("Bearer {}", token())
            );
            let mut response = tiny_http::Response::from_data(body).with_status_code(status);
            for header in headers {
                response.add_header(header);
            }
            request.respond(response).unwrap();
        } else {
            panic!("client did not send a request");
        }
    });
    op(Repository::connect(&endpoint, &token()).unwrap());
    thread.join().unwrap();
}

#[test]
fn refuses_insecure_or_credential_bearing_urls_and_unsafe_keys() {
    for endpoint in [
        format!("http://example.com/api/rbq/{ID}"),
        format!("https://secret@host/api/rbq/{ID}"),
        format!("https://host/api/rbq/{ID}?token=secret"),
        format!("https://host/api/rbq/{ID}#secret"),
        "https://host/other".into(),
    ] {
        assert!(Repository::connect(&endpoint, &token()).is_err());
    }
    let repo = Repository::connect(&format!("https://host/api/rbq/{ID}"), &token()).unwrap();
    for key in ["../escape", "a//b", "a/%2Fsecret", "/absolute", "a/"] {
        assert!(repo.read(key).is_err());
        assert!(repo.append(key, b"x").is_err());
    }
    assert!(repo.list("/bad", None, 20).is_err());
    assert!(repo.list("", None, 101).is_err());
    assert!(repo.append("valid", &vec![0; 262145]).is_err());
}

#[test]
fn binary_reads_verify_digests_and_reject_corruption() {
    let bytes = vec![0, 255, 128, 13, 10];
    let hash = format!("{:x}", Sha256::digest(&bytes));
    response_test(
        200,
        vec![("x-content-sha256", hash)],
        bytes.clone(),
        |repo| assert_eq!(repo.read("binary").unwrap(), bytes),
    );
    response_test(
        200,
        vec![("x-content-sha256", "0".repeat(64))],
        b"wrong".to_vec(),
        |repo| assert!(repo.read("binary").is_err()),
    );
    response_test(200, vec![], b"missing digest".to_vec(), |repo| {
        assert!(repo.read("binary").is_err())
    });
}

#[test]
fn errors_and_redirects_never_expose_response_bodies_or_follow_redirects() {
    for status in [302, 401, 404, 409, 413, 500] {
        response_test(
            status,
            vec![("location", "http://127.0.0.1:1/leak".into())],
            token().into_bytes(),
            |repo| {
                let error = repo.describe().unwrap_err().to_string();
                assert!(!error.contains(&token()));
            },
        );
    }
}

#[test]
fn appends_check_the_acknowledged_key_size_and_digest() {
    let bytes = b"private";
    let response = serde_json::to_vec(&serde_json::json!({"key":"note", "size_bytes":bytes.len(), "sha256":format!("{:x}", Sha256::digest(bytes)), "created":true})).unwrap();
    response_test(201, vec![], response, |repo| {
        assert_eq!(repo.append("note", bytes).unwrap()["created"], true)
    });
    response_test(200, vec![], b"{}".to_vec(), |repo| {
        assert!(repo.append("note", bytes).is_err())
    });
}

#[test]
fn output_is_owner_only_and_never_overwrites_local_work() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("download");
    write_output(&path, b"first").unwrap();
    assert!(write_output(&path, b"replacement").is_err());
    // No temporary files are left next to the output, even after a refusal.
    let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".rbq-download-")
        })
        .collect();
    assert!(leftovers.is_empty());
    assert_eq!(read_input(&path).unwrap(), b"first");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Repository::from_token_file(&format!("https://host/api/rbq/{ID}"), &path).is_err());
    }
}
