#![cfg(all(feature = "serve", feature = "storage-object-store"))]
//! restic REST server: protocol and policy tests through the handler, then a
//! real `restic` (skipped when not installed) over HTTP and TLS.
use rebsync_core::restic_rest::{self, Reply, Repository, Request, ResticOptions};
use rebsync_core::storage::{FsObjectStorage, ObjectStorage};
use std::process::Command;
use std::sync::Arc;

const USER: &str = "backup";
const PASSWORD: &str = "correct-horse-battery-staple";

fn sha(bytes: &[u8]) -> String {
    rebsync_core::wire::sha256_hex(bytes)
}

fn basic(user: &str, password: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input = format!("{user}:{password}").into_bytes();
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (*b as u32) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                TABLE[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    format!("Basic {out}")
}

struct Fixture {
    _dir: tempfile::TempDir,
    storage: Arc<dyn ObjectStorage>,
    auth: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn ObjectStorage> =
            Arc::new(FsObjectStorage::open(dir.path().join("store")).unwrap());
        Self {
            _dir: dir,
            storage,
            auth: basic(USER, PASSWORD),
        }
    }
    fn repository(&self, append_only: bool, max_bytes: Option<u64>) -> Repository {
        Repository::new(
            Arc::clone(&self.storage),
            USER,
            PASSWORD,
            append_only,
            max_bytes,
        )
        .unwrap()
    }
}

fn call(repository: &Repository, auth: &str, method: &str, path: &str, body: &[u8]) -> Reply {
    call_with(repository, auth, method, path, body, None, None)
}

fn call_with(
    repository: &Repository,
    auth: &str,
    method: &str,
    path: &str,
    body: &[u8],
    accept: Option<&str>,
    range: Option<&str>,
) -> Reply {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    repository.handle(&Request {
        client: None,
        method,
        path,
        query,
        authorization: Some(auth),
        accept,
        range,
        body,
    })
}

#[test]
fn every_request_needs_the_right_credentials() {
    let f = Fixture::new();
    let repo = f.repository(true, None);
    for auth in [
        basic(USER, "wrong-password-xxxxx"),
        basic("other", PASSWORD),
        "Bearer x".into(),
        "Basic !!!".into(),
    ] {
        let reply = call(&repo, &auth, "GET", "/config", b"");
        assert_eq!(reply.status, 401);
        assert!(
            reply
                .headers
                .iter()
                .any(|(name, _)| *name == "WWW-Authenticate")
        );
    }
    let no_header = repo.handle(&Request {
        client: None,
        method: "GET",
        path: "/config",
        query: "",
        authorization: None,
        accept: None,
        range: None,
        body: b"",
    });
    assert_eq!(no_header.status, 401);
    assert!(
        Repository::new(Arc::clone(&f.storage), USER, "short", true, None).is_err(),
        "weak passwords are refused"
    );
}

#[test]
fn uploads_are_verified_immutable_and_idempotent() {
    let f = Fixture::new();
    let repo = f.repository(true, None);
    assert_eq!(
        call(&repo, &f.auth, "POST", "/?create=true", b"").status,
        200
    );
    assert_eq!(call(&repo, &f.auth, "HEAD", "/config", b"").status, 404);
    assert_eq!(call(&repo, &f.auth, "POST", "/config", b"cfg").status, 200);
    assert_eq!(
        call(&repo, &f.auth, "POST", "/config", b"cfg").status,
        200,
        "identical retry"
    );
    assert_eq!(
        call(&repo, &f.auth, "POST", "/config", b"other").status,
        403,
        "config is never replaced"
    );
    let head = call(&repo, &f.auth, "HEAD", "/config", b"");
    assert_eq!(
        (head.status, head.head_length, head.body.len()),
        (200, Some(3), 0)
    );

    let pack = b"pack bytes".to_vec();
    let id = sha(&pack);
    assert_eq!(
        call(
            &repo,
            &f.auth,
            "POST",
            &format!("/data/{}", sha(b"different")),
            &pack
        )
        .status,
        400,
        "name must be the content hash"
    );
    assert_eq!(
        call(&repo, &f.auth, "POST", &format!("/data/{id}"), &pack).status,
        200
    );
    assert_eq!(
        call(&repo, &f.auth, "POST", &format!("/data/{id}"), &pack).status,
        200
    );
    assert_eq!(
        call(&repo, &f.auth, "GET", &format!("/data/{id}"), b"").body,
        pack
    );
    assert!(
        f.storage
            .head(
                &rebsync_core::storage::ObjectKey::parse(&format!("restic/data/{}/{id}", &id[..2]))
                    .unwrap()
            )
            .is_ok()
    );
    for path in [
        "/data/../config",
        "/data/ABC",
        "/data/x/y",
        "/other/abc",
        "/data/%2e%2e",
    ] {
        assert!(
            matches!(call(&repo, &f.auth, "GET", path, b"").status, 400 | 404),
            "{path}"
        );
    }
}

#[test]
fn ranges_and_listings_follow_the_protocol() {
    let f = Fixture::new();
    let repo = f.repository(true, None);
    let pack = b"0123456789".to_vec();
    let id = sha(&pack);
    call(&repo, &f.auth, "POST", &format!("/data/{id}"), &pack);
    let part = call_with(
        &repo,
        &f.auth,
        "GET",
        &format!("/data/{id}"),
        b"",
        None,
        Some("bytes=2-5"),
    );
    assert_eq!((part.status, part.body.as_slice()), (206, &b"2345"[..]));
    let tail = call_with(
        &repo,
        &f.auth,
        "GET",
        &format!("/data/{id}"),
        b"",
        None,
        Some("bytes=7-"),
    );
    assert_eq!(tail.body, b"789");
    assert_eq!(
        call_with(
            &repo,
            &f.auth,
            "GET",
            &format!("/data/{id}"),
            b"",
            None,
            Some("bytes=10-12")
        )
        .status,
        416
    );

    let v1 = call(&repo, &f.auth, "GET", "/data/", b"");
    assert_eq!(
        serde_json::from_slice::<Vec<String>>(&v1.body).unwrap(),
        vec![id.clone()]
    );
    let v2 = call_with(
        &repo,
        &f.auth,
        "GET",
        "/data/",
        b"",
        Some("application/vnd.x.restic.rest.v2"),
        None,
    );
    let entries: serde_json::Value = serde_json::from_slice(&v2.body).unwrap();
    assert_eq!(entries, serde_json::json!([{"name": id, "size": 10}]));
    assert_eq!(call(&repo, &f.auth, "GET", "/keys/", b"").body, b"[]");
}

#[test]
fn append_only_refuses_deletion_except_locks_and_quota_is_enforced() {
    let f = Fixture::new();
    let repo = f.repository(true, Some(25));
    let (pack, lock) = (b"0123456789".to_vec(), b"lock".to_vec());
    call(
        &repo,
        &f.auth,
        "POST",
        &format!("/data/{}", sha(&pack)),
        &pack,
    );
    call(
        &repo,
        &f.auth,
        "POST",
        &format!("/locks/{}", sha(&lock)),
        &lock,
    );
    assert_eq!(
        call(
            &repo,
            &f.auth,
            "DELETE",
            &format!("/data/{}", sha(&pack)),
            b""
        )
        .status,
        403
    );
    assert_eq!(call(&repo, &f.auth, "DELETE", "/config", b"").status, 403);
    assert_eq!(
        call(
            &repo,
            &f.auth,
            "DELETE",
            &format!("/locks/{}", sha(&lock)),
            b""
        )
        .status,
        200
    );
    assert_eq!(repo.used_bytes(), 10);
    let big = vec![7u8; 16];
    assert_eq!(
        call(
            &repo,
            &f.auth,
            "POST",
            &format!("/data/{}", sha(&big)),
            &big
        )
        .status,
        507
    );
    let fits = vec![8u8; 15];
    assert_eq!(
        call(
            &repo,
            &f.auth,
            "POST",
            &format!("/data/{}", sha(&fits)),
            &fits
        )
        .status,
        200
    );
    assert_eq!(repo.used_bytes(), 25);
    // The quota is recomputed from storage when the server restarts.
    assert_eq!(f.repository(true, Some(25)).used_bytes(), 25);

    let admin = f.repository(false, None);
    assert_eq!(
        call(
            &admin,
            &f.auth,
            "DELETE",
            &format!("/data/{}", sha(&pack)),
            b""
        )
        .status,
        200
    );
    assert_eq!(admin.used_bytes(), 15);
}

#[test]
fn plain_http_is_refused_off_loopback() {
    let options = ResticOptions {
        bind: "0.0.0.0:0".parse().unwrap(),
        user: USER.into(),
        password: PASSWORD.into(),
        append_only: true,
        max_bytes: None,
        tls: None,
    };
    let error = restic_rest::bind(&options)
        .err()
        .expect("refused")
        .to_string();
    assert!(error.contains("requires TLS"), "{error}");
}

/// One raw HTTP/1.1 exchange; returns the status line and headers.
fn raw_get(port: u16, path: &str, range: &str) -> (String, Vec<(String, String)>, usize) {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: {}\r\nRange: {range}\r\nConnection: close\r\n\r\n",
        basic(USER, PASSWORD)
    )
    .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let split = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&response[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap().to_owned();
    let headers = lines
        .filter_map(|line| line.split_once(": "))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.to_owned()))
        .collect();
    (status, headers, response.len() - split - 4)
}

#[test]
fn large_range_replies_carry_content_length_not_chunked_encoding() {
    // restic 0.18 rejects a range read whose Content-Length differs from the
    // requested length; tiny_http chunks bodies over 32 KiB unless told not to.
    let f = Fixture::new();
    let options = ResticOptions {
        bind: "127.0.0.1:0".parse().unwrap(),
        user: USER.into(),
        password: PASSWORD.into(),
        append_only: true,
        max_bytes: None,
        tls: None,
    };
    let server = Arc::new(restic_rest::bind(&options).unwrap());
    let repository = Arc::new(f.repository(true, None));
    {
        let (server, repository) = (Arc::clone(&server), Arc::clone(&repository));
        std::thread::spawn(move || server.serve(repository, 1));
    }
    let pack: Vec<u8> = (0..300_000u32).map(|n| (n % 251) as u8).collect();
    let id = sha(&pack);
    assert_eq!(
        call(&repository, &f.auth, "POST", &format!("/data/{id}"), &pack).status,
        200
    );
    let (status, headers, body) = raw_get(server.port, &format!("/data/{id}"), "bytes=1000-200999");
    let header = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    };
    assert!(status.contains("206"), "{status}");
    assert_eq!(header("content-length").as_deref(), Some("200000"));
    assert_eq!(header("transfer-encoding"), None);
    assert_eq!(
        header("content-range").as_deref(),
        Some("bytes 1000-200999/300000")
    );
    assert_eq!(body, 200_000);
    let (status, headers, _) = raw_get(server.port, &format!("/data/{id}"), "bytes=300000-");
    assert!(status.contains("416"), "{status}");
    assert!(
        headers
            .iter()
            .any(|(n, v)| n == "content-range" && v == "bytes */300000")
    );
    server.unblock();
}

fn have_restic() -> bool {
    Command::new("restic")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn restic(
    repo: &str,
    extra: &[&str],
    args: &[&str],
    workdir: &std::path::Path,
) -> std::process::Output {
    Command::new("restic")
        .args(["--repo", repo, "--no-cache", "--quiet"])
        .args(extra)
        .args(args)
        .env("RESTIC_PASSWORD", "repository-encryption-password")
        .env("HOME", workdir)
        .env_remove("RESTIC_REPOSITORY")
        .output()
        .expect("run restic")
}

fn ok(output: &std::process::Output, what: &str) {
    assert!(
        output.status.success(),
        "{what}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn exercise_real_restic(tls: Option<(Vec<u8>, Vec<u8>)>, extra: Vec<String>, try_forget: bool) {
    let f = Fixture::new();
    let work = tempfile::tempdir().unwrap();
    let options = ResticOptions {
        bind: "127.0.0.1:0".parse().unwrap(),
        user: USER.into(),
        password: PASSWORD.into(),
        append_only: true,
        max_bytes: None,
        tls,
    };
    let server = Arc::new(restic_rest::bind(&options).unwrap());
    let repository = Arc::new(f.repository(true, None));
    {
        let (server, repository) = (Arc::clone(&server), Arc::clone(&repository));
        std::thread::spawn(move || server.serve(repository, 4));
    }
    let scheme = if server.tls { "https" } else { "http" };
    let url = format!(
        "rest:{scheme}://{USER}:{PASSWORD}@localhost:{}/",
        server.port
    );
    let extra: Vec<&str> = extra.iter().map(String::as_str).collect();

    let source = work.path().join("source");
    std::fs::create_dir_all(source.join("nested")).unwrap();
    std::fs::write(source.join("a.txt"), b"alpha").unwrap();
    std::fs::write(
        source.join("nested/b.bin"),
        (0..200_000u32)
            .flat_map(|n| n.to_le_bytes())
            .collect::<Vec<_>>(),
    )
    .unwrap();

    ok(&restic(&url, &extra, &["init"], work.path()), "init");
    ok(
        &restic(
            &url,
            &extra,
            &["backup", source.to_str().unwrap()],
            work.path(),
        ),
        "backup",
    );
    let snapshots = restic(&url, &extra, &["snapshots", "--json"], work.path());
    ok(&snapshots, "snapshots");
    let list: serde_json::Value = serde_json::from_slice(&snapshots.stdout).unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);
    let id = list[0]["short_id"].as_str().unwrap().to_owned();

    let target = work.path().join("restore");
    ok(
        &restic(
            &url,
            &extra,
            &["restore", &id, "--target", target.to_str().unwrap()],
            work.path(),
        ),
        "restore",
    );
    let restored = target.join(source.strip_prefix("/").unwrap());
    assert_eq!(std::fs::read(restored.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(
        std::fs::read(restored.join("nested/b.bin")).unwrap(),
        std::fs::read(source.join("nested/b.bin")).unwrap()
    );
    ok(
        &restic(&url, &extra, &["check", "--read-data"], work.path()),
        "check --read-data",
    );

    // Append-only: forgetting a snapshot needs a deletion the server refuses.
    // restic retries the refusal with backoff (about a minute), so only once.
    if try_forget {
        let forget = restic(&url, &extra, &["forget", &id], work.path());
        // restic 0.16 exits non-zero; 0.18 reports "unable to remove" and exits 0.
        // Either way the server refused, and the snapshot must survive (below).
        let stderr = String::from_utf8_lossy(&forget.stderr);
        assert!(
            !forget.status.success() || stderr.contains("unable to remove"),
            "forget must be refused on an append-only server: {stderr}"
        );
        let after = restic(&url, &extra, &["snapshots", "--json"], work.path());
        ok(&after, "snapshots after refused forget");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&after.stdout)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    // Normal operation removed its locks; nothing else was deleted.
    assert_eq!(
        restic(&url, &extra, &["list", "locks"], work.path()).stdout,
        b""
    );

    let wrong = format!(
        "rest:{scheme}://{USER}:not-the-password-xyz@localhost:{}/",
        server.port
    );
    assert!(
        !restic(&wrong, &extra, &["snapshots"], work.path())
            .status
            .success()
    );
    server.unblock();
}

#[test]
fn real_restic_over_loopback_http() {
    if !have_restic() {
        eprintln!("skipped: restic not installed");
        return;
    }
    exercise_real_restic(None, Vec::new(), true);
}

#[test]
fn real_restic_over_tls_with_a_pinned_certificate() {
    if !have_restic() {
        eprintln!("skipped: restic not installed");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (cert, key, _fingerprint) =
        rebsync_core::serve::certificate(&dir.path().join("tls"), vec!["localhost".into()])
            .unwrap();
    let cacert = dir.path().join("ca.pem");
    std::fs::write(&cacert, &cert).unwrap();
    exercise_real_restic(
        Some((cert, key)),
        vec!["--cacert".into(), cacert.to_string_lossy().into_owned()],
        false,
    );
}

fn private_file(path: &std::path::Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn git(dir: &std::path::Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

#[test]
fn rbq_backs_up_dirty_work_to_a_peer_over_pinned_tls_and_it_restores_off_machine() {
    // Plan stage 2: encrypted preservation to a restic REST peer, restored elsewhere.
    if !have_restic() {
        eprintln!("skipped: restic not installed");
        return;
    }
    let peer_dir = tempfile::tempdir().unwrap();
    let (cert, key, _) =
        rebsync_core::serve::certificate(&peer_dir.path().join("tls"), vec!["localhost".into()])
            .unwrap();
    let f = Fixture::new();
    let server = Arc::new(
        restic_rest::bind(&ResticOptions {
            bind: "127.0.0.1:0".parse().unwrap(),
            user: USER.into(),
            password: PASSWORD.into(),
            append_only: true,
            max_bytes: None,
            tls: Some((cert.clone(), key)),
        })
        .unwrap(),
    );
    let repository = Arc::new(f.repository(true, None));
    {
        let (server, repository) = (Arc::clone(&server), Arc::clone(&repository));
        std::thread::spawn(move || server.serve(repository, 4));
    }

    // The machine being protected: dirty work in a Git repository.
    let laptop = tempfile::tempdir().unwrap();
    let home = laptop.path().join("home");
    let project = home.join("proj");
    std::fs::create_dir_all(&project).unwrap();
    git(&project, &["init", "-q", "-b", "main"]);
    std::fs::write(project.join("notes.txt"), "committed\n").unwrap();
    git(&project, &["add", "notes.txt"]);
    git(&project, &["commit", "-qm", "one"]);
    std::fs::write(project.join("notes.txt"), "uncommitted edit\n").unwrap();
    std::fs::write(project.join("draft.md"), "untracked draft\n").unwrap();

    let secrets = laptop.path().join("secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    private_file(&secrets.join("http"), &format!("{PASSWORD}\n"));
    private_file(&secrets.join("restic"), "repository-encryption-password\n");
    let cacert = secrets.join("peer.pem");
    std::fs::write(&cacert, &cert).unwrap();

    let mut config = rebsync_core::Config::defaults(home.clone());
    config.backup.repository = Some(format!("rest:https://{USER}@localhost:{}/", server.port));
    config.backup.rest_password_file = Some(secrets.join("http"));
    config.backup.password_file = Some(secrets.join("restic"));
    config.backup.cacert = Some(cacert.clone());
    config.git.fetch = false;
    config.git.push = false;

    rebsync_core::sync::initialize_backup(&config).unwrap();
    let summary = rebsync_core::run(&config, rebsync_core::RunOptions { apply: true }).unwrap();
    let outcome = &summary.repositories[0];
    let snapshot = outcome
        .backup_snapshot
        .clone()
        .unwrap_or_else(|| panic!("backup failed: {:?}", outcome.issues));
    assert!(!summary.issues.iter().any(|i| i.contains("inline password")));
    let journal = std::fs::read_to_string(&summary.journal).unwrap();
    assert!(
        !journal.contains(PASSWORD),
        "the HTTP password must never reach the journal"
    );

    // Restore on another machine: only the URL, the two secrets and the CA.
    let elsewhere = tempfile::tempdir().unwrap();
    let restore = Command::new("restic")
        .env(
            "RESTIC_REPOSITORY",
            format!("rest:https://{USER}:{PASSWORD}@localhost:{}/", server.port),
        )
        .args(["--no-cache", "--cacert"])
        .arg(&cacert)
        .arg("--password-file")
        .arg(secrets.join("restic"))
        .args(["restore", &snapshot, "--target"])
        .arg(elsewhere.path())
        .env("HOME", elsewhere.path())
        .output()
        .unwrap();
    assert!(
        restore.status.success(),
        "restore: {}",
        String::from_utf8_lossy(&restore.stderr)
    );
    let archive = walkdir::WalkDir::new(elsewhere.path())
        .into_iter()
        .filter_map(Result::ok)
        .find(|e| e.file_name() == "worktree.tar")
        .expect("worktree archive restored")
        .into_path();
    let extracted = elsewhere.path().join("extracted");
    std::fs::create_dir(&extracted).unwrap();
    assert!(
        Command::new("tar")
            .arg("-xf")
            .arg(&archive)
            .arg("-C")
            .arg(&extracted)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        std::fs::read_to_string(extracted.join("notes.txt")).unwrap(),
        "uncommitted edit\n"
    );
    assert_eq!(
        std::fs::read_to_string(extracted.join("draft.md")).unwrap(),
        "untracked draft\n"
    );

    // Misconfigurations are refused before restic runs.
    let mut no_user = config.clone();
    no_user.backup.repository = Some(format!("rest:https://localhost:{}/", server.port));
    let error = rebsync_core::sync::initialize_backup(&no_user)
        .unwrap_err()
        .to_string();
    assert!(error.contains("needs the user"), "{error}");
    let mut inline = config.clone();
    inline.backup.repository = Some(format!("rest:https://{USER}:x@localhost:{}/", server.port));
    assert!(
        rebsync_core::sync::initialize_backup(&inline)
            .unwrap_err()
            .to_string()
            .contains("already carries a password")
    );
    inline.backup.rest_password_file = None;
    let summary = rebsync_core::run(&inline, rebsync_core::RunOptions { apply: false }).unwrap();
    assert!(
        summary.issues.iter().any(|i| i.contains("inline password")),
        "{:?}",
        summary.issues
    );
    server.unblock();
}

#[test]
fn failed_logins_are_throttled_per_client_without_checking_the_password() {
    let f = Fixture::new();
    let repo = f
        .repository(true, None)
        .with_login_limit(3, std::time::Duration::from_millis(300));
    let (attacker, other): (std::net::IpAddr, std::net::IpAddr) =
        ("192.0.2.7".parse().unwrap(), "192.0.2.8".parse().unwrap());
    let ask = |client, auth: &str| {
        repo.handle(&Request {
            client: Some(client),
            method: "GET",
            path: "/config",
            query: "",
            authorization: Some(auth),
            accept: None,
            range: None,
            body: b"",
        })
        .status
    };
    let wrong = basic(USER, "wrong-password-xxxxxxx");
    for _ in 0..3 {
        assert_eq!(ask(attacker, &wrong), 401);
    }
    assert_eq!(ask(attacker, &wrong), 429);
    // Even the right password waits out the window: no oracle while throttled.
    assert_eq!(ask(attacker, &f.auth), 429);
    // Other clients are unaffected.
    assert_eq!(ask(other, &f.auth), 404);
    std::thread::sleep(std::time::Duration::from_millis(350));
    assert_eq!(
        ask(attacker, &f.auth),
        404,
        "window expired, correct credentials work"
    );
    // A success clears the client's failures.
    for _ in 0..2 {
        assert_eq!(ask(attacker, &wrong), 401);
    }
    assert_eq!(ask(attacker, &f.auth), 404);
    for _ in 0..2 {
        assert_eq!(ask(attacker, &wrong), 401);
    }
    assert_eq!(
        ask(attacker, &wrong),
        401,
        "count restarted after the success"
    );
    let throttled = repo.handle(&Request {
        client: Some(attacker),
        method: "GET",
        path: "/config",
        query: "",
        authorization: Some(&wrong),
        accept: None,
        range: None,
        body: b"",
    });
    assert_eq!(throttled.status, 429);
    assert!(
        throttled
            .headers
            .iter()
            .any(|(name, _)| *name == "Retry-After")
    );
}

#[test]
fn upload_memory_is_reserved_from_a_server_wide_budget() {
    let f = Fixture::new();
    let max = restic_rest::MAX_UPLOAD_BYTES;
    let repo = f.repository(true, None).with_upload_budget(2 * max);
    let quick = std::time::Duration::from_millis(50);
    let first = repo.reserve_upload(max, quick).expect("first fits");
    let second = repo.reserve_upload(max, quick).expect("second fits");
    assert_eq!(repo.uploads_in_flight(), 2 * max);
    assert!(
        repo.reserve_upload(1, quick).is_none(),
        "budget full: refused after waiting"
    );
    drop(first);
    let third = repo
        .reserve_upload(max, quick)
        .expect("released memory is reusable");
    drop((second, third));
    assert_eq!(repo.uploads_in_flight(), 0);
    // A waiting upload proceeds as soon as another finishes.
    let repo = Arc::new(f.repository(true, None).with_upload_budget(2 * max));
    let held = repo.reserve_upload(2 * max, quick).unwrap();
    let waiter = {
        let repo = Arc::clone(&repo);
        std::thread::spawn(move || {
            repo.reserve_upload(max, std::time::Duration::from_secs(5))
                .is_some()
        })
    };
    std::thread::sleep(std::time::Duration::from_millis(100));
    drop(held);
    assert!(waiter.join().unwrap());
}

#[test]
fn unauthenticated_uploads_are_refused_before_their_body_is_read() {
    use std::io::{Read, Write};
    let f = Fixture::new();
    let options = ResticOptions {
        bind: "127.0.0.1:0".parse().unwrap(),
        user: USER.into(),
        password: PASSWORD.into(),
        append_only: true,
        max_bytes: None,
        tls: None,
    };
    let server = Arc::new(restic_rest::bind(&options).unwrap());
    let repository = Arc::new(f.repository(true, None));
    {
        let (server, repository) = (Arc::clone(&server), Arc::clone(&repository));
        std::thread::spawn(move || server.serve(repository, 1));
    }
    // Announce a 100 MB body and never send it: the server must answer 401
    // from the headers alone instead of waiting to buffer the body.
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "POST /data/{} HTTP/1.1\r\nHost: localhost\r\nAuthorization: {}\r\nContent-Length: 100000000\r\n\r\n",
        "0".repeat(64),
        basic(USER, "not-the-password-xxxxx")
    )
    .unwrap();
    let mut first = [0u8; 12];
    stream
        .read_exact(&mut first)
        .expect("answered without the body");
    assert_eq!(&first, b"HTTP/1.1 401");
    assert_eq!(repository.uploads_in_flight(), 0, "no memory was reserved");
    server.unblock();
}

#[test]
fn an_identical_retry_succeeds_even_when_the_quota_is_full() {
    let f = Fixture::new();
    let pack = b"0123456789".to_vec();
    let repo = f.repository(true, Some(pack.len() as u64));
    let path = format!("/data/{}", sha(&pack));
    assert_eq!(call(&repo, &f.auth, "POST", &path, &pack).status, 200);
    assert_eq!(
        call(&repo, &f.auth, "POST", &path, &pack).status,
        200,
        "lost-response retry"
    );
    let other = b"x".to_vec();
    assert_eq!(
        call(
            &repo,
            &f.auth,
            "POST",
            &format!("/data/{}", sha(&other)),
            &other
        )
        .status,
        507
    );
}

#[test]
fn creates_are_serialized_where_storage_lacks_atomic_create() {
    let dir = tempfile::tempdir().unwrap();
    let storage: Arc<dyn ObjectStorage> = Arc::new(
        FsObjectStorage::open(dir.path().join("store"))
            .unwrap()
            .without_hard_links(),
    );
    assert!(!storage.capabilities().atomic_create_if_absent);
    let repo = Arc::new(Repository::new(Arc::clone(&storage), USER, PASSWORD, true, None).unwrap());
    let auth = basic(USER, PASSWORD);
    let statuses: Vec<(u16, Vec<u8>)> = std::thread::scope(|scope| {
        (0..16)
            .map(|n| {
                let (repo, auth) = (Arc::clone(&repo), auth.clone());
                scope.spawn(move || {
                    let body = format!("config {n}").into_bytes();
                    (call(&repo, &auth, "POST", "/config", &body).status, body)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect()
    });
    let winners: Vec<_> = statuses
        .iter()
        .filter(|(status, _)| *status == 200)
        .collect();
    assert_eq!(winners.len(), 1, "{statuses:?}");
    assert!(
        statuses
            .iter()
            .all(|(status, _)| matches!(status, 200 | 403))
    );
    assert_eq!(call(&repo, &auth, "GET", "/config", b"").body, winners[0].1);
}

#[test]
fn concurrent_failures_from_one_address_cannot_exceed_the_limit() {
    let f = Fixture::new();
    let repo = Arc::new(
        f.repository(true, None)
            .with_login_limit(3, std::time::Duration::from_secs(60)),
    );
    let client: std::net::IpAddr = "192.0.2.9".parse().unwrap();
    let wrong = basic(USER, "wrong-password-xxxxxxx");
    let statuses: Vec<u16> = std::thread::scope(|scope| {
        (0..32)
            .map(|_| {
                let (repo, wrong) = (Arc::clone(&repo), wrong.clone());
                scope.spawn(move || {
                    repo.handle(&Request {
                        client: Some(client),
                        method: "GET",
                        path: "/config",
                        query: "",
                        authorization: Some(&wrong),
                        accept: None,
                        range: None,
                        body: b"",
                    })
                    .status
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect()
    });
    assert_eq!(
        statuses.iter().filter(|s| **s == 401).count(),
        3,
        "{statuses:?}"
    );
    assert_eq!(statuses.iter().filter(|s| **s == 429).count(), 29);
}

#[test]
fn bodies_without_declared_length_are_small_or_refused() {
    use std::io::{Read, Write};
    let f = Fixture::new();
    let options = ResticOptions {
        bind: "127.0.0.1:0".parse().unwrap(),
        user: USER.into(),
        password: PASSWORD.into(),
        append_only: true,
        max_bytes: None,
        tls: None,
    };
    let server = Arc::new(restic_rest::bind(&options).unwrap());
    let repository = Arc::new(f.repository(true, None));
    {
        let (server, repository) = (Arc::clone(&server), Arc::clone(&repository));
        std::thread::spawn(move || server.serve(repository, 1));
    }
    let exchange = |request: String| {
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", server.port)).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut first = [0u8; 12];
        stream.read_exact(&mut first).unwrap();
        String::from_utf8_lossy(&first).into_owned()
    };
    let auth = &f.auth;
    // restic's create: an empty chunked body (its transport wraps bodies).
    assert_eq!(
        exchange(format!(
            "POST /?create=true HTTP/1.1\r\nHost: x\r\nAuthorization: {auth}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n"
        )),
        "HTTP/1.1 200"
    );
    // Or no length headers at all: an empty body.
    assert_eq!(
        exchange(format!(
            "POST /?create=true HTTP/1.1\r\nHost: x\r\nAuthorization: {auth}\r\nConnection: close\r\n\r\n"
        )),
        "HTTP/1.1 200"
    );
    // A small chunked object is accepted and stored.
    assert_eq!(
        exchange(format!(
            "POST /config HTTP/1.1\r\nHost: x\r\nAuthorization: {auth}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\ncfg\r\n0\r\n\r\n"
        )),
        "HTTP/1.1 200"
    );
    assert_eq!(call(&repository, auth, "GET", "/config", b"").body, b"cfg");
    // A large one without Content-Length is refused.
    let big = restic_rest::MAX_UNDECLARED_BYTES as usize + 1;
    let chunk = format!("{big:x}\r\n{}\r\n0\r\n\r\n", "a".repeat(big));
    assert_eq!(
        exchange(format!(
            "POST /keys/{} HTTP/1.1\r\nHost: x\r\nAuthorization: {auth}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{chunk}",
            "0".repeat(64)
        )),
        "HTTP/1.1 411"
    );
    assert_eq!(repository.uploads_in_flight(), 0);
    server.unblock();
}

#[test]
fn self_signed_certificates_cover_the_requested_names() {
    let home = tempfile::tempdir().unwrap();
    let config = rebsync_core::Config::defaults(home.path().to_path_buf());
    let (a, _, path_a, _) = restic_rest::self_signed_certificate(
        &config,
        vec!["localhost".into(), "backup.example".into()],
    )
    .unwrap();
    let (_, _, path_b, _) =
        restic_rest::self_signed_certificate(&config, vec!["localhost".into()]).unwrap();
    assert_ne!(
        path_a, path_b,
        "a different name set gets its own certificate"
    );
    let again = restic_rest::self_signed_certificate(
        &config,
        vec!["backup.example".into(), "localhost".into()],
    )
    .unwrap();
    assert_eq!(
        again.2, path_a,
        "same names (any order) reuse the certificate"
    );
    let Ok(output) = Command::new("openssl")
        .args(["x509", "-noout", "-ext", "subjectAltName"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(&a)?;
            child.wait_with_output()
        })
    else {
        return eprintln!("skipped SAN check: openssl not installed");
    };
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("DNS:backup.example") && text.contains("DNS:localhost"),
        "{text}"
    );
}
